# -*- coding: utf-8
"""Universal per-hop adjudication — response analysis, param correlation, resolution."""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from minidrifter.verification.failure_diagnoser import diagnose_failure_with_ir
from minidrifter.verification.frontier_expander import get_required_business_fields
from minidrifter.verification.object_acquisition_planner import _producers_for_field
from minidrifter.verification.pack_loader import is_high_value_produce, load_field_ontology
from minidrifter.verification.response_param_analyzer import enrich_correlation_with_pair
from minidrifter.verification.transport_family_tracker import path_family


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


_MISSING_HINTS = re.compile(
    r'(orderid|order id|deviceid|device id|missing|required|不能为空|缺少|未找到|不存在)',
    re.I,
)


def _field_class(name: str) -> str:
    ont = load_field_ontology() or {}
    classes = ont.get('field_classes') or {}
    nl = name.lower()
    for cls, fields in classes.items():
        if name in fields or nl in {f.lower() for f in fields}:
            return cls
    return 'ordinary_business_param'


def correlate_param_response(
    test_case: Dict[str, Any],
    execution: Dict[str, Any],
    analysis: Dict[str, Any],
    *,
    baseline_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Link request param changes to response outcome (universal binding drift lens)."""
    baseline = (baseline_context or {}).get('resolved_fields') or {}
    params = test_case.get('params') or {}
    mut = test_case.get('mutation_type') or 'M0_baseline_replay'
    changed: List[Dict[str, Any]] = []

    for key, val in params.items():
        base_val = baseline.get(key)
        if base_val is None:
            for bk, bv in baseline.items():
                if str(bk).lower() == str(key).lower():
                    base_val = bv
                    break
        if mut.startswith('M7') or (base_val is not None and str(val) != str(base_val)):
            changed.append({
                'field': key,
                'role': _field_class(key),
                'mutated': True,
                'has_baseline': base_val is not None,
            })

    binding = analysis.get('binding_observation') or {}
    outcome = analysis.get('call_outcome') or 'unknown'
    security = list(analysis.get('security_signals') or [])

    if 'subject_object_binding_mismatch' in security:
        delta = 'binding_mismatch_under_mutation'
        interpretation = (
            f"Response reflects subject/object inconsistency after {mut} on "
            f"{', '.join(c['field'] for c in changed) or 'bindable fields'}."
        )
    elif binding.get('binding_status') == 'server_accepts_mutated_subject':
        delta = 'binding_mismatch_under_mutation'
        interpretation = 'Server accepted mutated subject credential — weak binding signal.'
    elif outcome == 'business_success' and mut.startswith('M8'):
        delta = 'credential_guard_bypass'
        interpretation = 'Business success after weakening signature/replay guard — credential guard may be cosmetic.'
    elif outcome == 'business_success' and mut.startswith('M7'):
        delta = 'mutation_accepted'
        interpretation = 'Server accepted mutated bindable params — potential binding weakness.'
    elif outcome == 'business_success' and changed:
        delta = 'success_with_param_change'
        interpretation = 'Business success despite param deviation; verify binding enforcement.'
    elif outcome in {'validation_error', 'binding_rejected', 'business_state_blocked'}:
        if outcome == 'binding_rejected' or (
            mut.startswith('M7') and outcome in {'validation_error', 'business_state_blocked'}
        ):
            delta = 'binding_enforced_under_mutation'
            interpretation = (
                f"Server rejected identity mutation on "
                f"{', '.join(c['field'] for c in changed) or 'bindable fields'} — binding likely enforced."
            )
        else:
            delta = 'rejected_params_or_state'
            interpretation = 'Server rejected request — likely missing prerequisite objects or invalid param shape.'
    elif outcome in {'transport_error', 'safety_blocked'}:
        delta = 'transport_failure'
        interpretation = 'No reliable business signal — transport/routing issue dominates.'
    elif outcome == 'auth_expired':
        delta = 'auth_failure'
        interpretation = 'Credential/session invalid for this hop.'
    else:
        delta = 'no_significant_param_signal'
        interpretation = 'Outcome not strongly tied to param mutation.'

    return {
        'mutation_type': mut,
        'changed_fields': changed,
        'response_delta': delta,
        'binding_status': binding.get('binding_status'),
        'interpretation': interpretation,
        'produced_fields': analysis.get('produced_fields') or [],
    }


def infer_missing_materials(
    *,
    test_case: Dict[str, Any],
    analysis: Dict[str, Any],
    execution: Dict[str, Any],
    graph: Dict[str, Any],
    templates_by_id: Dict[str, Any],
    object_pool: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Universal missing-field inference from graph requires, pool, and response hints."""
    api_id = test_case.get('api_id') or ''
    available = set((object_pool or {}).get('confirmed_fields') or [])
    available |= set((object_pool or {}).get('frontier_unlocks') or [])

    required = get_required_business_fields(graph, api_id) if api_id else set()
    missing_from_graph = [
        f for f in sorted(required)
        if f not in available and f.lower() not in {a.lower() for a in available}
    ]

    snippet = str(execution.get('response_snippet') or execution.get('build_status') or '')
    hint_fields: Set[str] = set()
    if _MISSING_HINTS.search(snippet):
        for f in missing_from_graph:
            hint_fields.add(f)
        ont = load_field_ontology() or {}
        for cls_fields in (ont.get('field_classes') or {}).values():
            for f in cls_fields:
                if f.lower() in snippet.lower():
                    hint_fields.add(f)

    materials: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    for field in list(dict.fromkeys(missing_from_graph + sorted(hint_fields))):
        if field.lower() in seen:
            continue
        seen.add(field.lower())
        producers = _producers_for_field(graph, field)[:3]
        producer_paths = []
        for p in producers:
            pid = p.get('api_id')
            tpl = templates_by_id.get(pid) or {}
            node = next((n for n in (graph.get('api_nodes') or []) if n.get('id') == pid), {})
            producer_paths.append(node.get('path') or tpl.get('path') or pid)

        why = f"Consumer `{test_case.get('path')}` requires `{field}` per workflow graph; not in object pool."
        if field not in missing_from_graph:
            why = f"Response/body hints suggest `{field}` may be required for `{test_case.get('path')}`."

        materials.append({
            'field': field,
            'field_class': _field_class(field),
            'why_needed': why,
            'producer_api_ids': [p.get('api_id') for p in producers if p.get('api_id')],
            'suggested_capture_paths': [p for p in producer_paths if p],
            'capture_hint': _capture_hint(field),
            'priority': 'high' if is_high_value_produce(field) else 'medium',
        })
    return materials


def _capture_hint(field: str) -> str:
    cls = _field_class(field)
    if cls == 'object_identifier':
        return f'在小程序中触发会返回 `{field}` 的 list/detail 接口，粘贴 raw HTTP response。'
    if cls == 'subject_credential':
        return f'提供登录/用户 profile 相关成功请求，确保 `{field}` 出现在 response 或 request 中。'
    if cls == 'capability_credential':
        return f'提供产生 `{field}` 的业务流程抓包（如支付/授权前置接口）。'
    return f'补充包含 `{field}` 的成功业务抓包。'


def _node_health(outcome: str, signals: Dict[str, Any], correlation: Dict[str, Any]) -> str:
    if signals.get('suspicious') or correlation.get('response_delta') == 'binding_mismatch_under_mutation':
        return 'finding_signal'
    if outcome == 'business_success':
        return 'healthy'
    if outcome in {'transport_error', 'safety_blocked', 'build_failed'}:
        return 'blocked'
    if outcome in {'validation_error', 'business_state_blocked', 'auth_expired'}:
        return 'degraded'
    return 'unknown'


def build_resolution_plan(
    attribution: Dict[str, Any],
    *,
    missing_materials: List[Dict[str, Any]],
    correlation: Dict[str, Any],
    retry_count: int = 0,
    transport_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Rule-based auto recovery + user material guidance."""
    layer = attribution.get('layer') or 'L4_business_state'
    fc = attribution.get('failure_class') or 'unknown'
    primary = attribution.get('primary_action') or 'continue_chain'
    auto: List[Dict[str, Any]] = []
    user: List[Dict[str, Any]] = []

    for mat in missing_materials[:3]:
        auto.append({
            'action': 'acquire_object',
            'target_field': mat.get('field'),
            'producer_paths': mat.get('suggested_capture_paths') or [],
        })
        user.append({
            'action': 'provide_capture',
            'field': mat.get('field'),
            'instruction': mat.get('capture_hint'),
            'paths': mat.get('suggested_capture_paths') or [],
        })

    if primary == 'transport_url_repair' or fc in {'transport_error', 'transport_url_routing'}:
        auto.append({'action': 'downrank_path_family', 'reason': fc or 'transport_error'})
        auto.append({'action': 'downrank_api', 'reason': 'transport_error'})
        if (transport_context or {}).get('domain_blocked'):
            auto.append({'action': 'switch_domain', 'reason': 'domain_transport_blocked'})
        else:
            auto.append({'action': 'switch_domain', 'reason': 'avoid broken path family'})
    elif primary == 'refresh_baseline':
        user.append({'action': 'refresh_baseline', 'field': 'Token', 'instruction': '重新登录并粘贴 capture'})
    elif primary == 'schema_repair':
        user.append({'action': 'provide_success_request', 'instruction': '粘贴该 API 真机成功 request 样本'})
        if retry_count < 1:
            auto.append({'action': 'schedule_retry_after_acquire', 'when': 'schema_repair_user_capture'})
    elif primary == 'quarantine_chain':
        auto.append({'action': 'quarantine_chain', 'revive_fields': [m.get('field') for m in missing_materials[:3]]})

    if correlation.get('response_delta') in {'binding_mismatch_under_mutation', 'binding_drift_confirmed'}:
        auto.append({'action': 'finding_escalation', 'reason': 'scope_confirmation'})
        auto.append({'action': 'graph_feedback', 'reason': 'binding_drift'})

    retry_eligible = (
        retry_count < 2
        and fc in {'validation_error', 'business_state_blocked'}
        and bool(missing_materials)
    )
    if retry_eligible:
        auto.insert(0, {'action': 'schedule_retry_after_acquire', 'when': 'revive_fields_satisfied'})

    return {
        'auto_actions': auto,
        'user_actions': user,
        'retry_eligible': retry_eligible,
        'primary_action': primary,
        'layer': layer,
    }


def build_material_request(
    *,
    test_case: Dict[str, Any],
    attribution: Dict[str, Any],
    missing_materials: List[Dict[str, Any]],
    correlation: Dict[str, Any],
    chain_id: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    if not missing_materials and attribution.get('failure_class') not in {
        'auth_expired', 'build_failed', 'validation_error',
    }:
        return None

    fields = [m.get('field') for m in missing_materials if m.get('field')]
    paths: List[str] = []
    for m in missing_materials:
        paths.extend(m.get('suggested_capture_paths') or [])
    paths = list(dict.fromkeys(paths))[:8]

    summary = correlation.get('interpretation') or attribution.get('diagnosis') or ''
    return {
        'schema_version': '1.0.0',
        'generated_at': _utc_now(),
        'request_type': 'material_for_deeper_chain',
        'chain_id': chain_id or test_case.get('chain_id'),
        'blocked_hop': {
            'api_id': test_case.get('api_id'),
            'path': test_case.get('path'),
            'test_stage': test_case.get('test_stage'),
        },
        'root_cause': {
            'layer': attribution.get('layer'),
            'failure_class': attribution.get('failure_class'),
            'diagnosis': attribution.get('diagnosis'),
            'summary': summary,
        },
        'missing_materials': missing_materials,
        'missing_fields': fields,
        'why_deeper_blocked': (
            f"深挖需要 {', '.join(fields)} 进入 object pool 后才能 unlock 下游 consumer。"
            if fields else summary
        ),
        'suggested_capture_paths': paths,
        'param_correlation': correlation,
        'user_next_steps': [
            '1. 按 suggested_capture_paths 在真机/开发者工具抓 list/detail 或 producer 接口',
            '2. 使用 intake-baseline --import-after 导入 raw HTTP',
            '3. run-deep-verify --resume 续跑',
        ],
        'accepted_formats': ['raw_http', 'har', 'burp_item', 'mitmproxy_flow'],
    }


def adjudicate_hop(
    test_case: Dict[str, Any],
    execution: Dict[str, Any],
    analysis: Dict[str, Any],
    *,
    signals: Optional[Dict[str, Any]] = None,
    baseline_context: Optional[Dict[str, Any]] = None,
    graph: Optional[Dict[str, Any]] = None,
    templates_by_id: Optional[Dict[str, Any]] = None,
    object_pool: Optional[Dict[str, Any]] = None,
    chain_context: Optional[Dict[str, Any]] = None,
    anchor_ok: bool = True,
    recent_same_fc_count: int = 0,
    retry_count: int = 0,
    prior_hops: Optional[List[Dict[str, Any]]] = None,
    m0_m7_pair: Optional[Dict[str, Any]] = None,
    transport_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Full hop adjudication: diagnose + correlate + missing materials + resolution."""
    signals = signals or {}
    graph = graph or {}
    templates_by_id = templates_by_id or {}

    attribution = diagnose_failure_with_ir(
        test_case, execution, analysis,
        signals=signals,
        chain_context=chain_context,
        anchor_ok=anchor_ok,
        recent_same_fc_count=recent_same_fc_count,
    )
    correlation = correlate_param_response(
        test_case, execution, analysis, baseline_context=baseline_context,
    )
    correlation = enrich_correlation_with_pair(correlation, m0_m7_pair)
    missing = infer_missing_materials(
        test_case=test_case,
        analysis=analysis,
        execution=execution,
        graph=graph,
        templates_by_id=templates_by_id,
        object_pool=object_pool,
    )
    resolution = build_resolution_plan(
        attribution,
        missing_materials=missing,
        correlation=correlation,
        retry_count=retry_count,
        transport_context=transport_context,
    )
    material_req = build_material_request(
        test_case=test_case,
        attribution=attribution,
        missing_materials=missing,
        correlation=correlation,
        chain_id=test_case.get('chain_id'),
    )
    health = _node_health(analysis.get('call_outcome') or '', signals, correlation)

    return {
        'schema_version': '1.0.0',
        'generated_at': _utc_now(),
        'test_id': test_case.get('test_id'),
        'api_id': test_case.get('api_id'),
        'path': test_case.get('path'),
        'path_family': path_family(test_case.get('path') or ''),
        'chain_id': test_case.get('chain_id'),
        'node_health': health,
        'attribution': attribution,
        'param_correlation': correlation,
        'm0_m7_pair': m0_m7_pair,
        'prior_hops_summary': _summarize_prior_hops(prior_hops),
        'transport_context': transport_context,
        'missing_materials': missing,
        'resolution_plan': resolution,
        'material_request': material_req,
    }


def _summarize_prior_hops(prior: Optional[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for h in (prior or [])[-4:]:
        out.append({
            'path': h.get('path'),
            'health': h.get('node_health'),
            'outcome': (h.get('attribution') or {}).get('failure_class'),
            'missing': [m.get('field') for m in h.get('missing_materials') or []],
        })
    return out
