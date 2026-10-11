# -*- coding: utf-8
"""Universal finding-driven escalation — deepen chains after binding drift signals."""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set, TYPE_CHECKING

from minidrifter.core.utils import stable_id
from minidrifter.verification.campaign_planner import build_test_case
from minidrifter.verification.frontier_expander import (
    _field_set_satisfied,
    get_required_business_fields,
)
from minidrifter.verification.mutation_engine import materialize_mutation_proposal
from minidrifter.verification.pack_loader import load_field_ontology
from minidrifter.verification.workflow_planner import _consumers_for_fields

if TYPE_CHECKING:
    from minidrifter.ir.loader import UniversalIRSession

ESCALATION_STRATEGIES = frozenset({
    'scope_confirmation',      # same mutation class on sibling APIs
    'lateral_binding',         # same domain cluster consumers
    'downstream_propagation',  # chain consumers not yet M7-tested
    'cross_object_binding',    # object_id fields from same producer context
    'privilege_escalation',   # N2-cross-subject tier APIs
})

# Identity fields eligible for M7 while session/crypto params stay stable.
IDENTITY_PARAM_RE = re.compile(
    r'^(user_?id|customer_?id|logincustomerid|platformuserid|memberid|openid|operatorid)$',
    re.I,
)
STABLE_CREDENTIAL_PARAM_RE = re.compile(
    r'^(api_?token|logincustomertoken|customertoken|token|authorization|signature|nonce|timestamp|timespan)$',
    re.I,
)
MAX_IDENTITY_M7_PROBES = 3


def _template_param_keys(template: Dict[str, Any]) -> Set[str]:
    plain = template.get('plain_template') or {}
    keys: Set[str] = set()
    for bag in (plain.get('params'), plain.get('body_params'), template.get('params')):
        if isinstance(bag, dict):
            keys.update(str(k) for k in bag)
    return keys


def _identity_bindable_from_params(param_keys: Set[str]) -> List[Dict[str, str]]:
    found: List[Dict[str, str]] = []
    seen: Set[str] = set()
    for key in sorted(param_keys):
        kl = key.lower()
        if kl in seen or STABLE_CREDENTIAL_PARAM_RE.match(kl):
            continue
        if IDENTITY_PARAM_RE.match(kl):
            role = 'subject_id' if 'customer' in kl or 'user' in kl or 'member' in kl else 'object_id'
            found.append({'field': key, 'role': role, 'source': 'identity_heuristic'})
            seen.add(kl)
    return found


def _ontology() -> Dict[str, Any]:
    return load_field_ontology() or {}


def bindable_fields_for_api(
    template: Dict[str, Any],
    ir_card: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, str]]:
    """Universal bindable param discovery from IR bindings + template params."""
    found: List[Dict[str, str]] = []
    seen: Set[str] = set()
    param_keys = _template_param_keys(template)

    for entry in _identity_bindable_from_params(param_keys):
        found.append(entry)
        seen.add(entry['field'].lower())

    for p in ((ir_card or {}).get('bindings') or {}).get('params') or []:
        name = p.get('name') or ''
        role = p.get('static_role') or ''
        if not name or name.lower() in seen:
            continue
        if role in {'subject_id', 'object_id', 'host_identity'} or 'subject' in role or 'object' in role:
            found.append({'field': name, 'role': role, 'source': 'ir_binding'})
            seen.add(name.lower())

    classes = (_ontology().get('field_classes') or {})
    subject_fields = set(classes.get('subject_credential') or [])
    object_fields = set(classes.get('object_identifier') or [])
    bridge_fields = set(classes.get('chain_bridge_fields') or [])
    for key in param_keys:
        kl = key.lower()
        if kl in seen:
            continue
        if key in subject_fields or kl in {f.lower() for f in subject_fields}:
            found.append({'field': key, 'role': 'subject_id', 'source': 'ontology'})
            seen.add(kl)
        elif key in object_fields or kl in {f.lower() for f in object_fields}:
            found.append({'field': key, 'role': 'object_id', 'source': 'ontology'})
            seen.add(kl)
        elif key in bridge_fields or kl in {f.lower() for f in bridge_fields}:
            found.append({'field': key, 'role': 'object_id', 'source': 'chain_bridge'})
            seen.add(kl)
    return found


def _finding_summary(analysis: Dict[str, Any], test_case: Dict[str, Any]) -> Dict[str, Any]:
    binding = analysis.get('binding_observation') or {}
    signals = list(analysis.get('security_signals') or [])
    suspicious = list((analysis.get('signals') or {}).get('suspicious') or [])
    return {
        'api_id': analysis.get('api_id'),
        'path': analysis.get('path'),
        'mutation_type': test_case.get('mutation_type'),
        'finding_type': (
            'subject_object_binding_mismatch'
            if 'subject_object_binding_mismatch' in signals
            else ('binding_anomaly_hypothesis' if 'binding_anomaly' in suspicious else 'data_harvest')
        ),
        'binding_status': binding.get('binding_status'),
        'subject_field': binding.get('subject_field'),
        'produced_fields': analysis.get('produced_fields') or [],
        'call_outcome': analysis.get('call_outcome'),
    }


def _rule_escalation_targets(
    *,
    finding_api_id: str,
    finding_path: str,
    bindable_fields: List[Dict[str, str]],
    graph: Dict[str, Any],
    templates_by_id: Dict[str, Any],
    object_pool: Dict[str, Any],
    ir_session: Optional['UniversalIRSession'],
    chain_nodes: Optional[List[Dict[str, Any]]] = None,
    exclude_apis: Optional[Set[str]] = None,
    limit: int = 12,
) -> List[Dict[str, Any]]:
    """Rank APIs that should receive follow-up binding tests after a finding."""
    exclude = set(exclude_apis or [])
    exclude.add(finding_api_id)
    available = set(object_pool.get('confirmed_fields') or []) | set(object_pool.get('frontier_unlocks') or [])
    targets: List[Dict[str, Any]] = []
    seen: Set[str] = set()

    subject_names = {b['field'] for b in bindable_fields if 'subject' in b.get('role', '')}
    object_names = {b['field'] for b in bindable_fields if 'object' in b.get('role', '')}
    bind_names = subject_names | object_names

    # Downstream: graph consumers unlocked by same fields
    consumers = _consumers_for_fields(
        graph, available, exclude_apis=exclude, templates_by_id=templates_by_id,
        object_pool=object_pool, from_path=finding_path,
    )
    for c in consumers[:8]:
        aid = c.get('api_id')
        if not aid or aid in seen:
            continue
        overlap = bind_names & set(c.get('required') or [])
        targets.append({
            'api_id': aid,
            'path': c.get('path'),
            'template': c.get('template'),
            'strategy': 'lateral_binding' if overlap else 'downstream_propagation',
            'score': float(c.get('_planner_total_score') or c.get('score') or 0) + 5.0,
            'shared_fields': sorted(overlap),
            'rationale': f"Consumer shares binding fields {sorted(overlap)}" if overlap else 'Graph consumer from finding context',
        })
        seen.add(aid)

    # IR: N2-cross-subject + same domain
    if ir_session:
        finding_card = ir_session.get_api(finding_api_id) or {}
        domain = finding_card.get('business_domain') or 'general'
        for api_id, card in ir_session.api_by_id.items():
            if api_id in seen or api_id in exclude:
                continue
            tpl = templates_by_id.get(api_id)
            if not tpl or tpl.get('status') != 'materialized_with_crypto_profile':
                continue
            tier = (card.get('runtime_tier') or {}).get('tier') or ''
            card_domain = card.get('business_domain') or 'general'
            if tier not in {'N2-cross-subject', 'N1-object'} and card_domain not in {domain, 'general'}:
                continue
            required = get_required_business_fields(graph, api_id)
            if required and not _field_set_satisfied(available, required):
                continue
            bf = bindable_fields_for_api(tpl, card)
            if not bf:
                continue
            overlap = bind_names & {b['field'] for b in bf}
            score = ir_session.priority_boost(api_id) + len(overlap) * 3.0
            if tier == 'N2-cross-subject':
                score += 4.0
            targets.append({
                'api_id': api_id,
                'path': card.get('path') or tpl.get('path'),
                'template': tpl,
                'strategy': 'privilege_escalation' if tier == 'N2-cross-subject' else 'cross_object_binding',
                'score': score,
                'shared_fields': sorted(overlap),
                'rationale': f"IR {tier} API in domain {card_domain}",
            })
            seen.add(api_id)

    # Chain nodes not yet tested with M7
    for node in chain_nodes or []:
        aid = node.get('api_id')
        if not aid or aid in seen or aid == finding_api_id:
            continue
        tpl = templates_by_id.get(aid)
        if not tpl:
            continue
        targets.append({
            'api_id': aid,
            'path': node.get('path') or tpl.get('path'),
            'template': tpl,
            'strategy': 'scope_confirmation',
            'score': 6.0,
            'shared_fields': sorted(bind_names),
            'rationale': 'Prior hop in same chain — confirm binding scope',
        })
        seen.add(aid)

    targets.sort(key=lambda x: x.get('score', 0), reverse=True)
    return targets[:limit]


def _materialize_m7_cases(
    targets: List[Dict[str, Any]],
    *,
    baseline_context: Dict[str, Any],
    object_pool: Dict[str, Any],
    ir_session: Optional['UniversalIRSession'],
    finding_id: str,
    chain_id: Optional[str],
    index_start: int = 5000,
) -> List[Dict[str, Any]]:
    cases: List[Dict[str, Any]] = []
    for i, tgt in enumerate(targets):
        tpl = tgt.get('template') or {}
        api_id = tgt.get('api_id')
        ir_card = ir_session.get_api(api_id) if ir_session else None
        bindable = bindable_fields_for_api(tpl, ir_card)
        if not bindable:
            continue
        parent = build_test_case(tpl, baseline_context=baseline_context, index=index_start + i * 2)
        parent['test_stage'] = 'finding_escalation_m0'
        parent['escalation_strategy'] = tgt.get('strategy')
        parent['escalation_from_finding'] = finding_id
        if chain_id:
            parent['chain_id'] = chain_id
        for bf in bindable[:2]:
            field = bf['field']
            proposal = {
                'proposal_id': stable_id('esc', finding_id, api_id, field),
                'parent_test_id': parent.get('test_id'),
                'api_id': api_id,
                'proposal_type': 'finding_escalation',
                'mutation_type': 'M7_subject_object_mismatch',
                'mutation_operator': 'replace_with_same_type_different_value',
                'target_field': field,
                'selector': {
                    'field': field,
                    'different_from': f'$baseline.{field}',
                    'required_pool': 'negative_pool',
                    'allow_synthetic': True,
                },
                'blocked_if': ['unsafe_side_effect'],
                'rationale': f"Escalation {tgt.get('strategy')}: {tgt.get('rationale')}",
            }
            result = materialize_mutation_proposal(
                proposal, parent, object_pool, baseline_context, index=index_start + i * 2 + 1,
            )
            if result.get('status') != 'materialized':
                continue
            mtc = result['test_case']
            mtc['test_stage'] = 'finding_escalation_m7'
            mtc['escalation_strategy'] = tgt.get('strategy')
            mtc['escalation_from_finding'] = finding_id
            mtc['escalation_rationale'] = tgt.get('rationale')
            if chain_id:
                mtc['chain_id'] = chain_id
            cases.append(mtc)
            break
    return cases


def plan_finding_escalation(
    *,
    analysis: Dict[str, Any],
    test_case: Dict[str, Any],
    pack_dir: Any,
    graph: Dict[str, Any],
    templates_by_id: Dict[str, Any],
    object_pool: Dict[str, Any],
    baseline_context: Dict[str, Any],
    ir_session: Optional['UniversalIRSession'] = None,
    chain_nodes: Optional[List[Dict[str, Any]]] = None,
    chain_id: Optional[str] = None,
    exclude_apis: Optional[Set[str]] = None,
    max_targets: int = 8,
) -> Dict[str, Any]:
    """Rule-first escalation plan after binding drift signal."""
    summary = _finding_summary(analysis, test_case)
    finding_id = stable_id(
        'finding', summary.get('api_id'), summary.get('mutation_type'), summary.get('finding_type'),
    )
    tpl = templates_by_id.get(summary.get('api_id') or '') or {}
    ir_card = ir_session.get_api(summary.get('api_id') or '') if ir_session else None
    bindable = bindable_fields_for_api(tpl, ir_card)

    targets = _rule_escalation_targets(
        finding_api_id=summary.get('api_id') or '',
        finding_path=summary.get('path') or '',
        bindable_fields=bindable,
        graph=graph,
        templates_by_id=templates_by_id,
        object_pool=object_pool,
        ir_session=ir_session,
        chain_nodes=chain_nodes,
        exclude_apis=exclude_apis,
        limit=max_targets,
    )
    test_cases = _materialize_m7_cases(
        targets,
        baseline_context=baseline_context,
        object_pool=object_pool,
        ir_session=ir_session,
        finding_id=finding_id,
        chain_id=chain_id,
    )
    fork_seeds = [
        {
            'api_id': t.get('api_id'),
            'path': t.get('path'),
            'strategy': t.get('strategy'),
            'hypothesis_id': f'esc_{finding_id}_{t.get("api_id")}',
        }
        for t in targets[:3]
    ]
    return {
        'finding_id': finding_id,
        'finding_summary': summary,
        'bindable_fields': bindable,
        'targets': targets,
        'test_cases': test_cases,
        'fork_seeds': fork_seeds,
        'target_count': len(targets),
        'test_count': len(test_cases),
    }
