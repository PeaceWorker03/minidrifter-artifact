# -*- coding: utf-8 -*-
"""Direct M0+M7 probes for probe_eligible APIs not reached via chain batch."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from minidrifter.business_chain.chain_run_context import load_json
from minidrifter.core.utils import write_json
from minidrifter.materials.intake_param_hints import load_intake_report, normalize_api_path
from minidrifter.verification.campaign_planner import build_test_case
from minidrifter.verification.chain_object_pool import ChainObjectPool
from minidrifter.verification.chain_strict_runner import HOP_STATUS_OK
from minidrifter.verification.credential_probe_planner import plan_intelligent_binding_campaign
from minidrifter.verification.executor import execute_test_case
from minidrifter.verification.pack_loader import load_field_ontology
from minidrifter.verification.hop_policy import collect_baseline_business_fields, inherit_baseline_params
from minidrifter.verification.response_oracle import analyze_response
from minidrifter.verification.safety_policy import evaluate_test_safety


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def select_uncovered_risk_probes(
    pack_dir: Path,
    *,
    covered_paths: Set[str],
    max_probes: int,
) -> List[Dict[str, Any]]:
    """Pick probe_eligible APIs not already covered by chain M7."""
    pack_dir = Path(pack_dir)
    risk_doc = load_json(pack_dir / 'binding_risk_candidates.json') or {}
    unlock = load_json(pack_dir / 'baseline_unlock_matrix.json') or {}
    rows = [
        c for c in (risk_doc.get('candidates') or [])
        if c.get('probe_eligible') and c.get('materialized') and c.get('replay_ready')
    ]
    for row in (unlock.get('pool_unlocked_materialized_apis') or []):
        rows.append({
            'api_id': row.get('api_id'),
            'path': row.get('api') or row.get('path'),
            'rule_score': row.get('rule_score') or 72.0,
            'combined_score': row.get('rule_score') or 72.0,
            'materialized': True,
            'replay_ready': True,
            'probe_eligible': True,
            'verification_intent': 'pool_unlocked_materialized',
            'required_objects': row.get('required_objects') or [],
        })
    rows.sort(key=lambda x: -(float(x.get('combined_score') or x.get('rule_score') or 0)))
    out: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    for row in rows:
        path = normalize_api_path(row.get('path') or '')
        if not path or path in covered_paths or path in seen:
            continue
        seen.add(path)
        out.append(row)
        if len(out) >= max_probes:
            break
    return out


def _load_ir_card(pack_dir: Path, api_id: str) -> Optional[Dict[str, Any]]:
    """Optional IR card — skipped when pack uses flat api card list (too large to scan)."""
    path = pack_dir / 'all_api_cards.json'
    if not path.exists() or path.stat().st_size > 2_000_000:
        return None
    doc = load_json(path)
    if isinstance(doc, list):
        cards = doc
    elif isinstance(doc, dict):
        cards = doc.get('cards') or doc.get('api_cards') or []
    else:
        return None
    for card in cards:
        if not isinstance(card, dict):
            continue
        if card.get('api_id') == api_id or card.get('card_id') == api_id:
            return card
    return None


def _baseline_object_fields(pool: Dict[str, str]) -> Set[str]:
    classes = (load_field_ontology() or {}).get('field_classes') or {}
    names: Set[str] = set()
    for group in ('object_identifier', 'chain_bridge_fields', 'subject_credential'):
        names.update(classes.get(group) or [])
    out: Set[str] = set()
    lower_map = {k.lower(): k for k in pool}
    for name in names:
        if name in pool:
            out.add(name)
        elif name.lower() in lower_map:
            out.add(lower_map[name.lower()])
    return out


def _hop_consumes_from_baseline(
    template: Dict[str, Any],
    baseline_context: Dict[str, Any],
    intake: Optional[Dict[str, Any]],
    *,
    ir_card: Optional[Dict[str, Any]] = None,
) -> List[str]:
    from minidrifter.verification.finding_escalation_planner import bindable_fields_for_api

    pool = collect_baseline_business_fields(baseline_context, intake)
    plain = template.get('plain_template') or {}
    keys: Set[str] = set()
    for bag in (plain.get('params'), plain.get('body_params'), template.get('params')):
        if isinstance(bag, dict):
            keys.update(str(k) for k in bag)
    bindable = {b['field'] for b in bindable_fields_for_api(template, ir_card)}
    bindable |= _baseline_object_fields(pool)
    consumes: List[str] = []
    seen: Set[str] = set()
    for field in sorted(keys | bindable):
        fl = field.lower()
        if fl in seen:
            continue
        if field in pool or fl in {k.lower() for k in pool}:
            consumes.append(field)
            seen.add(fl)
    for field in sorted(pool):
        fl = field.lower()
        if fl in seen:
            continue
        if field in bindable or fl in {b.lower() for b in bindable}:
            consumes.append(field)
            seen.add(fl)
    return consumes[:8]


def _count_http(executions: List[Dict[str, Any]]) -> int:
    return sum(1 for ex in executions if ex.get('executed') is not False)


def _probe_one_api(
    cand: Dict[str, Any],
    *,
    pack_dir: Path,
    baseline_context: Dict[str, Any],
    templates_by_id: Dict[str, Dict[str, Any]],
    mode: str,
    source_dir: Optional[Path],
    base_url: Optional[str],
    only_safe: bool,
    probe_role: str = 'risk_probe',
) -> Dict[str, Any]:
    api_id = cand.get('api_id') or ''
    path = cand.get('path') or ''
    template = templates_by_id.get(api_id)
    if not template:
        return {
            'api_id': api_id,
            'path': path,
            'status': 'no_template',
            'm0_outcome': None,
            'm7_count': 0,
            'reached_m7': False,
            'findings': 0,
            'http_calls': 0,
        }

    intake = load_intake_report(pack_dir)
    ir_card = _load_ir_card(pack_dir, api_id)
    hop = {
        'api_id': api_id,
        'path': path,
        'role': probe_role,
        'consumes': _hop_consumes_from_baseline(
            template, baseline_context, intake, ir_card=ir_card,
        ),
    }
    chain_pool = ChainObjectPool(f'{probe_role}_direct', static_hops=[hop])

    safety = evaluate_test_safety(
        build_test_case(template, baseline_context=baseline_context, index=9000),
        baseline_context=baseline_context,
        only_safe=only_safe,
        mode=mode,
    )
    if not safety.allowed and mode == 'execute':
        return {
            'api_id': api_id,
            'path': path,
            'status': 'safety_blocked',
            'm0_outcome': 'safety_blocked',
            'm7_count': 0,
            'reached_m7': False,
            'findings': 0,
            'http_calls': 0,
            'safety_reasons': safety.reasons,
        }

    if mode == 'dry-run':
        m0 = build_test_case(template, baseline_context=baseline_context, index=9000)
        m0 = inherit_baseline_params(
            m0, hop, baseline_context=baseline_context, intake_report=intake,
        )
        seed = {'api_id': api_id, 'path': path, 'template': template, 'seed_id': 'risk_probe'}
        campaign = plan_intelligent_binding_campaign(
            seed, m0, baseline_context=baseline_context, object_pool={'pools': {}},
            ir_card=ir_card,
        )
        m7_n = len(campaign.get('test_cases') or [])
        return {
            'api_id': api_id,
            'path': path,
            'status': 'dry_run_planned',
            'm0_outcome': 'dry_run',
            'm7_count': m7_n,
            'reached_m7': False,
            'findings': 0,
            'http_calls': 1 + m7_n,
        }

    m0 = build_test_case(template, baseline_context=baseline_context, index=9000)
    m0['test_stage'] = f'{probe_role}_m0'
    m0 = inherit_baseline_params(
        m0, hop, baseline_context=baseline_context, intake_report=intake,
    )
    m0 = chain_pool.apply_to_test_case(m0, hop)
    executions: List[Dict[str, Any]] = []
    analyses: List[Dict[str, Any]] = []

    ex0 = execute_test_case(
        m0, pack_dir=pack_dir, baseline_context=baseline_context,
        mode=mode, source_dir=source_dir, base_url=base_url,
    )
    a0 = analyze_response(ex0, m0, baseline_context=baseline_context, pack_dir=pack_dir)
    executions.append(ex0)
    analyses.append(a0)

    if a0.get('call_outcome') == HOP_STATUS_OK:
        seed = {'api_id': api_id, 'path': path, 'template': template, 'seed_id': 'risk_probe'}
        campaign = plan_intelligent_binding_campaign(
            seed, m0, baseline_context=baseline_context, object_pool={'pools': {}},
            ir_card=ir_card,
        )
        for mtc in campaign.get('test_cases') or []:
            mtc = chain_pool.apply_to_test_case(mtc, hop)
            mtc['test_stage'] = f'{probe_role}_m7'
            ex = execute_test_case(
                mtc, pack_dir=pack_dir, baseline_context=baseline_context,
                mode=mode, source_dir=source_dir, base_url=base_url,
            )
            analyses.append(analyze_response(ex, mtc, baseline_context=baseline_context, pack_dir=pack_dir))
            executions.append(ex)

    m0_out = (analyses[0] or {}).get('call_outcome') if analyses else None
    m7_analyses = analyses[1:] if len(analyses) > 1 else []
    findings = sum(
        1 for a in m7_analyses
        if 'subject_object_binding_mismatch' in (a.get('security_signals') or [])
    )
    reached_m7 = m0_out == HOP_STATUS_OK and bool(m7_analyses)
    status = 'm7_reached' if reached_m7 else ('m0_failed' if m0_out != HOP_STATUS_OK else 'm7_skipped')

    from minidrifter.verification.sensitive_read_metrics import attach_sensitive_read_metrics

    row = {
        'api_id': api_id,
        'path': path,
        'rule_score': cand.get('rule_score'),
        'status': status,
        'm0_outcome': m0_out,
        'm7_count': len(m7_analyses),
        'reached_m7': reached_m7,
        'findings': findings,
        'http_calls': _count_http(executions),
        'probe_role': probe_role,
    }
    return attach_sensitive_read_metrics(
        row,
        path=path,
        m0_analysis=analyses[0] if analyses else None,
        m0_execution=executions[0] if executions else None,
        m7_analyses=m7_analyses,
    )


def run_risk_probe_batch(
    pack_dir: Path,
    *,
    covered_paths: Set[str],
    mode: str = 'dry-run',
    max_probes: int = 15,
    max_http: int = 80,
    source_dir: Optional[Path] = None,
    base_url: Optional[str] = None,
    only_safe: bool = True,
    verbose: bool = False,
) -> Dict[str, Any]:
    """Probe uncovered probe_eligible APIs directly using baseline + M7 mutations."""
    pack_dir = Path(pack_dir)
    baseline_context = load_json(pack_dir / 'baseline_runtime_context.json') or {}
    tpl_doc = load_json(pack_dir / 'materialized_api_templates.json') or {}
    templates_by_id = {
        t['api_id']: t for t in (tpl_doc.get('templates') or []) if t.get('api_id')
    }

    selected = select_uncovered_risk_probes(
        pack_dir, covered_paths=covered_paths, max_probes=max_probes,
    )
    results: List[Dict[str, Any]] = []
    http_used = 0
    findings_total = 0

    if verbose:
        print(
            f'[MiniDrifter:risk_probe] selected={len(selected)} budget={max_http} mode={mode}',
            flush=True,
        )

    for i, cand in enumerate(selected):
        if http_used >= max_http:
            break
        if verbose:
            print(
                f'[MiniDrifter:risk_probe] {i+1}/{len(selected)} path={cand.get("path")}',
                flush=True,
            )
        row = _probe_one_api(
            cand,
            pack_dir=pack_dir,
            baseline_context=baseline_context,
            templates_by_id=templates_by_id,
            mode=mode,
            source_dir=source_dir,
            base_url=base_url,
            only_safe=only_safe,
        )
        calls = row.get('http_calls') or 0
        if http_used + calls > max_http and mode == 'execute':
            row['status'] = 'budget_exhausted'
            row['http_calls'] = 0
            results.append(row)
            break
        http_used += calls
        findings_total += row.get('findings') or 0
        results.append(row)

    doc = {
        'schema_version': '1.0.0',
        'generated_at': _utc_now(),
        'verify_mode': 'risk_probe',
        'max_probes': max_probes,
        'max_http': max_http,
        'http_calls_total': http_used,
        'probes_run': len(results),
        'probes_reached_m7': sum(1 for r in results if r.get('reached_m7')),
        'findings_total': findings_total,
        'results': results,
    }
    write_json(pack_dir / 'risk_probe_report.json', doc)
    return doc
