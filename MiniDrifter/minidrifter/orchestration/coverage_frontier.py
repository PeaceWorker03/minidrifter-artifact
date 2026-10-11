# -*- coding: utf-8
"""Unified API coverage frontier — L0-L5 tiers and frontier buckets."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from minidrifter.business_chain.high_risk_api_chain_ranker import (
    is_identity_relevant_path,
    is_low_value_path,
)
from minidrifter.core.utils import write_json
from minidrifter.graph.semantic_workflow_graph import infer_domain_from_path
from minidrifter.materials.intake_param_hints import normalize_api_path
from minidrifter.materials.object_pool_writer import load_baseline_field_pool, pool_has
from minidrifter.verification.pack_loader import load_field_ontology, load_safety_policy_pack
from minidrifter.verification.safety_policy import evaluate_test_safety, _path_blocked

SCHEMA_VERSION = '1.0.0'


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _load_json(path: Path) -> Any:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding='utf-8'))


def _identity_fields_for_api(path: str, template: Optional[Dict[str, Any]], risk_row: Optional[Dict[str, Any]]) -> List[str]:
    fields: List[str] = []
    if risk_row:
        for sig in risk_row.get('risk_signals') or []:
            if isinstance(sig, str) and sig.startswith('identity_params:'):
                fields.extend(x.strip() for x in sig.split(':', 1)[1].split(',') if x.strip())
    if template:
        plain = template.get('plain_template') or {}
        for bag in (plain.get('body_params'), plain.get('params'), template.get('params')):
            if isinstance(bag, dict):
                for k in bag:
                    if k.endswith('Id') or k.lower().endswith('id'):
                        fields.append(k)
    return list(dict.fromkeys(fields))


def _is_identity_object_relevant(
    path: str,
    *,
    id_fields: List[str],
    risk_row: Optional[Dict[str, Any]],
) -> bool:
    if id_fields:
        return True
    if risk_row and (risk_row.get('probe_eligible') or float(risk_row.get('rule_score') or 0) >= 65):
        return True
    if is_identity_relevant_path(path):
        return True
    ont = load_field_ontology() or {}
    obj_ids = set(ont.get('field_classes', {}).get('object_identifier') or [])
    sub_ids = set(ont.get('field_classes', {}).get('subject_credential') or [])
    return bool((obj_ids | sub_ids) & set(id_fields))


def build_coverage_frontier(pack_dir: Path) -> Dict[str, Any]:
    """Classify every static API into L0-L5 tiers and frontier buckets."""
    pack_dir = Path(pack_dir)
    ctx = _load_json(pack_dir / 'baseline_runtime_context.json') or {}
    ir = _load_json(pack_dir / 'universal_ir' / 'universal_api_cards.json') or {}
    tmpl_doc = _load_json(pack_dir / 'materialized_api_templates.json') or {}
    risk_doc = _load_json(pack_dir / 'binding_risk_candidates.json') or {}
    unlock = _load_json(pack_dir / 'baseline_unlock_matrix.json') or {}
    flow_doc = _load_json(pack_dir / 'object_flow_chains.json') or {}
    batch = _load_json(pack_dir / 'chain_batch_report.json') or {}
    findings_doc = _load_json(pack_dir / 'finding_registry.json') or {}
    pool = load_baseline_field_pool(pack_dir)
    policy = load_safety_policy_pack()

    cards = ir.get('items') or ir.get('cards') or []
    templates = {t['api_id']: t for t in (tmpl_doc.get('templates') or []) if t.get('api_id')}
    ready_paths = {
        normalize_api_path(r.get('path') or '')
        for r in (tmpl_doc.get('ready_for_replay') or [])
        if r.get('status') == 'materialized_with_crypto_profile'
    }
    risk_by_path = {
        normalize_api_path(c.get('path') or ''): c
        for c in (risk_doc.get('candidates') or [])
        if c.get('path')
    }

    m0_paths: Set[str] = set()
    m7_paths: Set[str] = set()
    finding_paths: Set[str] = set()
    clean_paths: Set[str] = set()

    for row in batch.get('chain_results') or []:
        p = normalize_api_path(row.get('target_path') or '')
        if not p:
            continue
        if row.get('reached_m7'):
            m7_paths.add(p)
            m0_paths.add(p)
            if row.get('findings'):
                finding_paths.add(p)
            elif row.get('verdict') == 'chain_completed_no_drift':
                clean_paths.add(p)
        elif row.get('http_calls'):
            m0_paths.add(p)

    for pr in ((batch.get('risk_probe') or {}).get('results') or []):
        p = normalize_api_path(pr.get('path') or '')
        if not p:
            continue
        if pr.get('m0_outcome') == 'business_success' or pr.get('http_calls'):
            m0_paths.add(p)
        if pr.get('reached_m7'):
            m7_paths.add(p)
            if pr.get('findings'):
                finding_paths.add(p)
            else:
                clean_paths.add(p)

    for f in findings_doc.get('findings') or findings_doc.get('items') or []:
        p = normalize_api_path(f.get('api_path') or f.get('path') or '')
        if p:
            finding_paths.add(p)

    attempted_chain_ids = {r.get('chain_id') for r in batch.get('chain_results') or []}
    verified_chains = [
        r for r in (batch.get('chain_results') or [])
        if r.get('reached_m7')
    ]

    l0_apis: List[Dict[str, Any]] = []
    l1_apis: List[Dict[str, Any]] = []
    l2_apis: List[Dict[str, Any]] = []
    l3_apis: List[Dict[str, Any]] = []
    l4_apis: List[Dict[str, Any]] = []
    l5_apis: List[Dict[str, Any]] = []

    materialized_unverified: List[Dict[str, Any]] = []
    safety_blocked: List[Dict[str, Any]] = []
    blocked_missing_material: List[Dict[str, Any]] = []
    low_value_skipped: List[Dict[str, Any]] = []
    verified_apis: List[Dict[str, Any]] = []

    for card in cards:
        path = normalize_api_path(card.get('path') or '')
        api_id = card.get('api_id') or card.get('card_id') or ''
        if not path:
            continue
        domain = infer_domain_from_path(path)
        tpl = templates.get(api_id) or {}
        risk_row = risk_by_path.get(path)
        id_fields = _identity_fields_for_api(path, tpl, risk_row)
        materialized = (
            path in ready_paths
            or tpl.get('status') in {'materialized_with_crypto_profile', 'materialized_plain'}
        )
        identity_rel = _is_identity_object_relevant(path, id_fields=id_fields, risk_row=risk_row)

        row = {
            'api_id': api_id,
            'path': path,
            'domain': domain,
            'identity_relevant': identity_rel,
            'required_objects': id_fields,
        }
        l0_apis.append({**row, 'tier': 'L0_static_recovered'})

        if not materialized:
            continue
        l1_apis.append({**row, 'tier': 'L1_materialized'})

        side = tpl.get('side_effect_level') or 'S0_read_only'
        tc_stub = {
            'path': path,
            'api_id': api_id,
            'side_effect_level': side,
            'status': tpl.get('status'),
            'template_status': tpl.get('status'),
            'plain_template': tpl.get('plain_template') or {},
            'missing_slots': tpl.get('missing_slots') or [],
            'crypto_required': tpl.get('transport_hint') == 'encrypted',
        }
        safety = evaluate_test_safety(tc_stub, baseline_context=ctx, only_safe=True, mode='execute', policy=policy)
        path_blocked = _path_blocked(path, policy.get('blocked_path_patterns') or [])

        missing_objs = [f for f in id_fields if not pool_has(f, pool['field_names'], pool['fields'])]
        if path_blocked or not safety.allowed:
            safety_blocked.append({
                **row,
                'reasons': safety.reasons or (['path_blocked'] if path_blocked else []),
            })
            continue

        if missing_objs and identity_rel:
            blocked_missing_material.append({**row, 'missing_fields': missing_objs})
            continue

        if not identity_rel and is_low_value_path(path):
            low_value_skipped.append({**row, 'reason': 'low_value_non_identity'})
            continue

        if not identity_rel and float((risk_row or {}).get('rule_score') or 0) < 50:
            low_value_skipped.append({**row, 'reason': 'low_risk_non_identity'})
            continue

        l2_apis.append({**row, 'tier': 'L2_runnable'})

        if path in m0_paths:
            l3_apis.append({**row, 'tier': 'L3_reached_m0'})
        if path in m7_paths:
            l4_apis.append({**row, 'tier': 'L4_reached_m7', 'covered_via': _coverage_via(batch, path)})
            verified_apis.append({**row, 'covered_via': _coverage_via(batch, path)})
        if path in finding_paths:
            l5_apis.append({**row, 'tier': 'L5_finding', 'status': 'finding'})
        elif path in clean_paths:
            l5_apis.append({**row, 'tier': 'L5_clean', 'status': 'clean'})
        elif path in m7_paths:
            l5_apis.append({**row, 'tier': 'L5_clean', 'status': 'clean_pending_review'})

        if materialized and path not in m0_paths and identity_rel:
            materialized_unverified.append(row)

    unlocked_unscheduled: List[Dict[str, Any]] = []
    for chain in (flow_doc.get('chains') or []):
        cid = chain.get('chain_id')
        if cid in attempted_chain_ids:
            continue
        if chain.get('runtime_status') != 'runnable':
            continue
        unlocked_unscheduled.append({
            'chain_id': cid,
            'chain_source': chain.get('chain_source'),
            'producer_api': chain.get('entry_path'),
            'consumer_api': chain.get('target_path'),
            'binding_fields': chain.get('binding_fields'),
            'domain': chain.get('domain'),
        })

    for row in unlock.get('blocked_chains') or []:
        for api in (row.get('consumer_api'), row.get('target_path')):
            if api and normalize_api_path(api) not in {normalize_api_path(x.get('path', '')) for x in blocked_missing_material}:
                blocked_missing_material.append({
                    'path': api,
                    'chain_id': row.get('chain_id'),
                    'missing_fields': row.get('missing_fields'),
                    'domain': row.get('domain'),
                })

    large_scale_set = len(l2_apis)
    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': _utc_now(),
        'pack_dir': str(pack_dir),
        'definition': (
            'Large-scale Campaign = Static recovered ∩ Materializable ∩ Safety-allowed '
            '∩ Identity/Object-relevant APIs'
        ),
        'summary': {
            'L0_static_recovered': len(l0_apis),
            'L1_materialized': len(l1_apis),
            'L2_runnable': len(l2_apis),
            'L3_reached_m0': len(l3_apis),
            'L4_reached_m7': len(l4_apis),
            'L5_finding_or_clean': len(l5_apis),
            'large_scale_campaign_eligible': large_scale_set,
            'verified_api_count': len(verified_apis),
            'verified_chain_count': len(verified_chains),
            'materialized_unverified_count': len(materialized_unverified),
            'unlocked_unscheduled_chain_count': len(unlocked_unscheduled),
            'blocked_missing_material_count': len(blocked_missing_material),
            'safety_blocked_count': len(safety_blocked),
            'low_value_skipped_count': len(low_value_skipped),
        },
        'tiers': {
            'L0_static_recovered': l0_apis[:200],
            'L1_materialized': l1_apis[:120],
            'L2_runnable': l2_apis[:80],
            'L3_reached_m0': l3_apis[:80],
            'L4_reached_m7': l4_apis[:60],
            'L5_finding_or_clean': l5_apis[:60],
        },
        'frontier': {
            'verified_apis': verified_apis[:60],
            'verified_chains': verified_chains[:40],
            'materialized_unverified': materialized_unverified[:40],
            'unlocked_unscheduled_chains': unlocked_unscheduled[:40],
            'blocked_missing_material': blocked_missing_material[:30],
            'safety_blocked': safety_blocked[:30],
            'low_value_skipped': low_value_skipped[:40],
        },
        'deferred_material_gaps': unlock.get('deferred_material_gaps') or [],
    }


def _coverage_via(batch: Dict[str, Any], path: str) -> str:
    norm = normalize_api_path(path)
    for row in batch.get('chain_results') or []:
        if normalize_api_path(row.get('target_path') or '') == norm:
            return row.get('covered_via') or (
                'object_flow_chain' if row.get('campaign_phase') == 'A2' else 'static_chain'
            )
    for pr in ((batch.get('risk_probe') or {}).get('results') or []):
        if normalize_api_path(pr.get('path') or '') == norm and pr.get('reached_m7'):
            return 'direct_probe'
    return 'unknown'


def write_coverage_frontier(pack_dir: Path, doc: Optional[Dict[str, Any]] = None) -> Path:
    pack_dir = Path(pack_dir)
    frontier = doc or build_coverage_frontier(pack_dir)
    out = pack_dir / 'coverage_frontier.json'
    write_json(out, frontier)
    return out
