# -*- coding: utf-8
"""Synthesize producer→consumer chains from object pool + materialized API evidence."""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from minidrifter.core.utils import stable_id, write_json
from minidrifter.graph.semantic_workflow_graph import (
    infer_domain_from_path,
    list_detail_score,
)
from minidrifter.materials.intake_param_hints import normalize_api_path
from minidrifter.materials.object_pool_writer import load_baseline_field_pool, pool_has

SCHEMA_VERSION = '1.0.0'

_LIST_PATH_HINTS = re.compile(
    r'list|query|search|getall|records|historylist|orderlist', re.I,
)
_DETAIL_PATH_HINTS = re.compile(
    r'detail|info|getbyid|cardorder|verify|routing|cancelconfirm', re.I,
)

_FIELD_ALIASES: Dict[str, Set[str]] = {
    'orderid': {'orderid', 'order_id', 'id'},
    'taskid': {'taskid', 'task_id'},
    'memberid': {'memberid', 'member_id', 'userid', 'user_id'},
    'deptid': {'deptid', 'dept_id', 'storeid'},
    'cardid': {'cardid', 'card_id', 'couponid'},
}

_CONSUMER_PATH_HINTS: Dict[str, Tuple[str, ...]] = {
    'orderId': ('orderdetail', 'cardorder', 'cancelconfirm', 'routing', 'returnedorder'),
    'taskId': ('pickuptask', 'deposit/task', '/task/'),
    'deptId': ('deptdetail', 'deptguidedetail', 'querydept'),
    'memberId': ('memberidentity', 'identitycard'),
    'cardId': ('cardsku', 'coupon', 'equity'),
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _load_json(path: Path) -> Any:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding='utf-8'))


def _norm_field(field: str) -> str:
    return re.sub(r'[_\-\s]', '', str(field or '')).lower()


def _fields_match(producer_field: str, consumer_field: str) -> bool:
    pf = _norm_field(producer_field)
    cf = _norm_field(consumer_field)
    if pf == cf:
        return True
    for canon, aliases in _FIELD_ALIASES.items():
        if pf in aliases | {canon} and cf in aliases | {canon}:
            return True
    return False


def _path_role(path: str) -> str:
    low = normalize_api_path(path).lower()
    if _LIST_PATH_HINTS.search(low):
        return 'list'
    if _DETAIL_PATH_HINTS.search(low):
        return 'detail'
    return 'other'


def _consumer_fields_for_template(
    template: Dict[str, Any],
    *,
    cards_by_path: Dict[str, Dict[str, Any]],
) -> List[str]:
    from minidrifter.verification.finding_escalation_planner import bindable_fields_for_api

    path = normalize_api_path(template.get('path') or '')
    card = cards_by_path.get(path)
    fields = [b['field'] for b in bindable_fields_for_api(template, card)]
    plain = template.get('plain_template') or {}
    for bag in (plain.get('params'), plain.get('body_params'), template.get('params')):
        if isinstance(bag, dict):
            for k in bag:
                if k.endswith('Id') or k.lower().endswith('id'):
                    fields.append(k)
    return list(dict.fromkeys(fields))


def _template_by_path(templates: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for tpl in templates:
        p = normalize_api_path(tpl.get('path') or '')
        if p:
            out[p] = tpl
    return out


def _risk_by_path(pack_dir: Path) -> Dict[str, Dict[str, Any]]:
    doc = _load_json(pack_dir / 'binding_risk_candidates.json') or {}
    out: Dict[str, Dict[str, Any]] = {}
    for row in doc.get('candidates') or []:
        p = normalize_api_path(row.get('path') or '')
        if p:
            out[p] = row
    return out


def _score_object_flow_edge(
    *,
    producer_api: str,
    consumer_api: str,
    object_field: str,
    object_type: str,
    pool_confidence: float,
    materialized: bool,
) -> Tuple[float, List[str]]:
    score = 0.35 + pool_confidence * 0.25
    evidence: List[str] = [
        f'producer response contains {object_field}',
        f'object_pool has real value for {object_field}',
    ]
    prod_dom = infer_domain_from_path(producer_api)
    cons_dom = infer_domain_from_path(consumer_api)
    if prod_dom == cons_dom and prod_dom != 'general':
        score += 0.12
        evidence.append(f'both APIs in {prod_dom} domain')
    ld = list_detail_score(producer_api, consumer_api)
    if ld >= 0.55:
        score += ld * 0.18
        evidence.append('list/detail path continuity')
    if _path_role(producer_api) == 'list':
        score += 0.08
        evidence.append('producer path looks like list API')
    if _path_role(consumer_api) == 'detail':
        score += 0.08
        evidence.append('consumer path looks like detail API')
    hints = _CONSUMER_PATH_HINTS.get(object_field, ())
    if any(h in consumer_api.lower() for h in hints):
        score += 0.1
        evidence.append('consumer path matches object-field hint')
    if materialized:
        score += 0.12
        evidence.append('consumer API materialized and replay-ready')
    return min(score, 0.99), evidence


def _make_hop(
    tpl: Dict[str, Any],
    *,
    role: str,
    produces: Optional[List[str]] = None,
    consumes: Optional[List[str]] = None,
) -> Dict[str, Any]:
    produces = list(produces or [])
    consumes = list(consumes or [])
    mutation = list(consumes) if role == 'consumer' else []
    mat = tpl.get('status') in {'materialized_plain', 'materialized_with_crypto_profile', 'replay_ready'}
    return {
        'api_id': tpl.get('api_id') or '',
        'path': tpl.get('path') or '',
        'role': role,
        'produces': produces,
        'requires': list(consumes),
        'consumes': consumes,
        'mutation_targets': mutation,
        'side_effect': tpl.get('side_effect_level') or 'S0_read_only',
        'materialized': mat,
        'static_constructible': False,
        'request_template_partial': False,
        'request_template_ready': mat,
        'runtime_replay_ready': mat,
        'entry_seed_available': role == 'producer',
        'replay_readiness': 'ready' if mat else 'blocked',
        'replay_blockers': [] if mat else ['template_not_materialized'],
        'materialized_reason': 'object_flow_synthesis',
    }


def _build_chain_doc(
    edge: Dict[str, Any],
    *,
    producer_tpl: Dict[str, Any],
    consumer_tpl: Dict[str, Any],
    risk_row: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    producer_api = edge['producer_api']
    consumer_api = edge['consumer_api']
    object_field = edge['object_field']
    object_type = edge['object_type']
    producer_id = producer_tpl.get('api_id') or ''
    consumer_id = consumer_tpl.get('api_id') or ''
    chain_id = stable_id(
        'of_chain', object_type, producer_id, consumer_id, object_field,
    )
    domain = infer_domain_from_path(consumer_api) or object_type
    risk_score = float((risk_row or {}).get('rule_score') or 0)
    tier = 'high' if risk_score >= 70 or edge.get('confidence', 0) >= 0.85 else 'medium'
    return {
        'chain_id': chain_id,
        'chain_source': 'runtime_object_flow',
        'chain_type': 'OBJECT_FLOW',
        'campaign_phase': 'A2',
        'domain': domain,
        'entry_api': producer_id,
        'entry_path': producer_api,
        'target_hop': consumer_id,
        'target_path': consumer_api,
        'binding_fields': [object_field],
        'objects': [object_field],
        'primary_mutation_targets': [object_field],
        'binding_risk_tier': tier,
        'risk_hops': [consumer_id],
        'object_flow': {
            'edge_type': 'object_flow',
            'producer_api': producer_api,
            'consumer_api': consumer_api,
            'object_type': object_type,
            'object_field': object_field,
            'producer_path': edge.get('producer_path'),
            'consumer_location': edge.get('consumer_location'),
            'confidence': edge.get('confidence'),
            'evidence': edge.get('evidence') or [],
            'object_value': edge.get('object_value'),
            'object_source': edge.get('object_source'),
            'already_in_static_chains': edge.get('already_in_static_chains'),
        },
        'hops': [
            _make_hop(producer_tpl, role='producer', produces=[object_field]),
            _make_hop(consumer_tpl, role='consumer', consumes=[object_field]),
        ],
        'runtime_status': 'runnable',
        'verification_mode': 'chain_first',
        'fallback_mode': 'direct_probe',
        'entry_runtime_replay_ready': True,
        'consumer_runtime_replay_ready': True,
        'score': edge.get('confidence', 0) * 100 + risk_score * 0.3,
    }


def synthesize_object_flow_chains(pack_dir: Path) -> Dict[str, Any]:
    """Build object-flow chains and high-risk API chains from pool + templates."""
    pack_dir = Path(pack_dir)
    pool = load_baseline_field_pool(pack_dir)
    values = pool['fields']
    field_names = pool['field_names']

    obj_doc = _load_json(pack_dir / 'object_pool.json') or {}
    pool_objects = obj_doc.get('objects') or []

    tmpl_doc = _load_json(pack_dir / 'materialized_api_templates.json') or {}
    templates = tmpl_doc.get('templates') or []
    ready_paths = {
        normalize_api_path(r.get('path') or '')
        for r in (tmpl_doc.get('ready_for_replay') or [])
        if r.get('status') == 'materialized_with_crypto_profile'
    }
    tpl_by_path = _template_by_path(templates)

    ir = _load_json(pack_dir / 'universal_ir' / 'universal_api_cards.json') or {}
    cards_by_path = {}
    cards_by_id = {}
    for card in (ir.get('items') or ir.get('cards') or []):
        p = normalize_api_path(card.get('path') or '')
        if p:
            cards_by_path[p] = card
        aid = card.get('api_id') or card.get('card_id')
        if aid:
            cards_by_id[aid] = card

    risk_by_path = _risk_by_path(pack_dir)
    static_paths = {
        normalize_api_path(c.get('target_path') or '')
        for c in (_load_json(pack_dir / 'business_chains.json') or {}).get('chains') or []
    }

    edges: List[Dict[str, Any]] = []
    seen_pairs: Set[Tuple[str, str, str]] = set()

    for obj in pool_objects:
        object_field = obj.get('field') or ''
        object_type = obj.get('object_type') or 'generic'
        object_value = obj.get('value')
        src = obj.get('source') or {}
        producer_api = normalize_api_path(src.get('api') or '')
        producer_path = src.get('response_path')
        if not producer_api or not object_field:
            continue
        if not pool_has(object_field, field_names, values):
            continue

        producer_tpl = tpl_by_path.get(producer_api)
        if not producer_tpl:
            aid = src.get('api_id')
            if aid and aid in cards_by_id:
                producer_tpl = {
                    'api_id': aid,
                    'path': producer_api,
                    'status': 'materialized_with_crypto_profile' if producer_api in ready_paths else 'partial',
                }

        for cons_path, consumer_tpl in tpl_by_path.items():
            if cons_path == producer_api:
                continue
            if cons_path not in ready_paths:
                continue
            cons_fields = _consumer_fields_for_template(
                consumer_tpl, cards_by_path=cards_by_path,
            )
            if not any(_fields_match(object_field, cf) for cf in cons_fields):
                hints = _CONSUMER_PATH_HINTS.get(object_field, ())
                if not any(h in cons_path.lower() for h in hints):
                    continue
            key = (producer_api, cons_path, object_field)
            if key in seen_pairs:
                continue
            seen_pairs.add(key)

            conf, evidence = _score_object_flow_edge(
                producer_api=producer_api,
                consumer_api=cons_path,
                object_field=object_field,
                object_type=object_type,
                pool_confidence=float(obj.get('confidence') or src.get('confidence') or 0.8),
                materialized=True,
            )
            if conf < 0.45:
                continue

            prov = (
                f"{src.get('capture', '')}::{producer_api}::{producer_path or ''}"
            )
            edges.append({
                'edge_type': 'object_flow',
                'producer_api': producer_api,
                'consumer_api': cons_path,
                'object_type': object_type,
                'object_field': object_field,
                'producer_path': producer_path,
                'consumer_location': f'params.{object_field}',
                'confidence': round(conf, 3),
                'evidence': evidence,
                'object_value': object_value,
                'object_source': prov,
                'already_in_static_chains': cons_path in static_paths,
            })

    edges.sort(key=lambda x: -x.get('confidence', 0))
    chains: List[Dict[str, Any]] = []

    for edge in edges:
        prod_tpl = tpl_by_path.get(edge['producer_api'])
        cons_tpl = tpl_by_path.get(edge['consumer_api'])
        if not prod_tpl or not cons_tpl:
            continue
        risk_row = risk_by_path.get(edge['consumer_api'])
        chain = _build_chain_doc(edge, producer_tpl=prod_tpl, consumer_tpl=cons_tpl, risk_row=risk_row)
        chains.append(chain)

    chains.sort(key=lambda c: -(c.get('score') or 0))
    high_risk = [c for c in chains if c.get('binding_risk_tier') == 'high' or (c.get('object_flow') or {}).get('confidence', 0) >= 0.82]

    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': _utc_now(),
        'pack_dir': str(pack_dir),
        'summary': {
            'edge_count': len(edges),
            'chain_count': len(chains),
            'high_risk_chain_count': len(high_risk),
            'domains': sorted({c.get('domain') for c in chains if c.get('domain')}),
        },
        'edges': edges[:120],
        'chains': chains[:80],
        'high_risk_chains': high_risk[:40],
    }


def build_high_risk_api_chains(pack_dir: Path, flow_doc: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    flow_doc = flow_doc or synthesize_object_flow_chains(pack_dir)
    rows = flow_doc.get('high_risk_chains') or []
    if not rows:
        rows = [c for c in (flow_doc.get('chains') or []) if c.get('binding_risk_tier') == 'high']
    hr_rows = []
    for chain in rows:
        of = chain.get('object_flow') or {}
        hr_rows.append({
            'chain_id': chain.get('chain_id'),
            'chain_source': chain.get('chain_source'),
            'domain': chain.get('domain'),
            'producer_api': of.get('producer_api') or chain.get('entry_path'),
            'consumer_api': of.get('consumer_api') or chain.get('target_path'),
            'risk_api': of.get('consumer_api') or chain.get('target_path'),
            'object_type': of.get('object_type'),
            'binding_fields': chain.get('binding_fields') or [],
            'credential_anchor': ['token', 'uid', 'Authorization'],
            'object_anchor': chain.get('binding_fields') or [],
            'risk_type': 'identity_object_binding',
            'runtime_status': chain.get('runtime_status'),
            'verification_mode': chain.get('verification_mode'),
            'fallback_mode': chain.get('fallback_mode'),
            'evidence': {
                'object_value': of.get('object_value'),
                'object_source': of.get('object_source'),
                'materialized': True,
                'confidence': of.get('confidence'),
            },
        })
    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': _utc_now(),
        'pack_dir': str(pack_dir),
        'chain_count': len(flow_doc.get('chains') or []),
        'high_risk_count': len(hr_rows),
        'chains': hr_rows,
    }


def write_object_flow_artifacts(pack_dir: Path) -> Dict[str, str]:
    pack_dir = Path(pack_dir)
    flow_doc = synthesize_object_flow_chains(pack_dir)
    from minidrifter.business_chain.high_risk_api_chain_ranker import (
        rank_object_flow_chains,
        rank_high_risk_api_chains,
    )
    flow_doc['chains'] = rank_object_flow_chains(flow_doc.get('chains') or [])
    flow_doc['high_risk_chains'] = [
        c for c in flow_doc['chains']
        if c.get('binding_risk_tier') == 'high' or (c.get('object_flow') or {}).get('confidence', 0) >= 0.82
    ][:40]
    hr_doc = build_high_risk_api_chains(pack_dir, flow_doc)
    hr_doc['chains'] = rank_high_risk_api_chains(hr_doc.get('chains') or [])

    flow_path = pack_dir / 'object_flow_chains.json'
    hr_path = pack_dir / 'high_risk_api_chains.json'
    write_json(flow_path, flow_doc)
    write_json(hr_path, hr_doc)
    return {
        'object_flow_chains': str(flow_path),
        'high_risk_api_chains': str(hr_path),
    }
