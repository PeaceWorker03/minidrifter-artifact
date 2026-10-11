# -*- coding: utf-8
"""Inject object-flow anchors from pool into consumer materialized templates."""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from minidrifter.core.utils import write_json
from minidrifter.graph.object_flow_chain_synthesizer import (
    _CONSUMER_PATH_HINTS,
    _consumer_fields_for_template,
    _fields_match,
)
from minidrifter.materials.intake_param_hints import normalize_api_path
from minidrifter.materials.object_pool_writer import load_baseline_field_pool

SCHEMA_VERSION = '1.0.0'
INJECTED_BY = 'object_flow_anchor_materializer'


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _load_json(path: Path) -> Any:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding='utf-8'))


def _cards_by_path(pack_dir: Path) -> Dict[str, Dict[str, Any]]:
    ir = _load_json(pack_dir / 'universal_ir' / 'universal_api_cards.json') or {}
    out: Dict[str, Dict[str, Any]] = {}
    for card in (ir.get('items') or ir.get('cards') or []):
        p = normalize_api_path(card.get('path') or '')
        if p:
            out[p] = card
    return out


def _param_bags(plain: Dict[str, Any]) -> List[Tuple[str, Dict[str, Any]]]:
    bags: List[Tuple[str, Dict[str, Any]]] = []
    for name in ('body_params', 'params', 'query_params'):
        bag = plain.get(name)
        if isinstance(bag, dict):
            bags.append((name, bag))
    return bags


def _find_param_key(bags: List[Tuple[str, Dict[str, Any]]], field: str) -> Optional[Tuple[str, str]]:
    want = re.sub(r'[_\-\s]', '', field).lower()
    for bag_name, bag in bags:
        for k in bag:
            if re.sub(r'[_\-\s]', '', k).lower() == want:
                return bag_name, k
    return None


def _path_hint_matches(object_field: str, consumer_path: str) -> bool:
    hints = _CONSUMER_PATH_HINTS.get(object_field) or ()
    low = normalize_api_path(consumer_path).lower()
    return any(h in low for h in hints)


def anchor_injection_allowed(
    *,
    object_field: str,
    consumer_path: str,
    template: Dict[str, Any],
    ir_card: Optional[Dict[str, Any]] = None,
    chain_doc: Optional[Dict[str, Any]] = None,
) -> Tuple[bool, str]:
    """Conservative gate — require field/path/card/flow evidence before injection."""
    plain = template.get('plain_template') or {}
    bags = _param_bags(plain)
    cards_by_path = {consumer_path: ir_card} if ir_card else {}

    cons_fields = _consumer_fields_for_template(template, cards_by_path=cards_by_path)
    if any(_fields_match(object_field, cf) for cf in cons_fields):
        return True, 'template_or_card_field_evidence'

    if _find_param_key(bags, object_field):
        return True, 'template_param_key'

    for p in ((ir_card or {}).get('bindings') or {}).get('params') or []:
        name = p.get('name') or ''
        if _fields_match(object_field, name):
            return True, 'ir_binding'

    if _path_hint_matches(object_field, consumer_path):
        of = (chain_doc or {}).get('object_flow') or {}
        if of.get('object_field') == object_field or object_field in (chain_doc or {}).get('binding_fields') or []:
            return True, 'object_flow_path_hint'

    of = (chain_doc or {}).get('object_flow') or {}
    loc = of.get('consumer_location') or ''
    if loc and object_field.lower() in loc.lower():
        return True, 'object_flow_consumer_location'

    return False, 'insufficient_anchor_evidence'


def _resolve_anchor_value(
    object_field: str,
    *,
    chain_doc: Dict[str, Any],
    pool_values: Dict[str, Any],
) -> Tuple[Optional[str], Optional[str]]:
    of = chain_doc.get('object_flow') or {}
    if of.get('object_value') not in (None, ''):
        return str(of['object_value']), of.get('object_source')
    if object_field in pool_values and pool_values[object_field] not in (None, ''):
        src = (chain_doc.get('object_flow') or {}).get('object_source')
        return str(pool_values[object_field]), src
    for k, v in pool_values.items():
        if _fields_match(object_field, k) and v not in (None, ''):
            return str(v), of.get('object_source')
    return None, None


def _inject_into_template(
    template: Dict[str, Any],
    *,
    object_field: str,
    value: str,
    provenance: str,
    chain_id: str,
    reason: str,
) -> bool:
    plain = template.setdefault('plain_template', {})
    bags = _param_bags(plain)
    if not bags:
        plain['body_params'] = {}
        bags = [('body_params', plain['body_params'])]

    found = _find_param_key(bags, object_field)
    if found:
        bag_name, key = found
        target_bag = plain[bag_name]
    else:
        bag_name, target_bag = bags[0]
        key = object_field

    prior = target_bag.get(key)
    target_bag[key] = value if not isinstance(value, (int, float)) else value

    injections = template.setdefault('object_flow_anchor_injections', [])
    injections.append({
        'field': key,
        'value': value,
        'prior_value': prior,
        'source': 'object_pool',
        'provenance': provenance,
        'chain_id': chain_id,
        'injected_by': INJECTED_BY,
        'reason': reason,
        'bag': bag_name,
    })
    template['object_flow_anchor_field'] = key
    return True


def _collect_chain_anchors(pack_dir: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    seen: Set[Tuple[str, str]] = set()
    for fname in ('object_flow_chains.json', 'high_risk_api_chains.json'):
        doc = _load_json(pack_dir / fname) or {}
        for chain in (doc.get('chains') or doc.get('high_risk_chains') or []):
            consumer = normalize_api_path(
                chain.get('target_path') or chain.get('consumer_api') or '',
            )
            of = chain.get('object_flow') or {}
            field = (
                of.get('object_field')
                or (chain.get('binding_fields') or [None])[0]
                or (chain.get('objects') or [None])[0]
            )
            if not consumer or not field:
                continue
            key = (consumer, field)
            if key in seen:
                continue
            seen.add(key)
            rows.append({
                'chain_id': chain.get('chain_id'),
                'consumer_path': consumer,
                'consumer_api_id': chain.get('target_hop') or chain.get('consumer_api_id'),
                'object_field': field,
                'chain_doc': chain,
            })
    return rows


def inject_object_flow_anchors(pack_dir: Path, *, write: bool = True) -> Dict[str, Any]:
    """Inject pool-backed object anchors into consumer materialized templates."""
    pack_dir = Path(pack_dir)
    tmpl_doc = _load_json(pack_dir / 'materialized_api_templates.json') or {}
    templates = tmpl_doc.get('templates') or []
    if not templates:
        return {'injected': 0, 'skipped': 0, 'reason': 'no_templates'}

    pool = load_baseline_field_pool(pack_dir)
    values = pool.get('fields') or {}
    cards_by_path = _cards_by_path(pack_dir)
    tpl_by_path = {normalize_api_path(t.get('path') or ''): t for t in templates if t.get('path')}
    tpl_by_id = {t.get('api_id'): t for t in templates if t.get('api_id')}

    injected = 0
    skipped = 0
    details: List[Dict[str, Any]] = []

    for row in _collect_chain_anchors(pack_dir):
        consumer_path = row['consumer_path']
        object_field = row['object_field']
        chain_doc = row['chain_doc']
        tpl = tpl_by_path.get(consumer_path)
        if not tpl:
            cid = row.get('consumer_api_id')
            tpl = tpl_by_id.get(cid) if cid else None
        if not tpl:
            skipped += 1
            details.append({'consumer_path': consumer_path, 'field': object_field, 'status': 'no_template'})
            continue

        allowed, reason = anchor_injection_allowed(
            object_field=object_field,
            consumer_path=consumer_path,
            template=tpl,
            ir_card=cards_by_path.get(consumer_path),
            chain_doc=chain_doc,
        )
        if not allowed:
            skipped += 1
            details.append({'consumer_path': consumer_path, 'field': object_field, 'status': 'blocked', 'reason': reason})
            continue

        value, provenance = _resolve_anchor_value(object_field, chain_doc=chain_doc, pool_values=values)
        if not value:
            skipped += 1
            details.append({'consumer_path': consumer_path, 'field': object_field, 'status': 'no_pool_value'})
            continue

        if _inject_into_template(
            tpl,
            object_field=object_field,
            value=value,
            provenance=provenance or '',
            chain_id=row.get('chain_id') or '',
            reason=reason,
        ):
            injected += 1
            details.append({
                'consumer_path': consumer_path,
                'field': object_field,
                'value': value,
                'status': 'injected',
                'reason': reason,
            })

    report = {
        'schema_version': SCHEMA_VERSION,
        'generated_at': _utc_now(),
        'pack_dir': str(pack_dir),
        'injected_count': injected,
        'skipped_count': skipped,
        'details': details[:80],
    }

    if write and templates:
        tmpl_doc['object_flow_anchor_materialization'] = report
        write_json(pack_dir / 'materialized_api_templates.json', tmpl_doc)
        write_json(pack_dir / 'object_flow_anchor_materialization.json', report)

    return report
