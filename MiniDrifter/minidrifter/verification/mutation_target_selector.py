# -*- coding: utf-8
"""Prioritize M7 mutation targets — object anchors before environment fields."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

IDENTITY_PROBE_ORDER = (
    'loginCustomerId',
    'customerId',
    'CustomerId',
    'fromCustomerId',
    'userId',
    'UserId',
    'platformUserId',
    'memberId',
    'openId',
)

ENVIRONMENT_FIELDS = frozenset({
    'cityid', 'city_id', 'deptid', 'dept_id', 'storeid', 'store_id',
    'page', 'pagesize', 'size', 'offset', 'limit', 'channel', 'lat', 'lon',
    'latitude', 'longitude', 'bucketidlist', 'estimatedpickuptime', 'estimatedreturntime',
})

OBJECT_FIELD_PRIORITY = {
    'orderid': 95, 'invoiceid': 92, 'paymentid': 90, 'memberid': 88,
    'userid': 85, 'taskid': 82, 'cardid': 80, 'couponid': 78,
    'addressid': 76, 'deviceid': 74, 'vehicleid': 72,
    'deptid': 45, 'cityid': 25, 'storeid': 40,
}


def _norm(field: str) -> str:
    return re.sub(r'[_\-\s]', '', (field or '')).lower()


def _load_ontology() -> Dict[str, Any]:
    try:
        import json
        from pathlib import Path
        path = Path(__file__).resolve().parents[2] / 'packs' / 'object_field_ontology.json'
        if path.exists():
            return json.loads(path.read_text(encoding='utf-8'))
    except Exception:
        pass
    return {}


def _field_priority(field: str, ontology: Dict[str, Any]) -> float:
    fp = ontology.get('field_priority') or OBJECT_FIELD_PRIORITY
    key = field if field in fp else field[0].lower() + field[1:] if field else field
    if key in fp:
        return float(fp[key])
    nl = _norm(field)
    for k, v in fp.items():
        if _norm(k) == nl:
            return float(v)
    if nl in ENVIRONMENT_FIELDS:
        return 10.0
    if nl.endswith('id'):
        return 60.0
    return 30.0


def chain_object_anchors(chain_doc: Optional[Dict[str, Any]] = None) -> List[str]:
    if not chain_doc:
        return []
    anchors: List[str] = []
    of = chain_doc.get('object_flow') or {}
    for src in (
        [of.get('object_field')],
        chain_doc.get('primary_mutation_targets') or [],
        chain_doc.get('binding_fields') or [],
        chain_doc.get('objects') or [],
    ):
        for item in src:
            if item and item not in anchors:
                anchors.append(item)
    return anchors


def prioritize_mutation_fields(
    fields: List[str],
    *,
    chain_doc: Optional[Dict[str, Any]] = None,
    ontology: Optional[Dict[str, Any]] = None,
) -> List[str]:
    """Order fields: object anchor → identity → medium-risk → environment."""
    if not fields:
        return []
    ont = ontology or _load_ontology()
    anchors = [_norm(a) for a in chain_object_anchors(chain_doc)]
    identity_order = [_norm(x) for x in IDENTITY_PROBE_ORDER]

    def sort_key(field: str) -> tuple:
        nf = _norm(field)
        anchor_rank = anchors.index(nf) if nf in anchors else 99
        if nf in anchors:
            tier = 0
        elif nf in identity_order:
            tier = 1
            anchor_rank = identity_order.index(nf)
        elif nf in ENVIRONMENT_FIELDS:
            tier = 3
            anchor_rank = 99
        else:
            tier = 2
            anchor_rank = 99
        return (tier, anchor_rank, -_field_priority(field, ont), field.lower())

    return sorted(dict.fromkeys(fields), key=sort_key)


def select_chain_strict_m7_fields(
    candidate_fields: List[str],
    *,
    chain_doc: Optional[Dict[str, Any]] = None,
    max_fields: int = 3,
) -> List[str]:
    """For chain_strict: prefer object anchors; deprioritize environment-only probes."""
    ordered = prioritize_mutation_fields(candidate_fields, chain_doc=chain_doc)
    anchors = chain_object_anchors(chain_doc)
    if anchors:
        anchor_norm = {_norm(a) for a in anchors}
        anchor_hits = [f for f in ordered if _norm(f) in anchor_norm]
        if anchor_hits:
            return anchor_hits[:max_fields]
    non_env = [f for f in ordered if _norm(f) not in ENVIRONMENT_FIELDS]
    if non_env:
        return non_env[:max_fields]
    return ordered[:max_fields]
