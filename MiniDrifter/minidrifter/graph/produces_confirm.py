# -*- coding: utf-8 -*-
"""Promote static produces candidates to baseline_confirmed using runtime context."""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set

PATH_MATERIAL_MAP = [
    (re.compile(r'/Special/Mini/Device/List', re.I), 'first_hop_response_device_list', ['DeviceId', 'TokenCode', 'DeviceName']),
    (re.compile(r'/User/Base/CacheInfo|/CardInfo/ByUserId', re.I), 'login_or_user_profile_response', ['UserId', 'userId', 'Phone', 'UserJwt', 'MarketToken']),
    (re.compile(r'/Federated/Login|/MiniProgram/OpenId|OpenId', re.I), 'openid_flow_sample', ['OpenId', 'openId', 'unionId', 'code']),
]

FIELD_ALIASES = {
    'userId': 'UserId',
    'openId': 'OpenId',
}


def _fields_from_context(ctx: Dict[str, Any]) -> Set[str]:
    pool = ctx.get('resolved_fields') or {}
    names: Set[str] = set()
    for k in pool:
        names.add(k)
        if k in FIELD_ALIASES:
            names.add(FIELD_ALIASES[k])
    return names


def confirm_produces_from_baseline(
    produces_edges: List[Dict[str, Any]],
    cards_by_id: Dict[str, Dict[str, Any]],
    baseline_context: Dict[str, Any],
    *,
    intake_report: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    confirmed_fields = _fields_from_context(baseline_context)
    agg = ((intake_report or {}).get('decrypted_fields_aggregate') or {}).get('fields') or {}
    for k in agg:
        confirmed_fields.add(k)
        if k in FIELD_ALIASES:
            confirmed_fields.add(FIELD_ALIASES[k])

    path_material: Dict[str, str] = {}
    for cap in (intake_report or {}).get('captures') or []:
        path = cap.get('path') or ''
        for pat, mid, _ in PATH_MATERIAL_MAP:
            if pat.search(path):
                path_material[path] = mid

    out = []
    for edge in produces_edges:
        e = dict(edge)
        cid = e.get('from_api') or e.get('from')
        card = cards_by_id.get(cid) or {}
        path = ((card.get('static') or {}).get('endpoint') or {}).get('path') or ''
        field = e.get('to_field') or e.get('to') or ''

        evidence_level = e.get('evidence_level') or 'static_candidate'
        source_material = e.get('source_material')
        confidence = float(e.get('confidence') or 0.5)

        if field in confirmed_fields or field.lower() in {f.lower() for f in confirmed_fields}:
            evidence_level = 'baseline_confirmed'
            confidence = max(confidence, 0.92)
            for pat, mid, fields in PATH_MATERIAL_MAP:
                if pat.search(path) and field in fields:
                    source_material = mid
                    break
            if not source_material:
                source_material = 'baseline_runtime_context'

        e['evidence_level'] = evidence_level
        e['source_material'] = source_material
        e['confidence'] = round(confidence, 3)
        if evidence_level == 'baseline_confirmed':
            e['phase'] = 'baseline_confirmed'
        out.append(e)
    return out
