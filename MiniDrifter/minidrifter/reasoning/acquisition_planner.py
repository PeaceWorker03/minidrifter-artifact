# -*- coding: utf-8 -*-
"""Pre-baseline Runtime Requirement Planner: acquisition plan + demand graph."""
from __future__ import annotations

import re
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from minidrifter.reasoning.runtime_skeleton import (
    N1_A,
    N1_B,
    N1_H,
    N1_X,
    O4_WORKFLOW,
    O5_CAPABILITY,
    build_runtime_requirement_skeleton,
)
from minidrifter.core.runtime_taxonomy import is_stage1_safe_side_effect, side_effect_short

from minidrifter.core.schema import SCHEMA_VERSION

DEFERRED_PATH_RE = re.compile(
    r'(subscribe|/pay|payment|freeze|refund|cancel|delete|bind|unbind|submit|charge|wallet|preauth|pre-auth)',
    re.I,
)
REPLAY_UNSAFE_PATH_RE = re.compile(
    r'(subscribe|/auth\b|bind|unbind|freeze|preauth|pre-auth|/pay|payment|submit|delete|cancel|modify|update|withdraw|charge|wallet)',
    re.I,
)
STAGE1_PATH_BOOST_RE = re.compile(
    r'(device/list|on.?line/device/list|cardinfo|emergencycontact|frequentcontact|recentemail|user/profile|byuserid)',
    re.I,
)
AUTO_DISCOVERY_PATH_RE = re.compile(
    r'/(list|orders/list|recent|address|email/list|invoice|contact)',
    re.I,
)
ORDER_LIST_PATH_RE = re.compile(r'/orders?/list', re.I)

MATERIAL_PACKAGES = {
    'authenticated_request_sample': {
        'description': 'One successful post-login request with full headers, query, body.',
        'covers_roles': ['auth_token', 'crypto_derived', 'static_constant'],
        'covers_fields': ['Token', 'Authorization', 'AppIdentity', 'AppVersion', 'AppPlatform'],
    },
    'login_or_user_profile_response': {
        'description': 'Login or user profile API response containing UserId and related subject fields.',
        'covers_roles': ['subject_id'],
        'covers_fields': ['UserId', 'Phone', 'UserJwt', 'MarketToken'],
    },
    'openid_flow_sample': {
        'description': 'wx.login + OpenId acquisition request/response sample.',
        'covers_roles': ['host_identity'],
        'covers_fields': ['OpenId', 'code', 'appId', 'channelId'],
    },
    'first_hop_response_device_list': {
        'description': 'Baseline request/response for device list (produces DeviceId).',
        'covers_roles': ['object_id', 'local_device_context'],
        'covers_fields': ['DeviceId', 'TokenCode', 'DeviceName'],
    },
    'first_hop_response_order_list': {
        'description': 'Baseline for order list (produces OrderId); do not ask user for OrderId directly.',
        'covers_roles': ['object_id'],
        'covers_fields': ['OrderId', 'OrderNo', 'StoreId'],
    },
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _card_brief(card: Dict[str, Any], item: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    sk = (item or {}).get('runtime_requirement_skeleton') or {}
    ep = (card.get('static') or {}).get('endpoint') or {}
    return {
        'card_id': card.get('card_id'),
        'method': (card.get('static') or {}).get('http', {}).get('method'),
        'path': ep.get('path'),
        'runtime_sublevel': sk.get('runtime_sublevel'),
        'side_effect_level': sk.get('side_effect_level'),
        'replay_readiness': (card.get('replay') or {}).get('readiness', {}).get('status'),
        'priority_tier': (card.get('ranking') or {}).get('priority_tier'),
        'stage1_user_fields': sk.get('stage1_user_fields'),
        'deferred_fields': sk.get('deferred_fields'),
    }


def _score_audit_rank(card: Dict[str, Any], skeleton: Dict[str, Any]) -> float:
    """High-value audit candidate score (may include state-changing APIs)."""
    path = skeleton.get('endpoint') or ''
    ranking = card.get('ranking') or {}
    score = float(ranking.get('rank_score') or 0)
    if re.search(r'(invoice|payment|order|auth|bind|subscribe)', path, re.I):
        score += 15.0
    score += max(0.0, 20.0 - (ranking.get('rank') or 999) * 0.02)
    return round(score, 2)


def _score_replay_safe(card: Dict[str, Any], skeleton: Dict[str, Any]) -> float:
    """Conservative Stage-1 auto-replay score; S0/S1 only."""
    path = skeleton.get('endpoint') or ''
    side = side_effect_short(skeleton.get('side_effect_level') or skeleton.get('side_effect_short') or 'S3')
    sub = skeleton.get('runtime_sublevel') or N1_X
    deferred = skeleton.get('deferred_fields') or []
    readiness = (card.get('replay') or {}).get('readiness', {}).get('status')
    method = ((card.get('static') or {}).get('http') or {}).get('method') or 'UNKNOWN'

    if side not in {'S0', 'S1'}:
        return -200.0
    if side == 'S2':
        return -80.0
    if deferred:
        return -60.0
    if REPLAY_UNSAFE_PATH_RE.search(path):
        return -120.0
    if DEFERRED_PATH_RE.search(path):
        return -100.0
    if sub == N1_X or method == 'UNKNOWN':
        return -50.0

    score = 0.0
    if side == 'S0':
        score += 40.0
    elif side == 'S1':
        score += 20.0
    if readiness == 'ready':
        score += 15.0
    if sub in {N1_A, N1_H}:
        score += 20.0
    if STAGE1_PATH_BOOST_RE.search(path):
        score += 45.0
    if AUTO_DISCOVERY_PATH_RE.search(path) and side == 'S0':
        score += 12.0
    if sub == N1_B:
        score -= 15.0
    ranking = card.get('ranking') or {}
    score += max(0.0, 10.0 - (ranking.get('rank') or 999) * 0.01)
    return round(score, 2)


def _score_stage1_target(card: Dict[str, Any], skeleton: Dict[str, Any]) -> float:
    """Legacy alias → replay_safe_rank."""
    return _score_replay_safe(card, skeleton)


def _classify_api_bucket(card: Dict[str, Any], skeleton: Dict[str, Any], stage1_score: float) -> str:
    path = skeleton.get('endpoint') or ''
    kind = (card.get('provenance') or {}).get('card_kind')
    side = side_effect_short(skeleton.get('side_effect_level') or skeleton.get('side_effect_short') or 'S3')

    if kind != 'operation':
        return 'blocked_or_unresolved'
    if skeleton.get('deferred_fields') or DEFERRED_PATH_RE.search(path):
        return 'deferred'
    if side in {'S3', 'S4'}:
        return 'deferred'
    if skeleton.get('runtime_sublevel') == N1_X:
        return 'blocked_or_unresolved'
    if ORDER_LIST_PATH_RE.search(path) and side in {'S0', 'S1'}:
        return 'auto_discovery'
    if STAGE1_PATH_BOOST_RE.search(path) and side in {'S0', 'S1'}:
        return 'stage_1_target'
    if AUTO_DISCOVERY_PATH_RE.search(path) and side in {'S0', 'S1'} and skeleton.get('produces_fields'):
        return 'auto_discovery'
    if stage1_score >= 25:
        return 'stage_1_target'
    if AUTO_DISCOVERY_PATH_RE.search(path):
        return 'auto_discovery'
    if skeleton.get('runtime_sublevel') in {N1_A, N1_H} and side in {'S0', 'S1'}:
        return 'stage_1_target'
    return 'deferred'


def _build_demand_graph(cards: List[Dict[str, Any]], items_by_id: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    from minidrifter.graph.runtime_demand_graph import (
        assemble_demand_graph,
        build_requires_edges,
        truncate_graph_preview,
    )

    api_nodes, requires_edges, field_nodes = build_requires_edges(cards, items_by_id)
    skeleton_produces = []
    for card in cards:
        if (card.get('provenance') or {}).get('card_kind') != 'operation':
            continue
        cid = card['card_id']
        item = items_by_id.get(cid) or {}
        sk = item.get('runtime_requirement_skeleton') or build_runtime_requirement_skeleton(
            card, (item.get('runtime_requirement') or {}).get('level', 'N1_BASELINE_RUNTIME_TEMPLATE')
        )
        for f in sk.get('produces_fields') or []:
            fname = f.get('name')
            if not fname:
                continue
            skeleton_produces.append({
                'type': 'produces',
                'from': cid,
                'from_api': cid,
                'to': fname,
                'to_field': fname,
                'confidence': f.get('confidence', 0.55),
                'evidence_type': f.get('evidence_type') or 'skeleton_heuristic',
                'phase': 'pre_baseline_candidate',
            })

    full = assemble_demand_graph(api_nodes, requires_edges, skeleton_produces, field_nodes)
    return truncate_graph_preview(full)


def build_acquisition_plan(
    cards: List[Dict[str, Any]],
    manifest: Dict[str, Any],
    erd_items: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    items_by_id = {i['card_id']: i for i in (erd_items or [])}
    operations = [c for c in cards if (c.get('provenance') or {}).get('card_kind') == 'operation']

    scored: List[tuple] = []
    buckets: Dict[str, List[Dict[str, Any]]] = {
        'stage_1_target_apis': [],
        'auto_discovery_apis': [],
        'deferred_apis': [],
        'blocked_or_unresolved_apis': [],
    }

    material_hints: Set[str] = set()
    sublevel_dist = Counter()
    side_dist = Counter()

    for card in operations:
        item = items_by_id.get(card['card_id'], {})
        runtime_level = (item.get('runtime_requirement') or {}).get('level', 'N1_BASELINE_RUNTIME_TEMPLATE')
        skeleton = item.get('runtime_requirement_skeleton') or build_runtime_requirement_skeleton(card, runtime_level)
        if item:
            item['runtime_requirement_skeleton'] = skeleton

        sublevel_dist[skeleton.get('runtime_sublevel')] += 1
        side_dist[skeleton.get('side_effect_level')] += 1
        for h in skeleton.get('user_material_hints') or []:
            material_hints.add(h)

        score = _score_replay_safe(card, skeleton)
        audit_score = _score_audit_rank(card, skeleton)
        bucket = _classify_api_bucket(card, skeleton, score)
        brief = _card_brief(card, {**item, 'runtime_requirement_skeleton': skeleton})
        brief['stage1_score'] = round(score, 2)
        brief['replay_safe_rank'] = round(score, 2)
        brief['audit_rank'] = audit_score
        buckets[f'{bucket}_apis' if bucket != 'blocked_or_unresolved' else 'blocked_or_unresolved_apis'].append(brief)
        scored.append((score, card, skeleton, bucket))

    scored.sort(key=lambda x: x[0], reverse=True)
    for key in buckets:
        buckets[key].sort(key=lambda x: x.get('replay_safe_rank', x.get('stage1_score', 0)), reverse=True)

    stage1_materials = []
    MATERIAL_PRIORITY = {
        'authenticated_request_sample': 'required',
        'login_or_user_profile_response': 'required',
        'openid_flow_sample': 'recommended',
        'first_hop_response_device_list': 'recommended',
        'first_hop_response_order_list': 'deferred',
    }
    for mid in [
        'authenticated_request_sample',
        'login_or_user_profile_response',
        'openid_flow_sample',
        'first_hop_response_device_list',
        'first_hop_response_order_list',
    ]:
        priority = MATERIAL_PRIORITY[mid]
        if mid in material_hints or priority == 'required':
            pkg = dict(MATERIAL_PACKAGES[mid])
            pkg['material_id'] = mid
            pkg['priority'] = priority
            pkg['required_in_stage_1'] = priority == 'required'
            stage1_materials.append(pkg)

    stage1_materials = list({m['material_id']: m for m in stage1_materials}.values())

    user_instructions = [
        '1. Log in to the mini-program with test account A.',
        '2. Capture one successful authenticated API request (headers + body + response).',
        '3. Capture login or user profile response containing UserId.',
    ]
    if 'openid_flow_sample' in material_hints:
        user_instructions.append('4. If testing OpenId-related APIs, capture /MiniProgram/OpenId request/response.')
    if any('device' in (b.get('path') or '').lower() for b in buckets['stage_1_target_apis'][:5]):
        user_instructions.append('5. Optionally capture device list baseline (recommended first-hop target).')
    user_instructions.append('Do NOT manually provide OrderId, PayNo, FreezeNo, or other workflow-deep IDs in stage 1.')

    graph = _build_demand_graph(cards, items_by_id)

    return {
        'schema_version': SCHEMA_VERSION,
        'pack_id': manifest.get('pack_id'),
        'generated_at': _utc_now(),
        'generator': {'tool': 'MiniDrifter', 'stage': 'pre_baseline_acquisition_planner'},
        'phase': 'pre_baseline',
        'stage_1_user_materials': stage1_materials,
        'user_collection_instructions': user_instructions,
        'stage_1_target_apis': buckets['stage_1_target_apis'][:40],
        'auto_discovery_apis': buckets['auto_discovery_apis'][:40],
        'deferred_apis': buckets['deferred_apis'][:60],
        'blocked_or_unresolved_apis': buckets['blocked_or_unresolved_apis'][:40],
        'plan_summary': {
            'operation_cards': len(operations),
            'stage_1_target_count': len(buckets['stage_1_target_apis']),
            'auto_discovery_count': len(buckets['auto_discovery_apis']),
            'deferred_count': len(buckets['deferred_apis']),
            'blocked_count': len(buckets['blocked_or_unresolved_apis']),
            'runtime_sublevel_distribution': dict(sublevel_dist),
            'side_effect_level_distribution': dict(side_dist),
            'material_package_count': len(stage1_materials),
        },
        'runtime_demand_graph': graph,
        'top_stage_1_recommendation': sorted(
            buckets['stage_1_target_apis'],
            key=lambda x: x.get('replay_safe_rank', 0),
            reverse=True,
        )[:8],
        'top_audit_recommendation': sorted(
            buckets['deferred_apis'] + buckets['stage_1_target_apis'],
            key=lambda x: x.get('audit_rank', 0),
            reverse=True,
        )[:8],
        'explicitly_deferred_examples': [
            b for b in buckets['deferred_apis']
            if b.get('path') and DEFERRED_PATH_RE.search(b['path'])
        ][:8],
    }
