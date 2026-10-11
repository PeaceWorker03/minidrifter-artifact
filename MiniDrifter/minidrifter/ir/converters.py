# -*- coding: utf-8
"""Legacy artifacts → Universal IR converters."""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from minidrifter.core.runtime_taxonomy import classify_side_effect, side_effect_short
from minidrifter.ir.constants import (
    API_ROLES,
    BUSINESS_DOMAINS,
    CHAIN_TYPES,
    FAILURE_CLASSES,
    FIELD_ROLE_TO_OBJECT_ROLE,
    IR_VERSION,
    LEGACY_FAILURE_MAP,
    OBJECT_ROLES,
)
from minidrifter.ir.n_tier import classify_universal_n_tier

ACCEPTED_INPUT_FORMATS = ['raw_http', 'har', 'burp_item', 'mitmproxy_flow', 'curl']


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def to_universal_failure(legacy_class: str, *, detail: str = '', layer: str = '') -> Dict[str, Any]:
    code = LEGACY_FAILURE_MAP.get(legacy_class or '', 'USER_MATERIAL_REQUIRED')
    if code not in FAILURE_CLASSES:
        code = 'USER_MATERIAL_REQUIRED'
    return {
        'failure_class': code,
        'legacy_class': legacy_class,
        'detail': detail,
        'layer': layer,
    }


def _infer_api_role(card: Dict[str, Any]) -> str:
    replay = card.get('replay') or {}
    cat = (replay.get('side_effect') or {}).get('category') or ''
    path = ((card.get('static') or {}).get('endpoint') or {}).get('path') or ''
    produces = set((card.get('bindings') or {}).get('produces') or [])
    consumes = set((card.get('bindings') or {}).get('consumes') or [])

    if side_effect_short(classify_side_effect(card)) == 'S4':
        return 'audit_only'
    if produces and not consumes:
        return 'producer'
    if consumes and not produces:
        return 'consumer'
    if re.search(r'list|query|search', path, re.I) and produces:
        return 'producer'
    if re.search(r'detail|info|get', path, re.I) and consumes:
        return 'consumer'
    if re.search(r'pay|qrcode|verify|auth', path, re.I):
        return 'capability_issuer'
    if re.search(r'encrypt|transform|sign', path, re.I):
        return 'transformer'
    return 'unknown'


def _infer_business_domain(card: Dict[str, Any]) -> str:
    path = ((card.get('static') or {}).get('endpoint') or {}).get('path') or ''
    low = path.lower()
    for dom in ('invoice', 'order', 'device', 'payment', 'coupon', 'address', 'store', 'member'):
        if dom in low:
            return dom
    if re.search(r'user|profile|cacheinfo|cardinfo', low):
        return 'profile'
    return 'general'


def to_universal_api_card(card: Dict[str, Any], erd_item: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    static = card.get('static') or {}
    ep = static.get('endpoint') or {}
    http = static.get('http') or {}
    method = http.get('method') or 'UNKNOWN'
    host = ep.get('host') or ''
    path = ep.get('path') or ''
    url = ep.get('normalized_url') or (f'https://{host}{path}' if host and path else path)

    params = []
    for p in ((card.get('bindings') or {}).get('params') or []):
        role = p.get('static_role') or 'unknown'
        params.append({
            'name': p.get('name'),
            'location': p.get('where') or 'body',
            'object_role': FIELD_ROLE_TO_OBJECT_ROLE.get(
                p.get('field_role') or role, 'unknown'
            ),
            'binding_role': role,
            'required': bool(p.get('required')),
        })

    n_tier = classify_universal_n_tier(card, erd_item)
    side = side_effect_short(classify_side_effect(card))

    evidence = []
    for cs in ((card.get('evidence') or {}).get('callsites') or [])[:5]:
        if cs.get('evidence_id'):
            evidence.append(cs['evidence_id'])

    crypto_profile = None
    if (card.get('replay') or {}).get('crypto') or {}:
        crypto_profile = ((card.get('replay') or {}).get('crypto') or {}).get('profile_id')

    return {
        'ir_version': IR_VERSION,
        'api_id': card.get('card_id'),
        'method': method,
        'url': url,
        'host': host,
        'path': path,
        'params': params,
        'headers': [],
        'body_schema': {},
        'response_schema': {},
        'source_evidence': evidence,
        'runtime_requirements': [n_tier['tier'], *n_tier.get('blocking_reasons', [])],
        'runtime_tier': n_tier,
        'crypto_profile': crypto_profile,
        'side_effect_level': side,
        'api_role': _infer_api_role(card),
        'business_domain': _infer_business_domain(card),
        'confidence': float((card.get('ranking') or {}).get('score') or 0.0),
        'legacy_card_id': card.get('card_id'),
    }


def to_universal_object_model(resolved_fields: Dict[str, Any]) -> Dict[str, Any]:
    buckets: Dict[str, List[Dict[str, Any]]] = {r: [] for r in sorted(OBJECT_ROLES)}
    for name, spec in (resolved_fields or {}).items():
        if not isinstance(spec, dict):
            continue
        role = _field_name_to_object_role(name)
        buckets.setdefault(role, []).append({
            'name': name,
            'status': spec.get('status', 'unknown'),
            'source': spec.get('source', ''),
        })
    return {
        'ir_version': IR_VERSION,
        'subject_credential': buckets.get('subject_credential', []),
        'business_object': buckets.get('business_object', []),
        'capability_credential': buckets.get('capability_credential', []),
        'state_object': buckets.get('state_object', []),
        'session_credential': buckets.get('session_credential', []),
        'environment_context': buckets.get('environment_context', []),
        'crypto_material': buckets.get('crypto_material', []),
        'field_count': sum(len(v) for v in buckets.values()),
    }


def _field_name_to_object_role(name: str) -> str:
    low = re.sub(r'[^a-z0-9]', '', (name or '').lower())
    if low in {'token', 'authorization', 'sessionid', 'cookie'}:
        return 'session_credential'
    if low in {'userid', 'customerid', 'memberid', 'openid', 'unionid', 'operatorid'}:
        return 'subject_credential'
    if any(x in low for x in ('orderid', 'invoiceid', 'deviceid', 'addressid', 'couponid')):
        return 'business_object'
    if any(x in low for x in ('paycode', 'qrcode', 'verifycode', 'ticketcode')):
        return 'capability_credential'
    if low in {'appversion', 'appplatform', 'host', 'source', 'company'}:
        return 'environment_context'
    if low in {'appidentity', 'timespan', 'sign'}:
        return 'crypto_material'
    return 'unknown'


def to_universal_chain_hypothesis(
    chain: Dict[str, Any],
    *,
    domain: str = 'general',
) -> Dict[str, Any]:
    nodes = chain.get('nodes') or []
    subjects: List[str] = []
    objects: List[str] = []
    for node in nodes:
        for p in node.get('binding_params') or []:
            role = p.get('static_role') or ''
            name = p.get('name') or ''
            if 'subject' in role:
                subjects.append(name)
            elif 'object' in role:
                objects.append(name)

    chain_type = 'producer_consumer_binding'
    if len(nodes) >= 2:
        paths = [n.get('path') or '' for n in nodes]
        if any('list' in p.lower() for p in paths) and any('detail' in p.lower() for p in paths):
            chain_type = 'list_to_detail'

    return {
        'ir_version': IR_VERSION,
        'chain_id': chain.get('chain_id'),
        'chain_type': chain_type if chain_type in CHAIN_TYPES else 'producer_consumer_binding',
        'business_domain': domain if domain in BUSINESS_DOMAINS else 'general',
        'subject': list(dict.fromkeys(subjects)),
        'object': list(dict.fromkeys(objects)),
        'capability': [],
        'producer_candidates': [n.get('path') for n in nodes if n.get('role') == 'producer'],
        'consumer_candidates': [n.get('path') for n in nodes if n.get('role') == 'consumer'],
        'expected_binding': 'subject must own object',
        'missing_materials': chain.get('missing_materials') or [],
        'verified_facts': chain.get('verified_facts') or [],
        'failed_assumptions': chain.get('failed_assumptions') or [],
        'next_action': chain.get('next_action') or 'PROBE_PRODUCER',
        'confidence': float(chain.get('confidence') or 0.0),
        'status': chain.get('status'),
    }


def to_universal_feedback_ticket(ticket: Dict[str, Any]) -> Dict[str, Any]:
    fc = ticket.get('failure_class') or 'unknown'
    universal = to_universal_failure(fc, detail=ticket.get('diagnosis') or '', layer=ticket.get('layer') or '')

    return {
        'ir_version': IR_VERSION,
        'ticket_id': ticket.get('ticket_id'),
        'verification_target': ticket.get('evidence', {}).get('api') or ticket.get('path') or '',
        'chain_hypothesis': ticket.get('chain_id') or '',
        'completed_evidence': ticket.get('evidence') or {},
        'missing_materials': ticket.get('field') or ticket.get('missing_materials') or [],
        'user_must_provide': ticket.get('user_instruction') or '',
        'suggested_next_steps': ticket.get('example_paths') or [],
        'accepted_input_formats': ticket.get('accepted_formats') or ACCEPTED_INPUT_FORMATS,
        'resume_action': ticket.get('resume_action') or '',
        'failure': universal,
        'severity': ticket.get('severity'),
        'status': ticket.get('status'),
    }


def build_universal_chain_from_search_session(session: Dict[str, Any]) -> List[Dict[str, Any]]:
    chains = []
    for ch in session.get('active_chains') or session.get('beam_chains') or []:
        if isinstance(ch, dict):
            chains.append(to_universal_chain_hypothesis(ch))
    return chains
