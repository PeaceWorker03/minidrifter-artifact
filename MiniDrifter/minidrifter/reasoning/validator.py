# -*- coding: utf-8 -*-
"""Validate LLM structured outputs against MiniDrifter reasoning constraints."""
from __future__ import annotations

import re
from typing import Any, Dict, List, Set, Tuple

from minidrifter.core.schema import SCHEMA_VERSION

FORBIDDEN_KEYS = {
    'vulnerable', 'is_vulnerable', 'exploit', 'exploit_steps',
    'severity', 'final_verdict', 'cve',
}

FORBIDDEN_SUBSTRINGS = re.compile(
    r'\b(vulnerable|exploit|critical\s+severity|confirmed\s+vulnerability)\b',
    re.I,
)


def _walk_keys(obj: Any, prefix: str = '') -> List[str]:
    keys = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            keys.append(f"{prefix}.{k}" if prefix else k)
            keys.extend(_walk_keys(v, f"{prefix}.{k}" if prefix else k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            keys.extend(_walk_keys(v, f"{prefix}[{i}]"))
    return keys


def _collect_strings(obj: Any) -> List[str]:
    out = []
    if isinstance(obj, dict):
        for v in obj.values():
            out.extend(_collect_strings(v))
    elif isinstance(obj, list):
        for v in obj:
            out.extend(_collect_strings(v))
    elif isinstance(obj, str):
        out.append(obj)
    return out


def valid_evidence_ids(card: Dict[str, Any]) -> Set[str]:
    ids = set()
    for cs in (card.get('evidence') or {}).get('callsites') or []:
        eid = cs.get('evidence_id')
        if eid:
            ids.add(eid)
    return ids


def validate_card_audit(payload: Dict[str, Any], card: Dict[str, Any]) -> Tuple[bool, List[str]]:
    errors: List[str] = []
    if not isinstance(payload, dict):
        return False, ['payload must be a JSON object']

    for key in ('card_id', 'field_quality', 'consistency_findings', 'confidence'):
        if key not in payload:
            errors.append(f'missing required field: {key}')

    if payload.get('card_id') != card.get('card_id'):
        errors.append('card_id mismatch')

    for k in FORBIDDEN_KEYS:
        if k in payload:
            errors.append(f'forbidden top-level field: {k}')

    for text in _collect_strings(payload):
        if FORBIDDEN_SUBSTRINGS.search(text):
            errors.append(f'forbidden wording in output: {text[:80]}')
            break

    valid_ids = valid_evidence_ids(card)
    for finding in payload.get('consistency_findings') or []:
        for ref in finding.get('evidence_refs') or []:
            if ref not in valid_ids:
                errors.append(f'invalid evidence_ref: {ref}')

    conf = payload.get('confidence')
    if conf is not None and not (0 <= float(conf) <= 1):
        errors.append('confidence must be between 0 and 1')

    # Gate: must not recommend auto execute on payment/state-changing cards
    for finding in payload.get('consistency_findings') or []:
        ftype = (finding.get('type') or '').lower()
        if 'safe_to_auto_execute' in ftype and finding.get('severity') == 'low':
            side = (card.get('replay') or {}).get('side_effect') or {}
            if not side.get('auto_execute_allowed'):
                errors.append('cannot mark safe_to_auto_execute when replay.side_effect disallows')

    return len(errors) == 0, errors


FORBIDDEN_STAGE1_FIELDS = re.compile(
    r'\b(orderid|orderno|payno|freezeno|invoiceorderid|contractid|qrcode|prepayid|paysign|barcode|verifycode)\b',
    re.I,
)

VALID_OBTAINABILITY = {
    'O0_static_derived', 'O1_login_bootstrap', 'O2_host_local',
    'O3_first_hop_object', 'O4_workflow_object', 'O5_sensitive_capability',
}

VALID_CHAIN_PHASES = {
    'user_material_collection', 'auto_discovery', 'stage_1_test', 'deferred_preview',
}

VALID_FIELD_ROLES = {
    'subject_id', 'auth_token', 'host_identity', 'object_id', 'capability_token',
    'environment_context', 'crypto_derived', 'static_constant', 'local_device_context',
    'pagination_filter', 'ordinary_field',
}


def validate_acquisition_advisor(
    payload: Dict[str, Any],
    rule_plan: Dict[str, Any],
    cards_by_id: Dict[str, Dict[str, Any]],
    selected_cards: List[Dict[str, Any]],
) -> Tuple[bool, List[str]]:
    errors: List[str] = []
    if not isinstance(payload, dict):
        return False, ['payload must be a JSON object']

    for key in ('pack_id', 'chain_guidance', 'confidence'):
        if key not in payload:
            errors.append(f'missing required field: {key}')

    if payload.get('pack_id') != rule_plan.get('pack_id'):
        errors.append('pack_id mismatch')

    for k in FORBIDDEN_KEYS:
        if k in payload:
            errors.append(f'forbidden top-level field: {k}')

    for text in _collect_strings(payload):
        if FORBIDDEN_SUBSTRINGS.search(text):
            errors.append(f'forbidden wording: {text[:80]}')
            break

    rule_buckets = _rule_bucket_map(rule_plan)

    for step in (payload.get('chain_guidance') or {}).get('recommended_sequence') or []:
        cid = step.get('card_id')
        phase = step.get('phase')
        if phase and phase not in VALID_CHAIN_PHASES:
            errors.append(f'invalid chain phase: {phase}')
        if phase == 'user_material_collection':
            mid = step.get('material_id')
            valid_materials = {
                m.get('material_id') for m in (rule_plan.get('stage_1_user_materials') or [])
            }
            if mid and valid_materials and mid not in valid_materials:
                errors.append(f'unknown material_id in chain: {mid}')
            for f in step.get('requires_fields') or []:
                if FORBIDDEN_STAGE1_FIELDS.search(str(f)):
                    errors.append(f'stage-1 chain step requires forbidden field: {f}')
        elif cid:
            if cid not in cards_by_id:
                errors.append(f'unknown card_id in chain: {cid}')
            rb = step.get('rule_bucket')
            if rb and rule_buckets.get(cid) and rb != rule_buckets[cid]:
                errors.append(f'chain step bucket mismatch for {cid}: {rb} vs rule {rule_buckets[cid]}')
            card = cards_by_id.get(cid)
            if card:
                valid_ids = valid_evidence_ids(card)
                for ref in step.get('evidence_refs') or []:
                    if ref not in valid_ids:
                        errors.append(f'invalid evidence_ref in chain step: {ref}')
        elif phase != 'user_material_collection':
            errors.append(f'chain step {step.get("step")} missing card_id')

    for review in payload.get('field_role_reviews') or []:
        cid = review.get('card_id')
        if cid and cid not in cards_by_id:
            errors.append(f'unknown card_id in field review: {cid}')
        sug_obs = review.get('suggested_obtainability')
        if sug_obs and sug_obs not in VALID_OBTAINABILITY:
            errors.append(f'invalid suggested_obtainability: {sug_obs}')
        if sug_obs in {'O4_workflow_object', 'O5_sensitive_capability'} and review.get('apply_suggestion'):
            errors.append('cannot apply O4/O5 obtainability in stage-1 advisor')
        sug_role = review.get('suggested_role')
        if sug_role and sug_role not in VALID_FIELD_ROLES:
            errors.append(f'invalid suggested_role: {sug_role}')
        card = cards_by_id.get(cid or '')
        if card:
            for ref in review.get('evidence_refs') or []:
                if ref not in valid_evidence_ids(card):
                    errors.append(f'invalid evidence_ref in field review: {ref}')

    for dis in payload.get('bucket_disagreements') or []:
        cid = dis.get('card_id')
        if cid and cid not in cards_by_id:
            errors.append(f'unknown card_id in bucket disagreement: {cid}')

    conf = payload.get('confidence')
    if conf is not None and not (0 <= float(conf) <= 1):
        errors.append('confidence must be between 0 and 1')

    return len(errors) == 0, errors


def _rule_bucket_map(plan: Dict[str, Any]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for key, label in [
        ('stage_1_target_apis', 'stage_1_target'),
        ('auto_discovery_apis', 'auto_discovery'),
        ('deferred_apis', 'deferred'),
        ('blocked_or_unresolved_apis', 'blocked'),
    ]:
        for b in plan.get(key) or []:
            cid = b.get('card_id')
            if cid:
                out[cid] = label
    return out


def merge_acquisition_guidance(
    rule_plan: Dict[str, Any],
    advisor: Dict[str, Any],
    advisor_record: Dict[str, Any],
) -> Dict[str, Any]:
    """Merge LLM guidance into rule plan. Rule buckets remain authoritative."""
    guided = dict(rule_plan)
    guided['schema_version'] = SCHEMA_VERSION
    guided['llm_enriched'] = True
    guided['authority_model'] = {
        'rule_layer': 'authoritative for buckets, obtainability gates, side-effect tiers',
        'llm_layer': 'advisory for chain order, field semantics, user narrative',
        'merge_policy': 'LLM cannot override rule buckets; disagreements are recorded only',
    }
    guided['llm_guidance'] = {
        'generated_at': advisor_record.get('generated_at'),
        'model': advisor_record.get('model'),
        'status': advisor_record.get('status'),
        'agrees_with_rule_plan': advisor.get('agrees_with_rule_plan'),
        'confidence': advisor.get('confidence'),
        'chain_guidance': advisor.get('chain_guidance'),
        'field_role_reviews': [
            {
                **r,
                'status': 'pending_rule_confirmation' if r.get('apply_suggestion') else 'advisory_only',
            }
            for r in (advisor.get('field_role_reviews') or [])
        ],
        'material_package_review': advisor.get('material_package_review'),
        'bucket_disagreements': advisor.get('bucket_disagreements'),
        'user_collection_narrative': advisor.get('user_collection_narrative'),
    }

    # Re-order stage_1 within rule bucket using LLM sequence (API steps only)
    seq = (advisor.get('chain_guidance') or {}).get('recommended_sequence') or []
    stage1_ids = [
        s['card_id'] for s in seq
        if s.get('rule_bucket') == 'stage_1_target' and s.get('card_id') and s.get('phase') != 'user_material_collection'
    ]
    if stage1_ids:
        existing = {b['card_id']: b for b in guided.get('stage_1_target_apis') or []}
        reordered = [existing[cid] for cid in stage1_ids if cid in existing]
        tail = [b for b in guided.get('stage_1_target_apis') or [] if b['card_id'] not in {x['card_id'] for x in reordered}]
        guided['stage_1_target_apis'] = reordered + tail
        guided['llm_guidance']['stage_1_reordered'] = True

    if advisor.get('user_collection_narrative'):
        guided['user_collection_instructions'] = [
            advisor['user_collection_narrative'],
            '',
            '---',
            'Rule-enforced reminders:',
        ] + list(guided.get('user_collection_instructions') or [])[-2:]

    return guided


def parse_json_from_llm(text: str) -> Dict[str, Any]:
    import json

    text = (text or '').strip()
    if text.startswith('```'):
        text = re.sub(r'^```(?:json)?\s*', '', text)
        text = re.sub(r'\s*```$', '', text)
    return json.loads(text)
