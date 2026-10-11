# -*- coding: utf-8 -*-
"""Freeze optimized static outputs into unified API Cards (phase-one deliverable)."""
from __future__ import annotations

import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from minidrifter.core.patterns import CAP_KEYS, CRYPTO_KEYS, OBJECT_KEYS, SUBJECT_KEYS
from minidrifter.core.utils import tokenise_identifier, write_json

SCHEMA_VERSION = '1.0.0'

CONTEXT_KEYS = re.compile(
    r'(tenantid|companyid|orgid|branchid|deptid|merchantid|shopid|brandcode|entid|corpcode)',
    re.I,
)
AUTH_CRED_KEYS = re.compile(r'(apikey|accesstoken|bearertoken|refreshtoken)', re.I)

NEGATIVE_PATH_RULES: List[Tuple[str, re.Pattern[str]]] = [
    ('notification_or_subscribe_api', re.compile(r'subscribe|message/|template|push|notify', re.I)),
    ('config_api', re.compile(r'config|settings|entrance|banner|memorycache|description\?', re.I)),
    ('logging_or_telemetry', re.compile(r'log|track|report|stat|bury|telemetry|monitor', re.I)),
    ('captcha_or_otp_send', re.compile(r'captcha|verifycode|sms|otp|sendcode', re.I)),
    ('agreement_or_banner', re.compile(r'privacy|agreement|advert|protocol', re.I)),
    ('pure_auth_bootstrap', re.compile(r'login|oauth|session/init|auth/init', re.I)),
    ('payment_related', re.compile(r'/pay|payment|charge|wallet|prepay', re.I)),
]

READ_ONLY_PATH = re.compile(r'(list|query|get|detail|info|search|fetch|load)', re.I)
STATE_CHANGING_PATH = re.compile(
    r'(subscribe|auth|send|create|update|delete|cancel|submit|save|bind|unbind|apply|confirm)',
    re.I,
)

BINDING_HINT_MAP = {
    'object_id_replaceable_candidate': 'object_identifier_replaceable_candidate',
    'subject_object_binding_required': 'subject_object_binding_review_needed',
    'has_object_credential': 'object_identifier_replaceable_candidate',
}


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _method_trust_tier(method: str, confidence: float) -> str:
    if method == 'UNKNOWN':
        return 'unknown'
    if confidence >= 0.88:
        return 'high'
    if confidence >= 0.6:
        return 'medium'
    if confidence > 0:
        return 'low'
    return 'unknown'


def classify_binding_param(name: str, source: str = 'name_pattern+param_schema') -> Dict[str, Any]:
    if not name:
        return {
            'static_role': 'unknown',
            'role_confidence': 0.0,
            'source': source,
            'ambiguity': [],
        }

    if re.fullmatch(r'userid', name, re.I):
        return {
            'static_role': 'subject_identifier_candidate',
            'role_confidence': 0.58,
            'source': source,
            'ambiguity': ['may_be_object_identifier', 'may_be_redundant_context'],
        }

    if CRYPTO_KEYS.search(name):
        return {
            'static_role': 'crypto_material',
            'role_confidence': 0.85,
            'source': source,
            'ambiguity': [],
        }

    if AUTH_CRED_KEYS.search(name):
        return {
            'static_role': 'auth_credential_candidate',
            'role_confidence': 0.88,
            'source': source,
            'ambiguity': [],
        }

    if CAP_KEYS.search(name):
        return {
            'static_role': 'capability_credential_candidate',
            'role_confidence': 0.80,
            'source': source,
            'ambiguity': [],
        }

    if CONTEXT_KEYS.search(name) or re.search(r'storeid|tenantid|companyid', name, re.I):
        return {
            'static_role': 'context_identifier_candidate',
            'role_confidence': 0.75,
            'source': source,
            'ambiguity': [],
        }

    if SUBJECT_KEYS.search(name):
        amb: List[str] = []
        if re.search(r'user(id|guid)?', name, re.I) and not re.fullmatch(r'openid|unionid', name, re.I):
            amb.append('may_be_object_identifier')
        return {
            'static_role': 'subject_identifier_candidate',
            'role_confidence': 0.91 if not amb else 0.65,
            'source': source,
            'ambiguity': amb,
        }

    if OBJECT_KEYS.search(name):
        amb = []
        if re.search(r'storeid', name, re.I):
            amb.append('may_be_context_identifier')
        return {
            'static_role': 'object_identifier_candidate',
            'role_confidence': 0.82,
            'source': source,
            'ambiguity': amb,
        }

    return {
        'static_role': 'ordinary_parameter',
        'role_confidence': 0.50,
        'source': source,
        'ambiguity': [],
    }


def _legacy_role_to_binding(role: str) -> str:
    return {
        'subject_credential': 'subject_identifier_candidate',
        'object_credential': 'object_identifier_candidate',
        'capability_credential': 'capability_credential_candidate',
        'signature_or_crypto_material': 'crypto_material',
        'ordinary_or_unknown_param': 'ordinary_parameter',
    }.get(role, 'unknown')


def _truncate_snippet(text: str, limit: int = 500) -> str:
    text = (text or '').replace('\n', ' ').strip()
    if len(text) <= limit:
        return text
    return text[: limit - 3] + '...'


def _negative_reasons(path: str, url_keys: List[str], method: str, params: List[Dict[str, Any]]) -> List[str]:
    hay = f"{path} {' '.join(url_keys or [])}"
    found = []
    for tag, pat in NEGATIVE_PATH_RULES:
        if pat.search(hay):
            found.append(tag)
    if 'pure_auth_bootstrap' in found and any(
        p.get('static_role') in {
            'object_identifier_candidate',
            'capability_credential_candidate',
            'context_identifier_candidate',
        }
        for p in params
    ):
        found = [x for x in found if x != 'pure_auth_bootstrap']
    if method == 'GET' and 'payment_related' in found and READ_ONLY_PATH.search(path):
        found = [x for x in found if x != 'payment_related']
    return found


def _binding_hints(risk_hints: List[str], credential_roles: Dict[str, int]) -> List[str]:
    hints = []
    for h in risk_hints or []:
        mapped = BINDING_HINT_MAP.get(h)
        if mapped and mapped not in hints:
            hints.append(mapped)
    if credential_roles.get('object_credential'):
        if 'object_identifier_replaceable_candidate' not in hints:
            hints.append('object_identifier_replaceable_candidate')
    if credential_roles.get('subject_credential') and credential_roles.get('object_credential'):
        if 'subject_object_binding_review_needed' not in hints:
            hints.append('subject_object_binding_review_needed')
    return hints


def _has_binding_candidate(params: List[Dict[str, Any]], min_conf: float = 0.65) -> bool:
    roles = {
        'object_identifier_candidate',
        'capability_credential_candidate',
        'context_identifier_candidate',
    }
    for p in params:
        if p.get('static_role') not in roles:
            continue
        if float(p.get('role_confidence') or 0) < min_conf:
            continue
        if 'may_be_redundant_context' in (p.get('ambiguity') or []):
            continue
        return True
    return False


def _infer_side_effect(method: str, path: str, negatives: List[str]) -> Dict[str, Any]:
    if 'payment_related' in negatives:
        return {'category': 'payment_related', 'auto_execute_allowed': False, 'inference_source': 'path_tokens+negative_reasons'}
    if re.search(r'delete|remove|destroy|cancel', path, re.I):
        return {'category': 'destructive', 'auto_execute_allowed': False, 'inference_source': 'path_tokens+negative_reasons'}
    if method == 'GET' and READ_ONLY_PATH.search(path) and 'notification_or_subscribe_api' not in negatives:
        return {'category': 'read_only', 'auto_execute_allowed': True, 'inference_source': 'path_tokens+method+negative_reasons'}
    if STATE_CHANGING_PATH.search(path) or method in {'POST', 'PUT', 'PATCH', 'DELETE'}:
        cat = 'state_changing'
        if 'payment_related' in negatives:
            cat = 'payment_related'
        return {
            'category': cat,
            'auto_execute_allowed': False,
            'inference_source': 'path_tokens+method+negative_reasons',
        }
    return {'category': 'unknown', 'auto_execute_allowed': False, 'inference_source': 'path_tokens+method+negative_reasons'}


def _side_effect_risk(side_effect: Dict[str, Any]) -> str:
    cat = side_effect.get('category')
    if cat == 'read_only':
        return 'low'
    if cat in {'state_changing', 'payment_related'}:
        return 'medium'
    if cat == 'destructive':
        return 'high'
    return 'unknown'


def _oracle_likelihood(method: str, negatives: List[str], params: List[Dict[str, Any]], side_effect: Dict[str, Any]) -> str:
    if 'notification_or_subscribe_api' in negatives or 'logging_or_telemetry' in negatives:
        return 'low'
    if side_effect.get('category') == 'read_only' and _has_binding_candidate(params):
        return 'high'
    if _has_binding_candidate(params) and method == 'GET':
        return 'medium'
    if _has_binding_candidate(params):
        return 'low'
    return 'unknown'


def _validation_value(
    priority_tier: str,
    has_binding: bool,
    negatives: List[str],
    card_kind: str,
) -> str:
    if card_kind == 'registered_only':
        return 'low'
    if priority_tier == 'P0':
        return 'high'
    if has_binding and not any(x in negatives for x in {'logging_or_telemetry', 'config_api', 'agreement_or_banner'}):
        return 'medium'
    if has_binding:
        return 'low'
    return 'none'


def _priority_tier(
    card_kind: str,
    readiness: str,
    side_effect: Dict[str, Any],
    side_effect_risk: str,
    oracle: str,
    params: List[Dict[str, Any]],
    negatives: List[str],
    allow_fuzzing: bool,
) -> str:
    if card_kind == 'registered_only':
        return 'P2'
    if readiness == 'blocked':
        return 'P3'
    if (
        readiness == 'ready'
        and side_effect.get('auto_execute_allowed')
        and side_effect.get('category') == 'read_only'
        and side_effect_risk == 'low'
        and oracle in {'high', 'medium'}
        and _has_binding_candidate(params)
        and not set(negatives) & {
            'notification_or_subscribe_api',
            'config_api',
            'logging_or_telemetry',
            'captcha_or_otp_send',
            'agreement_or_banner',
            'pure_auth_bootstrap',
        }
        and allow_fuzzing
    ):
        return 'P0'
    if readiness in {'ready', 'partial'} and _has_binding_candidate(params, min_conf=0.55):
        if negatives and readiness == 'ready':
            return 'P1'
        if readiness == 'partial':
            return 'P2'
        return 'P1'
    if readiness == 'partial':
        return 'P2'
    if negatives:
        return 'P3'
    return 'P3'


def _fuzzing_gate(priority_tier: str, side_effect: Dict[str, Any], readiness: str, allow_fuzzing: bool) -> Dict[str, Any]:
    eligible = (
        allow_fuzzing
        and priority_tier == 'P0'
        and readiness == 'ready'
        and side_effect.get('auto_execute_allowed')
        and side_effect.get('category') == 'read_only'
    )
    return {
        'auto_fuzz_eligible': eligible,
        'requires_manual_promotion': not eligible,
        'promotion_requires': ['validation_value_high', 'side_effect_risk_low'],
    }


def _collect_auth_fields(wrappers: List[Dict[str, Any]]) -> Tuple[List[str], List[str]]:
    fields: List[str] = []
    locations: List[str] = []
    for w in wrappers:
        for h in w.get('header_hints') or []:
            if h not in fields:
                fields.append(h)
    if fields:
        locations.append('header')
    return fields, locations


def _infer_transport(wrappers: List[Dict[str, Any]], has_crypto: bool) -> Dict[str, Any]:
    content_type = 'json'
    for w in wrappers:
        hints = ' '.join(w.get('crypto_hints') or []).lower()
        if 'form' in hints:
            content_type = 'form'
    body_enc = 'encrypted' if has_crypto else 'plain'
    return {
        'content_type': content_type,
        'body_encoding': body_enc,
        'query_encoding': 'plain',
        'inference_source': 'request_wrapper_hints+crypto_chain',
    }


def _oracle_hints_from_params(params: List[Dict[str, Any]]) -> Dict[str, Any]:
    identity = []
    objects = []
    for p in params:
        role = p.get('static_role')
        name = p.get('name')
        if role == 'subject_identifier_candidate':
            identity.append(name)
        elif role == 'object_identifier_candidate':
            objects.append(name)
    conf = 0.55 if (identity or objects) else 0.25
    return {
        'success_code_fields': ['IsSuccess', 'code', 'status', 'success'],
        'data_fields': ['data', 'result', 'Message'],
        'identity_echo_fields': identity[:5],
        'object_echo_fields': objects[:5],
        'inference_source': 'response_snippet+name_pattern',
        'confidence': conf,
    }


def _empty_semantic() -> Dict[str, Any]:
    return {
        '_phase': 'reserved_for_llm',
        'business_domain': None,
        'human_label': None,
        'method_semantic_hint': {
            'hypothesis': None,
            'confidence': None,
            'evidence_refs': [],
            'allowed_usage': 'review_only_not_for_replay',
            'rationale': None,
        },
        'binding_disambiguation': {'params': [], 'confidence': None, 'evidence_refs': []},
        'chain_hints': None,
        'poc_template_hint': None,
        'confidence': None,
        'evidence_refs': [],
        'llm_notes': None,
    }


def _reachability_from_sources(sources: List[Dict[str, Any]]) -> Dict[str, Any]:
    page = None
    level = 'R1'
    card_type = 'service_reached'
    for s in sources or []:
        f = (s.get('file') or '').replace('\\', '/')
        if '/pages/' in f or f.startswith('pages/'):
            level = 'R0'
            card_type = 'page_reached'
            parts = f.split('/')
            if 'pages' in parts:
                idx = parts.index('pages')
                page = '/'.join(parts[idx:]).rsplit('.', 1)[0]
            break
    return {
        'level': level,
        'card_type': card_type,
        'evidence': 'Concrete callsite recovered' if sources else 'Inferred from optimized operation',
        'page_context': {'page_or_module': page, 'event_linkage': 'not_resolved'},
        'orphan_registry': False,
    }


def _build_bindings(op: Dict[str, Any]) -> Dict[str, Any]:
    params_out = []
    for name in op.get('param_schema') or []:
        meta = classify_binding_param(name)
        params_out.append({
            'name': name,
            'where': 'body',
            **meta,
            'required_guess': True,
        })
    for name in op.get('header_schema') or []:
        meta = classify_binding_param(name, source='header_schema')
        params_out.append({
            'name': name,
            'where': 'header',
            **meta,
            'required_guess': True,
        })
    return {
        'params': params_out,
        'binding_hints_static': _binding_hints(op.get('risk_hints') or [], op.get('credential_roles') or {}),
    }


def _build_evidence(op: Dict[str, Any]) -> Dict[str, Any]:
    callsites = []
    call_ids = op.get('supporting_callsites') or []
    for i, src in enumerate(op.get('supporting_sources') or []):
        call_id = call_ids[i] if i < len(call_ids) else None
        callsites.append({
            'evidence_id': f'ev_{i}',
            'call_id': call_id,
            'file': src.get('file'),
            'line': src.get('line'),
            'snippet': _truncate_snippet(src.get('snippet') or ''),
            'evidence_strategy': src.get('evidence_strategy') or 'snippet',
            'focus_meta': src.get('focus_meta') or None,
        })
    eq = op.get('evidence_quality') or {}
    return {
        'quality': {
            'score': eq.get('score', 0),
            'reasons': eq.get('reasons') or [],
            'offset_local_count': op.get('offset_local_evidence_count') or 0,
        },
        'callsites': callsites,
        'primary_evidence_id': 'ev_0' if callsites else None,
    }


def _build_replay_block(
    op: Dict[str, Any],
    contract: Optional[Dict[str, Any]],
    wrappers: List[Dict[str, Any]],
    frozen_at: str,
) -> Dict[str, Any]:
    readiness_raw = op.get('replay_readiness') or {}
    readiness_status = readiness_raw.get('readiness') or 'partial'
    has_crypto = bool((op.get('credential_roles') or {}).get('signature_or_crypto_material')) or bool(
        contract and (contract.get('request_transform_chain') or {}).get('core_request_encryptors')
    )
    path = (op.get('endpoint') or {}).get('path') or ''
    bindings = _build_bindings(op)
    negatives = _negative_reasons(path, op.get('url_key_candidates') or [], op.get('method') or 'UNKNOWN', bindings['params'])
    side_effect = _infer_side_effect(op.get('method') or 'UNKNOWN', path, negatives)
    auth_fields, auth_locations = _collect_auth_fields(wrappers)

    block: Dict[str, Any] = {
        'contract_id': contract.get('contract_id') if contract else None,
        'contract_included_in_top_k': contract is not None,
        'readiness': {
            'status': readiness_status,
            'blockers': readiness_raw.get('blockers') or [],
            'suggested_next_step': readiness_raw.get('suggested_next_step') or 'llm_or_runtime_enrichment',
        },
        'transport': _infer_transport(wrappers, has_crypto),
        'auth_dependency': {
            'requires_auth': bool(auth_fields),
            'auth_locations': auth_locations,
            'auth_fields': auth_fields[:12],
            'auth_status': 'known' if auth_fields else ('runtime_required' if has_crypto else 'unknown'),
            'inference_source': 'project_request_wrappers',
        },
        'oracle_hints': _oracle_hints_from_params(bindings['params']),
        'side_effect': side_effect,
        'plain_request_shape': None,
        'mutation_points': [],
        'transform_chain': {
            'request_encryptors_ref': [],
            'header_signers_ref': [],
            'response_decryptors_ref': [],
        },
        'safety_policy': {
            'mode': 'authorized_non_destructive_validation',
            'prefer_read_only_first': True,
        },
        'execution_policy': {
            'http_method_binding': 'static.http.method',
            'semantic_method_binding': 'forbidden',
        },
    }

    if contract:
        shape = contract.get('plain_request_shape') or {}
        body = {}
        for item in shape.get('query_or_body_params') or []:
            if isinstance(item, dict):
                body.update(item)
        headers = {}
        for item in shape.get('headers') or []:
            if isinstance(item, dict):
                headers.update(item)
        block['plain_request_shape'] = {'body': body, 'headers': headers}
        mps = []
        for mp in contract.get('mutation_points') or []:
            field = mp.get('field')
            meta = classify_binding_param(field) if field else {}
            mps.append({
                'field': field,
                'static_role': meta.get('static_role') or _legacy_role_to_binding(mp.get('role') or ''),
                'mutate_at_stage': mp.get('mutate_at_stage') or 'plain_stage',
                'strategy': mp.get('strategy') or 'replace_with_owned_object_value',
            })
        block['mutation_points'] = mps
        req_chain = contract.get('request_transform_chain') or {}
        block['transform_chain'] = {
            'request_encryptors_ref': [c.get('crypto_id') for c in req_chain.get('core_request_encryptors') or [] if c.get('crypto_id')],
            'header_signers_ref': [c.get('crypto_id') for c in req_chain.get('core_header_signers') or [] if c.get('crypto_id')],
            'response_decryptors_ref': [
                c.get('crypto_id') for c in (contract.get('response_transform_chain') or {}).get('core_response_decryptors') or []
                if c.get('crypto_id')
            ],
        }
        block['safety_policy'] = contract.get('safety_policy') or block['safety_policy']
    elif readiness_status == 'ready':
        block['readiness']['blockers'] = list(set((block['readiness']['blockers'] or []) + ['not_in_replay_top_k']))

    return block


def _build_ranking(
    op: Dict[str, Any],
    bindings: Dict[str, Any],
    replay: Dict[str, Any],
    card_kind: str,
    allow_fuzzing: bool,
) -> Dict[str, Any]:
    path = (op.get('endpoint') or {}).get('path') or ''
    params = bindings.get('params') or []
    negatives = _negative_reasons(path, op.get('url_key_candidates') or [], op.get('method') or 'UNKNOWN', params)
    side_effect = replay.get('side_effect') or {}
    ser = _side_effect_risk(side_effect)
    oracle = _oracle_likelihood(op.get('method') or 'UNKNOWN', negatives, params, side_effect)
    readiness = (replay.get('readiness') or {}).get('status') or 'partial'
    tier = _priority_tier(card_kind, readiness, side_effect, ser, oracle, params, negatives, allow_fuzzing)
    val = _validation_value(tier, _has_binding_candidate(params), negatives, card_kind)

    positive = []
    if _has_binding_candidate(params):
        positive.append('has_binding_identifier_candidate')
    if readiness == 'ready':
        positive.append('replay_ready')
    if op.get('supporting_sources'):
        positive.append('has_callsite_evidence')

    rank_reason = list(op.get('rank_reason') or [])
    for old, new in [
        ('has_object_credential', 'has_object_identifier_candidate'),
        ('has_capability_credential', 'has_capability_credential_candidate'),
    ]:
        if old in rank_reason:
            rank_reason = [new if x == old else x for x in rank_reason]

    tier_rationale = f"priority_tier={tier}; validation_value={val}"
    if negatives:
        tier_rationale += f"; negatives={','.join(negatives[:3])}"

    return {
        'rank': op.get('rank'),
        'rank_score': op.get('rank_score'),
        'rank_reason': rank_reason,
        'priority_tier': tier,
        'validation_value': val,
        'side_effect_risk': ser,
        'oracle_likelihood': oracle,
        'binding_review_value': val if val != 'none' else 'low',
        'positive_signals': positive,
        'negative_reasons': negatives,
        'tier_rationale': tier_rationale,
        'fuzzing_gate': _fuzzing_gate(tier, side_effect, readiness, allow_fuzzing),
    }


def _operation_downstream_policy() -> Dict[str, Any]:
    return {
        'allow_llm_semantic_typing': True,
        'allow_cwg_seed': True,
        'allow_replay': True,
        'allow_fuzzing': 'gated_by_ranking.fuzzing_gate',
        'reason': 'concrete_callsite_operation',
    }


def _registered_downstream_policy() -> Dict[str, Any]:
    return {
        'allow_llm_semantic_typing': True,
        'allow_cwg_seed': True,
        'allow_replay': False,
        'allow_fuzzing': False,
        'allow_manual_promotion_to_operation': False,
        'reason': 'registry_only_without_concrete_callsite',
    }


def build_operation_card(
    op: Dict[str, Any],
    contract: Optional[Dict[str, Any]],
    *,
    surface_shape: str,
    wrappers: List[Dict[str, Any]],
    frozen_at: str,
) -> Dict[str, Any]:
    endpoint = op.get('endpoint') or {}
    bindings = _build_bindings(op)
    evidence = _build_evidence(op)
    replay = _build_replay_block(op, contract, wrappers, frozen_at)
    ranking = _build_ranking(op, bindings, replay, 'operation', allow_fuzzing=True)

    artifacts = [f"ranked_api_candidates.json#rank={op.get('rank')}"]
    if contract:
        artifacts.append(f"replay_contracts.json#contract_id={contract.get('contract_id')}")

    path_tokens = tokenise_identifier(endpoint.get('path') or '')

    return {
        'card_id': op.get('operation_id'),
        'schema_version': SCHEMA_VERSION,
        'provenance': {
            'card_kind': 'operation',
            'source_artifacts': artifacts,
            'operation_id': op.get('operation_id'),
            'operation_key': op.get('operation_key'),
            'legacy_api_id': None,
            'frozen_at': frozen_at,
        },
        'static': {
            'endpoint': {
                'normalized_url': endpoint.get('normalized_url'),
                'host': endpoint.get('host'),
                'path': endpoint.get('path'),
                'query_schema': endpoint.get('query_schema') or [],
                'original_url': endpoint.get('original_url'),
                'url_role': endpoint.get('url_role'),
                'host_pool': endpoint.get('host_pool'),
                'is_chain_eligible': endpoint.get('is_chain_eligible'),
                'url_key_candidates': op.get('url_key_candidates') or [],
                'url_classification': op.get('url_classification') or {},
            },
            'http': {
                'method': op.get('method'),
                'method_source': op.get('method_source'),
                'method_confidence': op.get('method_confidence'),
                'method_trust_tier': _method_trust_tier(op.get('method') or 'UNKNOWN', float(op.get('method_confidence') or 0)),
            },
            'host_resolution': op.get('host_resolution') or {},
            'surface': {
                'surface_types': op.get('surface_types') or {},
                'support_count': op.get('support_count') or 0,
                'surface_shape': surface_shape,
            },
            'business_hints': {
                'description_args': op.get('description_args') or [],
                'path_tokens': path_tokens,
                'sensitive_hint': bool(op.get('risk_hints')),
            },
        },
        'evidence': evidence,
        'bindings': bindings,
        'reachability': _reachability_from_sources(op.get('supporting_sources') or []),
        'downstream_policy': _operation_downstream_policy(),
        'replay': replay,
        'ranking': ranking,
        'semantic': _empty_semantic(),
    }


def build_registered_only_card(
    reg: Dict[str, Any],
    *,
    surface_shape: str,
    frozen_at: str,
) -> Dict[str, Any]:
    endpoint = reg.get('endpoint') or {}
    path = endpoint.get('resolved_url') or ''
    path_only = path.split('?', 1)[0]
    if path_only.startswith('http'):
        from urllib.parse import urlparse

        path_only = urlparse(path_only).path or path_only

    params_out = []
    for p in reg.get('request_context', {}).get('params') or []:
        name = p.get('name')
        meta = classify_binding_param(name, source='registry_inference')
        legacy = p.get('credential_role')
        if legacy:
            meta['static_role'] = _legacy_role_to_binding(legacy)
        params_out.append({
            'name': name,
            'where': p.get('where') or 'body',
            **meta,
            'required_guess': bool(p.get('required_guess', True)),
        })

    src = reg.get('source') or {}
    evidence = {
        'quality': {'score': 2.0, 'reasons': ['registry_only'], 'offset_local_count': 0},
        'callsites': [{
            'evidence_id': 'ev_0',
            'call_id': None,
            'file': src.get('file'),
            'line': src.get('line'),
            'snippet': _truncate_snippet(src.get('snippet') or ''),
            'evidence_strategy': 'registry_snippet',
            'focus_meta': None,
        }] if src.get('file') or src.get('snippet') else [],
        'primary_evidence_id': 'ev_0' if src.get('file') or src.get('snippet') else None,
    }

    replay = {
        'contract_id': None,
        'contract_included_in_top_k': False,
        'readiness': {
            'status': 'not_applicable',
            'blockers': ['no_callsite_replay_surface'],
            'suggested_next_step': 'llm_registry_review_only',
        },
        'transport': {
            'content_type': 'unknown',
            'body_encoding': 'unknown',
            'query_encoding': 'unknown',
            'inference_source': 'registry_only',
        },
        'auth_dependency': {
            'requires_auth': bool(reg.get('crypto_context', {}).get('uses_project_http_crypto')),
            'auth_locations': [],
            'auth_fields': [],
            'auth_status': 'unknown',
            'inference_source': 'registry_inference',
        },
        'oracle_hints': _oracle_hints_from_params(params_out),
        'side_effect': {'category': 'unknown', 'auto_execute_allowed': False, 'inference_source': 'registry_only'},
        'plain_request_shape': None,
        'mutation_points': [],
        'transform_chain': {'request_encryptors_ref': [], 'header_signers_ref': [], 'response_decryptors_ref': []},
        'safety_policy': {'mode': 'authorized_non_destructive_validation', 'prefer_read_only_first': True},
        'execution_policy': {'http_method_binding': 'static.http.method', 'semantic_method_binding': 'forbidden'},
    }

    pseudo_op = {
        'endpoint': {'path': path_only, 'normalized_url': path},
        'method': endpoint.get('method') or 'UNKNOWN',
        'url_key_candidates': [endpoint.get('url_key')] if endpoint.get('url_key') else [],
        'rank': None,
        'rank_score': 0,
        'rank_reason': ['registered_only'],
        'risk_hints': reg.get('risk_hints') or [],
        'credential_roles': {},
        'supporting_sources': [],
    }
    bindings = {'params': params_out, 'binding_hints_static': _binding_hints(reg.get('risk_hints') or [], {})}
    ranking = _build_ranking(pseudo_op, bindings, replay, 'registered_only', allow_fuzzing=False)
    ranking['priority_tier'] = 'P2'
    ranking['validation_value'] = 'low'
    ranking['fuzzing_gate'] = {'auto_fuzz_eligible': False, 'requires_manual_promotion': True, 'promotion_requires': ['callsite_promotion']}

    return {
        'card_id': reg.get('api_id'),
        'schema_version': SCHEMA_VERSION,
        'provenance': {
            'card_kind': 'registered_only',
            'source_artifacts': [f"registered_only_api_cards.json#api_id={reg.get('api_id')}"],
            'operation_id': None,
            'operation_key': endpoint.get('url_key') or path,
            'legacy_api_id': reg.get('api_id'),
            'frozen_at': frozen_at,
        },
        'static': {
            'endpoint': {
                'normalized_url': path,
                'host': None,
                'path': path_only,
                'query_schema': [],
                'original_url': endpoint.get('raw_url_expr') or path,
                'url_key_candidates': [endpoint.get('url_key')] if endpoint.get('url_key') else [],
                'url_classification': reg.get('url_classification') or {'url_type': 'registered_only', 'is_business_api': True},
            },
            'http': {
                'method': endpoint.get('method') or 'UNKNOWN',
                'method_source': 'unresolved',
                'method_confidence': 0.0,
                'method_trust_tier': 'unknown',
            },
            'host_resolution': {'strategy': 'registry_url', 'confidence': 0.5},
            'surface': {'surface_types': {'registry': 1}, 'support_count': 0, 'surface_shape': surface_shape},
            'business_hints': {
                'description_args': [],
                'path_tokens': tokenise_identifier(path_only),
                'sensitive_hint': bool((reg.get('business_hints') or {}).get('sensitive_hint')),
            },
        },
        'evidence': evidence,
        'bindings': bindings,
        'reachability': {
            'level': 'R2',
            'card_type': 'registered_only',
            'evidence': (reg.get('reachability') or {}).get('evidence') or 'Found in URL registry only',
            'page_context': {'page_or_module': None, 'event_linkage': 'not_resolved'},
            'orphan_registry': True,
        },
        'downstream_policy': _registered_downstream_policy(),
        'replay': replay,
        'ranking': ranking,
        'semantic': _empty_semantic(),
    }


def build_evidence_pack(card: Dict[str, Any]) -> Dict[str, Any]:
    static = card.get('static') or {}
    endpoint = static.get('endpoint') or {}
    evidence = card.get('evidence') or {}
    snippets = []
    for cs in evidence.get('callsites') or []:
        snippets.append({
            'evidence_id': cs.get('evidence_id'),
            'file': cs.get('file'),
            'line': cs.get('line'),
            'text': cs.get('snippet'),
            'why_included': 'primary_callsite' if cs.get('evidence_id') == evidence.get('primary_evidence_id') else 'supporting_callsite',
        })
    return {
        'card_id': card.get('card_id'),
        'evidence_pack_version': SCHEMA_VERSION,
        'static_summary': {
            'method': (static.get('http') or {}).get('method'),
            'path': endpoint.get('path'),
            'surface_shape': (static.get('surface') or {}).get('surface_shape'),
        },
        'snippets': snippets,
        'bindings_summary': {
            'params': [p.get('name') for p in (card.get('bindings') or {}).get('params') or []],
            'binding_hints_static': (card.get('bindings') or {}).get('binding_hints_static') or [],
        },
        'crypto_refs': (card.get('replay') or {}).get('transform_chain', {}).get('request_encryptors_ref') or [],
        'do_not_fetch': ['full source tree', 'raw webpack chunks', 'api_call_sites.json', 'all_api_cards.json'],
    }


def _validate_manifest(manifest: Dict[str, Any]) -> List[str]:
    errors = []
    total = manifest['card_inventory']['total_cards']
    by_status = manifest['readiness_inventory']['by_status']
    if sum(by_status.values()) != total:
        errors.append(f'readiness sum {sum(by_status.values())} != total_cards {total}')
    rep = manifest['replay_inventory']
    if rep['cards_with_replay_contract'] + rep['cards_without_replay_contract'] != total:
        errors.append('replay_inventory does not sum to total_cards')
    for card in manifest.get('_cards_ref') or []:
        dp = card.get('downstream_policy') or {}
        if card.get('provenance', {}).get('card_kind') == 'registered_only':
            if dp.get('allow_replay') or dp.get('allow_fuzzing'):
                errors.append(f"registered_only card {card.get('card_id')} allows replay/fuzzing")
        sem = card.get('semantic') or {}
        if sem.get('_phase') != 'reserved_for_llm':
            errors.append(f"semantic not reserved on {card.get('card_id')}")
        pe = (card.get('evidence') or {}).get('primary_evidence_id')
        if pe:
            ids = {c.get('evidence_id') for c in (card.get('evidence') or {}).get('callsites') or []}
            if pe not in ids:
                errors.append(f'primary_evidence_id unresolved on {card.get("card_id")}')
    return errors


def build_manifest(
    cards: List[Dict[str, Any]],
    *,
    pack_id: str,
    generated_at: str,
    project_root: str,
    app_label: str,
    surface_shape: str,
    registered_only_policy: Dict[str, Any],
    dedup_report: Dict[str, Any],
    input_fingerprint: str = '',
) -> Dict[str, Any]:
    by_kind = Counter(c.get('provenance', {}).get('card_kind') for c in cards)
    readiness = Counter((c.get('replay') or {}).get('readiness', {}).get('status') for c in cards)
    readiness_by_kind: Dict[str, Counter] = {}
    replay_by_kind: Dict[str, Dict[str, int]] = {}
    for c in cards:
        kind = c.get('provenance', {}).get('card_kind') or 'unknown'
        st = (c.get('replay') or {}).get('readiness', {}).get('status') or 'unknown'
        readiness_by_kind.setdefault(kind, Counter())[st] += 1
        has_contract = bool((c.get('replay') or {}).get('contract_id'))
        bucket = replay_by_kind.setdefault(kind, {'with_contract': 0, 'without_contract': 0})
        if has_contract:
            bucket['with_contract'] += 1
        else:
            bucket['without_contract'] += 1

    fuzz_eligible = sum(1 for c in cards if (c.get('ranking') or {}).get('fuzzing_gate', {}).get('auto_fuzz_eligible'))
    replay_eligible = sum(1 for c in cards if (c.get('downstream_policy') or {}).get('allow_replay') is True)
    high_rank_not_p0 = sum(
        1 for c in cards
        if (c.get('ranking') or {}).get('rank') == 1 and (c.get('ranking') or {}).get('priority_tier') != 'P0'
    )

    reg_policy_use = 'llm_semantic_typing_and_cwg_seed_only' if surface_shape == 'registry_rich' else 'informational_only_ignore'

    manifest: Dict[str, Any] = {
        'schema_version': SCHEMA_VERSION,
        'pack_id': pack_id,
        'generated_at': generated_at,
        'generator': {'tool': 'MiniDrifter', 'pipeline_stage': 'static_frozen'},
        'source_snapshot': {
            'project_root': project_root,
            'input_fingerprint': input_fingerprint,
            'static_outputs_consumed': [
                'ranked_api_candidates.json',
                'replay_contracts.json',
                'registered_only_api_cards.json',
                'crypto_core_chains.json',
                'dedup_report.json',
                'request_wrappers.json',
            ],
            'static_outputs_audit_only': [
                'api_call_sites.json',
                'all_api_cards.json',
                'reached_api_cards.json',
            ],
        },
        'project_context': {
            'app_label': app_label,
            'platform': 'wechat',
            'surface_shape': surface_shape,
            'registered_only_policy': reg_policy_use,
        },
        'card_inventory': {
            'total_cards': len(cards),
            'by_provenance': {
                'operation_ranked': by_kind.get('operation', 0),
                'registered_only': by_kind.get('registered_only', 0),
            },
            'by_card_kind': dict(by_kind),
        },
        'readiness_inventory': {
            'population': 'all_api_cards',
            'by_status': dict(readiness),
            'by_card_kind_and_status': {k: dict(v) for k, v in readiness_by_kind.items()},
        },
        'replay_inventory': {
            'population': 'all_api_cards',
            'cards_with_replay_contract': sum(1 for c in cards if (c.get('replay') or {}).get('contract_id')),
            'cards_without_replay_contract': sum(1 for c in cards if not (c.get('replay') or {}).get('contract_id')),
            'note': 'contract exists only for Top-K replay_contracts join; readiness may still be ready/partial without contract',
            'by_card_kind': replay_by_kind,
        },
        'downstream_inventory': {
            'llm_semantic_eligible': len(cards),
            'cwg_seed_eligible': len(cards),
            'replay_eligible': replay_eligible,
            'fuzzing_eligible': fuzz_eligible,
            'high_rank_but_not_p0': high_rank_not_p0,
        },
        'upstream_stats_reference': {
            'dedup_report_replay_readiness': {
                'population': 'normalized_api_operations',
                'count': dedup_report.get('normalized_api_operations'),
                'ready': (dedup_report.get('replay_readiness_counts') or {}).get('ready'),
                'partial': (dedup_report.get('replay_readiness_counts') or {}).get('partial'),
                'note': 'NOT equal to api_cards total; do not merge into readiness_inventory without relabeling population',
            },
        },
        'consumption_policy': {
            'downstream_must_consume': 'api_cards.json',
            'downstream_must_not_consume': ['api_call_sites.json', 'all_api_cards.json'],
            'replay_http_method_source': 'static.http.method_only',
            'semantic_method_usage': 'review_only_not_for_replay',
            'llm_may_write': ['semantic'],
            'llm_must_not_write': ['static', 'bindings', 'evidence', 'replay', 'ranking', 'downstream_policy'],
            'vulnerability_verdict': 'forbidden_in_this_layer',
        },
        'fuzzing_eligibility': {
            'requires': [
                'card_kind == operation',
                'downstream_policy.allow_fuzzing == true',
                'ranking.fuzzing_gate.auto_fuzz_eligible == true',
                'replay.readiness.status == ready',
                'replay.side_effect.auto_execute_allowed == true',
                'replay.transport.content_type != unknown',
            ],
        },
        'registered_only_policy': {
            'actionable': registered_only_policy.get('actionable', False),
            'card_count': by_kind.get('registered_only', 0),
            'downstream_use': reg_policy_use,
            'forbidden_downstream': ['replay_runner', 'auto_fuzzer', 'binding_drift_auto_validation'],
        },
        '_cards_ref': cards,
    }
    return manifest


class APICardFreezer:
    def __init__(
        self,
        ranked: List[Dict[str, Any]],
        replay_contracts: List[Dict[str, Any]],
        registered_only: List[Dict[str, Any]],
        *,
        dedup_report: Optional[Dict[str, Any]] = None,
        request_wrappers: Optional[List[Dict[str, Any]]] = None,
        project_profile: Optional[Dict[str, Any]] = None,
        registered_only_policy: Optional[Dict[str, Any]] = None,
        app_label: str = '',
        include_registered_only: str = 'auto',
        top_k_evidence: int = 100,
    ):
        self.ranked = ranked
        self.replay_contracts = replay_contracts
        self.registered_only = registered_only
        self.dedup_report = dedup_report or {}
        self.wrappers = request_wrappers or []
        self.project_profile = project_profile or {}
        self.registered_only_policy = registered_only_policy or self.dedup_report.get('registered_only_policy') or {}
        self.app_label = app_label
        self.include_registered_only = include_registered_only
        self.top_k_evidence = top_k_evidence

    @classmethod
    def from_output_dir(cls, path: str | Path, **kwargs) -> 'APICardFreezer':
        p = Path(path)

        def j(name: str, default: Any = None):
            fp = p / name
            if not fp.exists():
                return default
            return json.loads(fp.read_text(encoding='utf-8'))

        profile = j('project_profile.json', {}) or {}
        dedup = j('dedup_report.json', {}) or {}
        label = kwargs.pop('app_label', None) or p.name
        return cls(
            ranked=j('ranked_api_candidates.json', []) or [],
            replay_contracts=j('replay_contracts.json', []) or [],
            registered_only=j('registered_only_api_cards.json', []) or [],
            dedup_report=dedup,
            request_wrappers=j('request_wrappers.json', []) or [],
            project_profile=profile,
            registered_only_policy=dedup.get('registered_only_policy') or {},
            app_label=label,
            **kwargs,
        )

    def run(self) -> Dict[str, Any]:
        frozen_at = _utc_now_iso()
        surface_shape = self.dedup_report.get('surface_shape') or 'mixed'
        contract_by_op = {c.get('operation_id'): c for c in self.replay_contracts if c.get('operation_id')}

        cards: List[Dict[str, Any]] = []
        for op in self.ranked:
            cards.append(
                build_operation_card(
                    op,
                    contract_by_op.get(op.get('operation_id')),
                    surface_shape=surface_shape,
                    wrappers=self.wrappers,
                    frozen_at=frozen_at,
                )
            )

        include_reg = self.include_registered_only
        if include_reg == 'auto':
            include_reg = 'yes' if surface_shape == 'registry_rich' and self.registered_only_policy.get('actionable') else 'no'

        if include_reg == 'yes':
            for reg in self.registered_only:
                cards.append(build_registered_only_card(reg, surface_shape=surface_shape, frozen_at=frozen_at))

        pack_id = f"pack_{self.app_label}_{datetime.now(timezone.utc).strftime('%Y%m%d')}"
        manifest = build_manifest(
            cards,
            pack_id=pack_id,
            generated_at=frozen_at,
            project_root=str(self.project_profile.get('project_root') or ''),
            app_label=self.app_label,
            surface_shape=surface_shape,
            registered_only_policy=self.registered_only_policy,
            dedup_report=self.dedup_report,
        )
        errors = _validate_manifest(manifest)
        cards_ref = manifest.pop('_cards_ref', None)

        evidence_packs = []
        sorted_for_pack = sorted(
            cards,
            key=lambda c: (
                {'P0': 0, 'P1': 1, 'P2': 2, 'P3': 3}.get((c.get('ranking') or {}).get('priority_tier'), 9),
                (c.get('ranking') or {}).get('rank') or 9999,
            ),
        )
        for card in sorted_for_pack[: self.top_k_evidence]:
            evidence_packs.append(build_evidence_pack(card))

        return {
            'api_cards': cards,
            'manifest': manifest,
            'evidence_packs': evidence_packs,
            'validation_errors': errors,
        }

    def write(self, output_dir: str | Path) -> Dict[str, Any]:
        result = self.run()
        write_frozen_outputs(output_dir, result)
        return result


def write_frozen_outputs(output_dir: str | Path, result: Dict[str, Any]) -> None:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    write_json(out / 'api_cards.json', result['api_cards'])
    write_json(out / 'api_card_pack_manifest.json', result['manifest'])
    pack_dir = out / 'evidence_packs'
    pack_dir.mkdir(parents=True, exist_ok=True)
    for pack in result.get('evidence_packs') or []:
        cid = pack.get('card_id') or 'unknown'
        write_json(pack_dir / f'{cid}.json', pack)
