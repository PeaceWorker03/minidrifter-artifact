# -*- coding: utf-8 -*-
"""Rule-based Evidence Requirement Detector with Account-aware N0/N1 runtime levels."""
from __future__ import annotations

import re
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Set, Tuple

from minidrifter.quality.sensitive_surface import resolve_verification_intent
from minidrifter.reasoning.runtime_skeleton import build_runtime_requirement_skeleton

from minidrifter.core.schema import SCHEMA_VERSION

N0_LEVEL = 'N0_STATIC_TEMPLATE'
N1_LEVEL = 'N1_BASELINE_RUNTIME_TEMPLATE'

N1_BINDING_ROLES = {
    'subject_identifier_candidate',
    'object_identifier_candidate',
    'capability_credential_candidate',
    'context_identifier_candidate',
    'auth_credential_candidate',
    'crypto_material',
}

LOW_RISK_SIDE_EFFECTS = {'read_only'}
CONFIG_LIKE_NEGATIVE = {'config_api', 'agreement_or_banner'}

CRYPTO_BLOCKER_TOKENS = re.compile(
    r'crypto|encrypt|sign|auth|runtime|method_unresolved|param_schema',
    re.I,
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _binding_params(card: Dict[str, Any]) -> List[Dict[str, Any]]:
    return (card.get('bindings') or {}).get('params') or []


def _params_by_role(card: Dict[str, Any], roles: Set[str]) -> List[Dict[str, Any]]:
    return [p for p in _binding_params(card) if p.get('static_role') in roles]


def _endpoint_complete(card: Dict[str, Any]) -> bool:
    ep = (card.get('static') or {}).get('endpoint') or {}
    host = ep.get('host')
    path = ep.get('path')
    if not path:
        return False
    if host:
        return True
    url = ep.get('normalized_url') or ''
    return url.startswith('http')


def _is_config_like(card: Dict[str, Any]) -> bool:
    negatives = set((card.get('ranking') or {}).get('negative_reasons') or [])
    if negatives & CONFIG_LIKE_NEGATIVE:
        return True
    path = ((card.get('static') or {}).get('endpoint') or {}).get('path') or ''
    return bool(re.search(r'config|settings|banner|entrance|description|protocol|privacy', path, re.I))


def _has_unsafe_params(card: Dict[str, Any]) -> Tuple[bool, str]:
    params = _binding_params(card)
    if not params:
        return False, ''
    for p in params:
        role = p.get('static_role') or ''
        if role in N1_BINDING_ROLES:
            return True, f"binding_role:{role}:{p.get('name')}"
        if role == 'unknown' and p.get('required_guess'):
            return True, f"unknown_required_param:{p.get('name')}"
    non_ordinary = [p for p in params if (p.get('static_role') or '') != 'ordinary_parameter']
    if non_ordinary:
        return True, 'non_ordinary_parameters_present'
    return False, ''


def classify_runtime_requirement(card: Dict[str, Any]) -> Dict[str, Any]:
    """Conservative Account-aware N0/N1 classifier. N1 is the default."""
    kind = (card.get('provenance') or {}).get('card_kind') or 'operation'
    static = card.get('static') or {}
    http = static.get('http') or {}
    replay = card.get('replay') or {}
    ranking = card.get('ranking') or {}
    readiness = (replay.get('readiness') or {}).get('status') or 'partial'
    readiness_blockers = (replay.get('readiness') or {}).get('blockers') or []
    auth = replay.get('auth_dependency') or {}
    transport = replay.get('transport') or {}
    chain = replay.get('transform_chain') or {}
    side = (replay.get('side_effect') or {}).get('category') or 'unknown'
    oracle = ranking.get('oracle_likelihood') or 'unknown'

    n1_triggers: List[str] = []
    non_blocking_warnings: List[str] = []

    if kind == 'registered_only':
        return _runtime_requirement_result(
            N1_LEVEL,
            'Registry-only surface without concrete callsite; static template is not reliable.',
            ['registry_review_only'],
            n1_triggers=['registered_only_without_callsite'],
            non_blocking_warnings=[],
            validation_scope={
                'can_attempt_static_replay': False,
                'can_attempt_baseline_replay': False,
                'can_attempt_parameter_mutation': False,
                'can_confirm_binding_violation': False,
            },
            allowed_result_strength='registry_review_only',
            next_stage_if_needed='callsite_promotion_or_manual_review',
        )

    if kind != 'operation':
        return _runtime_requirement_result(
            N1_LEVEL,
            'Non-operation card cannot use static template replay.',
            ['static_request_template'],
            n1_triggers=['non_operation_card'],
            non_blocking_warnings=[],
            validation_scope=_validation_scope_for(N1_LEVEL),
            allowed_result_strength='inconclusive',
            next_stage_if_needed='import_runtime_request',
        )

    if auth.get('requires_auth'):
        n1_triggers.append('auth_context_required')
    if readiness == 'partial':
        n1_triggers.append('replay_readiness_partial')
    if any(CRYPTO_BLOCKER_TOKENS.search(b) for b in readiness_blockers):
        n1_triggers.append('replay_blockers_crypto_auth_runtime')
    if transport.get('body_encoding') == 'encrypted' or chain.get('request_encryptors_ref'):
        n1_triggers.append('encrypted_body_or_transform_chain')
    if transport.get('query_encoding') == 'encrypted':
        n1_triggers.append('encrypted_query')

    unsafe, unsafe_reason = _has_unsafe_params(card)
    if unsafe:
        n1_triggers.append(unsafe_reason)

    if side not in LOW_RISK_SIDE_EFFECTS and not (_is_config_like(card) and side == 'unknown'):
        n1_triggers.append(f'side_effect:{side}')
    if side in {'state_changing', 'payment_related', 'destructive'}:
        if f'side_effect:{side}' not in n1_triggers:
            n1_triggers.append(f'side_effect:{side}')

    if http.get('method') in (None, 'UNKNOWN') or http.get('method_trust_tier') in {'unknown', 'low'}:
        n1_triggers.append('method_untrusted')
    if not _endpoint_complete(card):
        n1_triggers.append('endpoint_incomplete')

    # Oracle: account-scoped business APIs need baseline; public/config may stay N0 candidate
    if oracle in {'low', 'medium', 'unknown'} and not _is_config_like(card):
        n1_triggers.append('oracle_needs_baseline')
    if _params_by_role(card, N1_BINDING_ROLES):
        if not any(t.startswith('binding_role:') for t in n1_triggers):
            n1_triggers.append('binding_identifier_candidates')

    for p in _binding_params(card):
        if p.get('ambiguity'):
            non_blocking_warnings.append('param_role_ambiguous')
            break
    if oracle in {'low', 'unknown'}:
        non_blocking_warnings.append('oracle_low_confidence')
    if http.get('method_trust_tier') == 'medium':
        non_blocking_warnings.append('method_medium_confidence')

    if n1_triggers:
        blocking = ['runtime_request_sample', 'baseline_response']
        if auth.get('requires_auth'):
            blocking.append('auth_context')
        if transport.get('body_encoding') == 'encrypted' or chain.get('request_encryptors_ref'):
            blocking.append('crypto_plaintext_template')
        blocking = list(dict.fromkeys(blocking))
        return _runtime_requirement_result(
            N1_LEVEL,
            _n1_reason_text(n1_triggers),
            ['A.raw_request', 'A.auth_context', 'A.baseline_response'] if auth.get('requires_auth') else ['A.raw_request', 'A.baseline_response'],
            n1_triggers=n1_triggers,
            non_blocking_warnings=sorted(set(non_blocking_warnings)),
            validation_scope=_validation_scope_for(N1_LEVEL),
            allowed_result_strength='baseline_replay_or_potential_risk',
            next_stage_if_needed='import_baseline_runtime_template',
            blocking_requirements=blocking,
        )

    # N0: all conservative checks passed
    return _runtime_requirement_result(
        N0_LEVEL,
        'Static evidence suggests a public or config-like read surface without auth, crypto, or account-scoped parameters.',
        ['static_request_template'],
        n1_triggers=[],
        non_blocking_warnings=sorted(set(non_blocking_warnings)),
        validation_scope=_validation_scope_for(N0_LEVEL),
        allowed_result_strength='public_reachable_or_inconclusive',
        next_stage_if_needed='import_runtime_request_if_auth_required',
        blocking_requirements=[],
    )


def _validation_scope_for(level: str) -> Dict[str, bool]:
    if level == N0_LEVEL:
        return {
            'can_attempt_static_replay': True,
            'can_attempt_baseline_replay': False,
            'can_attempt_parameter_mutation': False,
            'can_confirm_binding_violation': False,
        }
    return {
        'can_attempt_static_replay': False,
        'can_attempt_baseline_replay': True,
        'can_attempt_parameter_mutation': True,
        'can_confirm_binding_violation': False,
    }


def _runtime_requirement_result(
    level: str,
    reason: str,
    minimum_inputs: List[str],
    *,
    n1_triggers: List[str],
    non_blocking_warnings: List[str],
    validation_scope: Dict[str, bool],
    allowed_result_strength: str,
    next_stage_if_needed: str,
    blocking_requirements: List[str] | None = None,
) -> Dict[str, Any]:
    return {
        'level': level,
        'reason': reason,
        'minimum_inputs': minimum_inputs,
        'allowed_result_strength': allowed_result_strength,
        'next_stage_if_needed': next_stage_if_needed,
        'n1_triggers': n1_triggers,
        'blocking_requirements': blocking_requirements or [],
        'non_blocking_warnings': non_blocking_warnings,
        'validation_scope': validation_scope,
    }


def _n1_reason_text(triggers: List[str]) -> str:
    head = triggers[:4]
    more = len(triggers) - len(head)
    text = 'Endpoint requires authenticated runtime context or non-static parameters: ' + ', '.join(head)
    if more > 0:
        text += f' (+{more} more)'
    return text


def detect_card_requirements(card: Dict[str, Any]) -> Dict[str, Any]:
    kind = (card.get('provenance') or {}).get('card_kind') or 'operation'
    ranking = card.get('ranking') or {}
    replay = card.get('replay') or {}
    readiness = (replay.get('readiness') or {}).get('status') or 'partial'
    runtime = classify_runtime_requirement(card)
    requirements: List[Dict[str, Any]] = []

    if kind == 'registered_only':
        requirements.append(_req(
            'registry_surface_review', 'info', 'not_applicable',
            'Registry-only endpoint; use for LLM typing and CWG seed only.',
        ))
        return _finalize_requirements(card, requirements, 'registry_review', runtime)

    intent = resolve_verification_intent(
        card,
        runtime_level=runtime['level'],
        validation_value=ranking.get('validation_value'),
    )

    if runtime['level'] == N1_LEVEL:
        requirements.append(_req(
            'runtime_request_sample', 'blocking', 'missing',
            'Authorized capture: method, url, headers, body, response.',
            collect_hints=['Trigger the page flow that calls this endpoint'],
            card_refs=['static.http.method', 'replay.transport'],
        ))
        requirements.append(_req(
            'baseline_response', 'blocking', 'missing',
            'Baseline response from account A for oracle calibration.',
        ))

        auth = replay.get('auth_dependency') or {}
        if auth.get('requires_auth') or 'auth_context' in runtime.get('blocking_requirements', []):
            known = auth.get('auth_fields') or []
            requirements.append(_req(
                'auth_context', 'blocking', 'missing',
                'Session/auth header values required for replay.',
                fields=known,
                known_from_static=known,
                missing_values=list(known),
            ))

        transport = replay.get('transport') or {}
        chain = replay.get('transform_chain') or {}
        if 'crypto_plaintext_template' in runtime.get('blocking_requirements', []):
            requirements.append(_req(
                'crypto_plaintext_template', 'blocking', 'missing',
                'Need plaintext/ciphertext pair or node_bridge transform confirmation.',
                crypto_refs=chain.get('request_encryptors_ref') or [],
            ))

    for p in _binding_params(card):
        if p.get('ambiguity'):
            requirements.append(_req(
                'binding_role_disambiguation', 'major', 'missing',
                f"Disambiguate role for {p.get('name')}.",
                fields=[{'name': p.get('name'), 'ambiguity': p.get('ambiguity')}],
            ))

    if runtime['level'] == N1_LEVEL and (ranking.get('oracle_likelihood') or 'unknown') in {'low', 'unknown'}:
        requirements.append(_req(
            'oracle_calibration', 'major', 'missing',
            'Need baseline success response sample.',
            success_code_fields=(replay.get('oracle_hints') or {}).get('success_code_fields'),
        ))

    if runtime['level'] == N1_LEVEL and ranking.get('validation_value') in {'medium', 'high'}:
        if _params_by_role(card, {'object_identifier_candidate'}):
            requirements.append(_req(
                'account_pair', 'major', 'missing',
                'Second account needed only for later binding mutation stage, not for N1 baseline.',
                collect_hints=['Defer until baseline template imported'],
            ))

    if readiness != 'ready' and runtime['level'] == N1_LEVEL:
        if (card.get('static') or {}).get('http', {}).get('method_trust_tier') in {'unknown', 'low'}:
            requirements.append(_req('method_confirmation', 'major', 'missing', 'HTTP method not reliable.'))
        if not _binding_params(card) and not _is_config_like(card):
            requirements.append(_req('param_schema_completion', 'major', 'missing', 'Parameter schema incomplete.'))

    side = (replay.get('side_effect') or {}).get('category') or 'unknown'
    requirements.append(_req(
        'side_effect_safety', 'info', 'satisfied',
        f'Side effect category: {side}.',
    ))

    return _finalize_requirements(card, requirements, intent, runtime)


def _req(req_type: str, severity: str, status: str, description: str, **extra: Any) -> Dict[str, Any]:
    return {
        'req_type': req_type,
        'severity': severity,
        'status': status,
        'description': description,
        'source': 'rule',
        **extra,
    }


def _finalize_requirements(
    card: Dict[str, Any],
    requirements: List[Dict[str, Any]],
    intent: str,
    runtime: Dict[str, Any],
) -> Dict[str, Any]:
    blocking_reqs = [r['req_type'] for r in requirements if r['severity'] == 'blocking' and r['status'] == 'missing']
    # Align with runtime_requirement blocking list
    for b in runtime.get('blocking_requirements') or []:
        if b not in blocking_reqs:
            blocking_reqs.append(b)

    non_blocking = list(runtime.get('non_blocking_warnings') or [])
    for r in requirements:
        if r['severity'] == 'major' and r['status'] == 'missing':
            w = r['req_type']
            if w not in non_blocking:
                non_blocking.append(w)

    blocking_missing = sum(1 for r in requirements if r['severity'] == 'blocking' and r['status'] == 'missing')
    major_missing = sum(1 for r in requirements if r['severity'] == 'major' and r['status'] == 'missing')
    satisfied = sum(1 for r in requirements if r['status'] == 'satisfied')

    next_action = runtime.get('next_stage_if_needed') or 'import_baseline_runtime_template'
    if runtime['level'] == N0_LEVEL:
        next_action = 'attempt_static_template_replay'
    elif blocking_reqs:
        next_action = f"import_{blocking_reqs[0]}"

    ranking = card.get('ranking') or {}
    replay = card.get('replay') or {}
    readiness = (replay.get('readiness') or {}).get('status')
    kind = (card.get('provenance') or {}).get('card_kind')

    skeleton = build_runtime_requirement_skeleton(card, runtime['level'])

    return {
        'card_id': card.get('card_id'),
        'requirement_id': f"req_{card.get('card_id')}",
        'verification_intent': intent,
        'priority_tier': ranking.get('priority_tier'),
        'validation_value': ranking.get('validation_value'),
        'runtime_requirement': {
            'level': runtime['level'],
            'runtime_sublevel': skeleton.get('runtime_sublevel'),
            'reason': runtime['reason'],
            'minimum_inputs': runtime['minimum_inputs'],
            'allowed_result_strength': runtime['allowed_result_strength'],
            'next_stage_if_needed': runtime['next_stage_if_needed'],
            'n1_triggers': runtime.get('n1_triggers') or [],
        },
        'runtime_requirement_skeleton': skeleton,
        'blocking_requirements': blocking_reqs,
        'non_blocking_warnings': sorted(set(non_blocking)),
        'validation_scope': runtime['validation_scope'],
        'verdict': {
            'statically_specified': kind == 'operation' and readiness in {'ready', 'partial'},
            'runtime_evidence_sufficient': False,
            'seed_pool_sufficient': False,
            'bound_replay_ready': False,
            'auto_fuzz_ready': bool((ranking.get('fuzzing_gate') or {}).get('auto_fuzz_eligible')),
        },
        'requirements': requirements,
        'requirement_summary': {
            'blocking_missing': blocking_missing,
            'major_missing': major_missing,
            'satisfied': satisfied,
            'next_action': next_action,
        },
        'suggested_collection_plan': _collection_plan(card, requirements, runtime),
    }


def _collection_plan(card: Dict[str, Any], requirements: List[Dict[str, Any]], runtime: Dict[str, Any]) -> List[str]:
    path = ((card.get('static') or {}).get('endpoint') or {}).get('path') or ''
    if runtime['level'] == N0_LEVEL:
        return [
            f"Construct static template for `{path}` without runtime capture.",
            'If response is 401/403, reclassify as N1 and import account A baseline.',
        ]
    steps = [f"Under account A, open flow that reaches `{path}`."]
    for r in requirements:
        if r['status'] != 'missing':
            continue
        if r['req_type'] == 'runtime_request_sample':
            steps.append('Capture full request/response (HAR or mitmproxy).')
        elif r['req_type'] == 'baseline_response':
            steps.append('Save baseline response body and success fields.')
        elif r['req_type'] == 'auth_context':
            steps.append('Record Authorization/AppIdentity headers from capture.')
        elif r['req_type'] == 'crypto_plaintext_template':
            steps.append('Pair ciphertext with plaintext via node_bridge if available.')
    return steps[:8]


def _verification_profile(card: Dict[str, Any], runtime: Dict[str, Any], item: Dict[str, Any]) -> Dict[str, Any]:
    static = card.get('static') or {}
    http = static.get('http') or {}
    replay = card.get('replay') or {}
    ranking = card.get('ranking') or {}
    readiness = (replay.get('readiness') or {}).get('status')
    has_evidence = bool((card.get('evidence') or {}).get('callsites'))
    crypto = (replay.get('transport') or {}).get('body_encoding') == 'encrypted' or bool(
        (replay.get('transform_chain') or {}).get('request_encryptors_ref')
    )
    return {
        'card_id': card.get('card_id'),
        'runtime_requirement_level': runtime['level'],
        'static_completeness': 'high' if http.get('method') not in (None, 'UNKNOWN') else 'partial',
        'binding_interest': ranking.get('validation_value') or 'none',
        'replay_distance': readiness or 'unknown',
        'crypto_distance': 'blocked' if crypto else 'clear',
        'oracle_distance': ranking.get('oracle_likelihood') or 'unknown',
        'fuzzing_distance': 'pass' if (ranking.get('fuzzing_gate') or {}).get('auto_fuzz_eligible') else 'gated',
        'blocking_gap_count': item['requirement_summary']['blocking_missing'],
        'n1_trigger_count': len(runtime.get('n1_triggers') or []),
        'collectability_hint': 'high' if runtime['level'] == N1_LEVEL and readiness == 'ready' else 'medium' if has_evidence else 'low',
    }


def build_evidence_requirements(cards: List[Dict[str, Any]], manifest: Dict[str, Any]) -> Dict[str, Any]:
    items = [detect_card_requirements(c) for c in cards]
    hist = Counter()
    for item in items:
        for r in item.get('requirements') or []:
            if r.get('status') == 'missing' and r.get('severity') == 'blocking':
                hist[r['req_type']] += 1

    ops = [i for i in items if (i.get('runtime_requirement') or {}).get('level') in {N0_LEVEL, N1_LEVEL}
           and i.get('verification_intent') != 'registry_review']
    level_dist = Counter((i.get('runtime_requirement') or {}).get('level') for i in items)
    n1_blocker = Counter()
    sublevel_dist = Counter()
    side_level_dist = Counter()
    for item in items:
        sk = item.get('runtime_requirement_skeleton') or {}
        sublevel_dist[sk.get('runtime_sublevel')] += 1
        side_level_dist[sk.get('side_effect_level')] += 1
        if (item.get('runtime_requirement') or {}).get('level') != N1_LEVEL:
            continue
        for b in item.get('blocking_requirements') or []:
            n1_blocker[b] += 1

    return {
        'schema_version': SCHEMA_VERSION,
        'pack_id': manifest.get('pack_id'),
        'generated_at': _utc_now(),
        'generator': {'tool': 'MiniDrifter', 'stage': 'account_aware_rule_erd'},
        'card_count': len(items),
        'items': items,
        'erd_inventory': {
            'runtime_requirement_distribution': dict(level_dist),
            'operation_runtime_distribution': dict(Counter(
                (i.get('runtime_requirement') or {}).get('level')
                for i in items
                if i.get('verification_intent') != 'registry_review'
                and (i.get('runtime_requirement') or {}).get('level') in {N0_LEVEL, N1_LEVEL}
            )),
            'blocking_missing_histogram': dict(hist),
            'n1_blocker_distribution': dict(n1_blocker),
            'operation_with_binding_check': sum(
                1 for i in items if i.get('verification_intent') == 'subject_object_binding_check'
            ),
            'operation_with_pii_scope_check': sum(
                1 for i in items if i.get('verification_intent') == 'sensitive_data_scope_check'
            ),
            'operation_with_pii_submission': sum(
                1 for i in items if i.get('verification_intent') == 'pii_submission_flow'
            ),
            'n0_static_template_count': level_dist.get(N0_LEVEL, 0),
            'n1_baseline_template_count': level_dist.get(N1_LEVEL, 0),
            'runtime_sublevel_distribution': dict(sublevel_dist),
            'side_effect_level_distribution': dict(side_level_dist),
        },
    }


def _card_brief(card: Dict[str, Any], item: Dict[str, Any]) -> Dict[str, Any]:
    ep = (card.get('static') or {}).get('endpoint') or {}
    return {
        'card_id': card.get('card_id'),
        'path': ep.get('path'),
        'method': (card.get('static') or {}).get('http', {}).get('method'),
        'priority_tier': (card.get('ranking') or {}).get('priority_tier'),
        'replay_readiness': (card.get('replay') or {}).get('readiness', {}).get('status'),
        'blocking_requirements': item.get('blocking_requirements'),
        'n1_triggers': (item.get('runtime_requirement') or {}).get('n1_triggers', [])[:5],
    }


def build_verification_panel(cards: List[Dict[str, Any]], manifest: Dict[str, Any]) -> Dict[str, Any]:
    items = [detect_card_requirements(c) for c in cards]
    card_by_id = {c['card_id']: c for c in cards}
    item_by_id = {i['card_id']: i for i in items}

    profiles = [
        _verification_profile(card_by_id[i['card_id']], classify_runtime_requirement(card_by_id[i['card_id']]), i)
        for i in items
    ]

    operations = [c for c in cards if (c.get('provenance') or {}).get('card_kind') == 'operation']
    op_items = [i for i in items if card_by_id[i['card_id']] in operations]

    level_dist = Counter((i.get('runtime_requirement') or {}).get('level') for i in items)
    op_level_dist = Counter((i.get('runtime_requirement') or {}).get('level') for i in op_items)

    n1_blocker = Counter()
    for item in op_items:
        if (item.get('runtime_requirement') or {}).get('level') != N1_LEVEL:
            continue
        for b in item.get('blocking_requirements') or []:
            n1_blocker[b] += 1

    n0_cards = sorted(
        [(card_by_id[i['card_id']], i) for i in op_items if (i.get('runtime_requirement') or {}).get('level') == N0_LEVEL],
        key=lambda x: (x[0].get('ranking') or {}).get('rank') or 9999,
    )
    n1_near = sorted(
        [(card_by_id[i['card_id']], i) for i in op_items if (i.get('runtime_requirement') or {}).get('level') == N1_LEVEL],
        key=lambda x: (
            0 if (x[0].get('replay') or {}).get('readiness', {}).get('status') == 'ready' else 1,
            len(x[1].get('blocking_requirements') or []),
            (x[0].get('ranking') or {}).get('rank') or 9999,
        ),
    )

    tier = Counter((c.get('ranking') or {}).get('priority_tier') for c in cards)
    anomalies = []
    for c in operations:
        r = c.get('ranking') or {}
        i = item_by_id.get(c['card_id'], {})
        if r.get('rank') == 1 and r.get('priority_tier') != 'P0':
            anomalies.append({'type': 'high_rank_low_validation', 'card_id': c['card_id'], 'note': f"rank=1 tier={r.get('priority_tier')}"})
        if (i.get('runtime_requirement') or {}).get('level') == N0_LEVEL and r.get('fuzzing_gate', {}).get('auto_fuzz_eligible'):
            anomalies.append({'type': 'n0_with_fuzz_gate_pass', 'card_id': c['card_id'], 'note': 'review N0 vs fuzzing_gate'})

    down = manifest.get('downstream_inventory') or {}
    funnel = manifest.get('readiness_inventory') or {}
    return {
        'schema_version': SCHEMA_VERSION,
        'pack_id': manifest.get('pack_id'),
        'generated_at': _utc_now(),
        'source': 'api_cards.json + account_aware_rule_erd',
        'funnel': {
            'total_cards': manifest.get('card_inventory', {}).get('total_cards'),
            'operation_cards': len(operations),
            'replay_ready': (funnel.get('by_status') or {}).get('ready'),
            'priority_p0': tier.get('P0', 0),
            'priority_p1': tier.get('P1', 0),
            'fuzzing_gate_pass': down.get('fuzzing_eligible'),
        },
        'runtime_requirement_distribution': dict(level_dist),
        'operation_runtime_requirement_distribution': dict(op_level_dist),
        'n0_static_replay_candidates': {
            'count': op_level_dist.get(N0_LEVEL, 0),
            'top_cards': [_card_brief(c, i) for c, i in n0_cards[:25]],
        },
        'n1_runtime_template_candidates': {
            'count': op_level_dist.get(N1_LEVEL, 0),
            'top_cards': [_card_brief(c, i) for c, i in n1_near[:25]],
        },
        'n1_blocker_distribution': dict(n1_blocker),
        'tier_distribution': dict(tier),
        'anomalies': anomalies[:20],
        'per_card_summary': profiles,
    }
