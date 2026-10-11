# -*- coding: utf-8 -*-
"""Unified mutation eligibility matrix — when M7 may run and how to conclude."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from minidrifter.materials.intake_param_hints import normalize_api_path
from minidrifter.verification.safety_policy import evaluate_test_safety

# P0 capability layers (frozen semantics)
CAPABILITY_LAYERS = (
    'static_recovery',   # API / params / wrapper / chain — must
    'm0_replay',         # exact replay — must
    'm7_mutation',       # subject/object override — conditional
    'conclusion',        # drift / clean / inconclusive — must
)

ELIGIBILITY_MUTATION_ALLOWED = 'mutation_allowed'
ELIGIBILITY_SIGNATURE_BOUND = 'signature_bound_skip'
ELIGIBILITY_NO_SUBJECT = 'no_subject_candidate'
ELIGIBILITY_NO_OBJECT = 'missing_object_material'
ELIGIBILITY_SAFETY_GATE = 'safety_gate_skip'
ELIGIBILITY_CREDENTIAL_EXPIRED = 'credential_expired'
ELIGIBILITY_MISSING_MATERIAL = 'missing_material_skip'
ELIGIBILITY_M0_FAILED = 'm0_failed'
ELIGIBILITY_CREDENTIAL_READ_ONLY = 'credential_bound_read_only'

WRITE_PATH_RE = re.compile(
    r'(submit|pay|delete|remove|cancel|refund|transfer|withdraw|create|update|save|bind|unbind)',
    re.I,
)

M7_DRIFT_STATUSES = frozenset({
    'subject_override_accepted_sensitive',
    'cross_subject_sensitive_success',
    'object_override_accepted_sensitive',
})
M7_CLEAN_STATUSES = frozenset({
    'subject_override_accepted_no_sensitive',
    'subject_override_ignored',
    'subject_override_blocked',
    'backend_rejected_or_self_bound',
    'object_override_rejected',
})
M7_INCONCLUSIVE_STATUSES = frozenset({
    'subject_override_inconclusive',
    'subject_override_invalid_test',
    'm0_failed',
})


def _load_crypto_static_profile(
    pack_dir: Optional[Path] = None,
    baseline_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    if baseline_context:
        embedded = baseline_context.get('crypto_static_profile')
        if isinstance(embedded, dict) and embedded:
            return embedded
        if baseline_context.get('crypto_replay_ready') is True:
            return {'can_replay': True, 'source': 'baseline_context.crypto_replay_ready'}
    if pack_dir:
        path = Path(pack_dir) / 'crypto_static_profile.json'
        if path.exists():
            try:
                doc = json.loads(path.read_text(encoding='utf-8'))
                return doc if isinstance(doc, dict) else {}
            except json.JSONDecodeError:
                pass
    return {}


def can_recompute_or_replay_signature(
    replay_context: Dict[str, Any],
    signature_profile: Optional[Dict[str, Any]] = None,
    baseline_context: Optional[Dict[str, Any]] = None,
    pack_dir: Optional[Path] = None,
) -> bool:
    """Three-layer fallback: replay context → signature profile → crypto_static_profile."""
    if replay_context.get('can_recompute_signature') is True:
        return True
    if replay_context.get('can_replay') is True:
        return True
    if replay_context.get('signature_mode') in {'recompute', 'crypto_materialize'}:
        return True
    if replay_context.get('mutation_policy') == 'crypto_materialize':
        return True

    if signature_profile and signature_profile.get('can_recompute_signature') is True:
        return True
    if signature_profile and signature_profile.get('can_replay') is True:
        return True

    crypto = _load_crypto_static_profile(pack_dir, baseline_context)
    if crypto.get('can_replay') is True:
        return True

    proc = replay_context.get('crypto_processing') or {}
    if proc.get('can_replay') is True and proc.get('sign_check'):
        return True

    return False


def _has_signature_on_wire(replay_context: Dict[str, Any], wire_row: Optional[Dict[str, Any]]) -> bool:
    if replay_context.get('signature_mode') == 'reuse_capture_signature':
        return True
    for layer in replay_context.get('field_layers') or []:
        if str(layer.get('name') or '').lower() in {'signature', 'sign'}:
            return True
    if wire_row:
        for f in wire_row.get('wire_subject_fields') or []:
            if f.get('signature_covered') is True:
                return True
    query = replay_context.get('query_params') or replay_context.get('query') or {}
    body = replay_context.get('body_params') or replay_context.get('body') or {}
    headers = replay_context.get('headers') or {}
    for key in list(query.keys()) + list(body.keys()) + list(headers.keys()):
        if str(key).lower() in {'signature', 'sign'}:
            return True
    return False



def _m0_auth_expired(m0_result: Optional[Dict[str, Any]]) -> bool:
    if not m0_result:
        return False
    outcome = str(m0_result.get('call_outcome') or m0_result.get('status') or '')
    if outcome in {'auth_expired', 'auth_required'}:
        return True
    for code in m0_result.get('reason_codes') or []:
        if 'auth' in str(code).lower() or 'expired' in str(code).lower():
            return True
    return False


def _m0_success(m0_result: Optional[Dict[str, Any]]) -> bool:
    if not m0_result:
        return False
    if m0_result.get('ok') is True:
        return True
    st = str(m0_result.get('status') or m0_result.get('replay_strategy') or '')
    if 'success' in st.lower() or st in {'live_m0_success', 'baseline_m0_success'}:
        return True
    return str(m0_result.get('call_outcome') or '') in {'ok', 'business_success'}


def _subject_fields(wire_row: Optional[Dict[str, Any]]) -> List[str]:
    if not wire_row:
        return []
    out: List[str] = []
    for f in wire_row.get('wire_subject_fields') or []:
        if f.get('mutation_allowed') is False:
            continue
        name = f.get('field')
        if name:
            out.append(str(name))
    return out


def _object_fields(object_row: Optional[Dict[str, Any]]) -> List[str]:
    if not object_row:
        return []
    return [str(f.get('field')) for f in object_row.get('wire_object_fields') or [] if f.get('field')]


def evaluate_mutation_eligibility(
    *,
    api: str,
    mutation_type: str,
    replay_context: Optional[Dict[str, Any]] = None,
    signature_profile: Optional[Dict[str, Any]] = None,
    subject_wire_row: Optional[Dict[str, Any]] = None,
    object_wire_row: Optional[Dict[str, Any]] = None,
    m0_result: Optional[Dict[str, Any]] = None,
    test_case: Optional[Dict[str, Any]] = None,
    baseline_context: Optional[Dict[str, Any]] = None,
    pack_dir: Optional[Path] = None,
    mode: str = 'dry-run',
    campaign_role: Optional[str] = None,
) -> Dict[str, Any]:
    """Return eligibility row for one API × mutation_type."""
    replay_context = replay_context or {}
    path = normalize_api_path(api)
    mutation_type = mutation_type or 'subject_override'

    if mutation_type == 'credential_bound_read':
        eligible = False
        status = ELIGIBILITY_CREDENTIAL_READ_ONLY
        conclusion = 'clean' if _m0_success(m0_result) else 'not_tested'
        reason = 'credential_bound_read_no_mutation'
        if _m0_auth_expired(m0_result):
            status = ELIGIBILITY_CREDENTIAL_EXPIRED
            conclusion = 'inconclusive'
            reason = 'credential_expired'
        return _row(
            api=path, mutation_type=mutation_type, eligible=eligible,
            eligibility_status=status, security_conclusion=conclusion, reason=reason,
            subject_candidates=_subject_fields(subject_wire_row),
            object_candidates=_object_fields(object_wire_row),
        )

    if test_case and baseline_context is not None:
        safety = evaluate_test_safety(
            test_case, baseline_context=baseline_context, mode=mode,
        )
        if not safety.allowed:
            return _row(
                api=path, mutation_type=mutation_type, eligible=False,
                eligibility_status=ELIGIBILITY_SAFETY_GATE,
                security_conclusion='not_tested',
                reason=';'.join(safety.reasons) or 'safety_gate_skip',
                subject_candidates=_subject_fields(subject_wire_row),
                object_candidates=_object_fields(object_wire_row),
            )

    if WRITE_PATH_RE.search(path) and mutation_type in {'subject_override', 'object_override'}:
        return _row(
            api=path, mutation_type=mutation_type, eligible=False,
            eligibility_status=ELIGIBILITY_SAFETY_GATE,
            security_conclusion='not_tested',
            reason='state_changing_path_default_dry_run',
            subject_candidates=_subject_fields(subject_wire_row),
            object_candidates=_object_fields(object_wire_row),
        )

    if _m0_auth_expired(m0_result):
        return _row(
            api=path, mutation_type=mutation_type, eligible=False,
            eligibility_status=ELIGIBILITY_CREDENTIAL_EXPIRED,
            security_conclusion='inconclusive',
            reason='credential_expired',
            subject_candidates=_subject_fields(subject_wire_row),
            object_candidates=_object_fields(object_wire_row),
        )

    if m0_result is not None and not _m0_success(m0_result):
        return _row(
            api=path, mutation_type=mutation_type, eligible=False,
            eligibility_status=ELIGIBILITY_M0_FAILED,
            security_conclusion='not_tested',
            reason=str(m0_result.get('reason') or m0_result.get('status') or 'm0_failed'),
            subject_candidates=_subject_fields(subject_wire_row),
            object_candidates=_object_fields(object_wire_row),
        )

    has_sig = _has_signature_on_wire(replay_context, subject_wire_row)
    can_recompute = can_recompute_or_replay_signature(
        replay_context,
        signature_profile,
        baseline_context,
        pack_dir=pack_dir,
    )
    if has_sig and not can_recompute:
        return _row(
            api=path, mutation_type=mutation_type, eligible=False,
            eligibility_status=ELIGIBILITY_SIGNATURE_BOUND,
            security_conclusion='inconclusive',
            reason='signature_not_recomputable',
            subject_candidates=_subject_fields(subject_wire_row),
            object_candidates=_object_fields(object_wire_row),
        )

    if mutation_type == 'subject_override':
        subjects = _subject_fields(subject_wire_row)
        if not subjects:
            return _row(
                api=path, mutation_type=mutation_type, eligible=False,
                eligibility_status=ELIGIBILITY_NO_SUBJECT,
                security_conclusion='not_tested',
                reason='no_wire_subject_field',
                subject_candidates=[], object_candidates=_object_fields(object_wire_row),
            )

    if mutation_type == 'object_override':
        objects = _object_fields(object_wire_row)
        if not objects:
            return _row(
                api=path, mutation_type=mutation_type, eligible=False,
                eligibility_status=ELIGIBILITY_NO_OBJECT,
                security_conclusion='not_tested',
                reason='missing_object_material',
                subject_candidates=_subject_fields(subject_wire_row),
                object_candidates=[],
            )

    return _row(
        api=path, mutation_type=mutation_type, eligible=True,
        eligibility_status=ELIGIBILITY_MUTATION_ALLOWED,
        security_conclusion='not_tested',
        reason='mutation_allowed',
        subject_candidates=_subject_fields(subject_wire_row),
        object_candidates=_object_fields(object_wire_row),
    )


def security_conclusion_from_m7(
    *,
    eligibility: Dict[str, Any],
    m7_status: Optional[str],
    oracle_result: Optional[str] = None,
) -> str:
    """Map executed M7 outcome to drift / clean / inconclusive."""
    if not m7_status or m7_status in {
        'not_executed', 'dry_run_planned', 'dry_run_planned_signature_bound',
        'skipped_signature_bound', 'subject_override_skipped', 'no_wire_subject_field',
    }:
        return str(eligibility.get('security_conclusion') or 'not_tested')

    status = oracle_result or m7_status
    if status in M7_DRIFT_STATUSES:
        return 'drift'
    if status in M7_CLEAN_STATUSES:
        return 'clean'
    if status in M7_INCONCLUSIVE_STATUSES:
        return 'inconclusive'
    if eligibility.get('eligibility_status') == ELIGIBILITY_SIGNATURE_BOUND:
        return 'inconclusive'
    return 'inconclusive'


def _row(
    *,
    api: str,
    mutation_type: str,
    eligible: bool,
    eligibility_status: str,
    security_conclusion: str,
    reason: str,
    subject_candidates: List[str],
    object_candidates: List[str],
) -> Dict[str, Any]:
    return {
        'api': api,
        'mutation_type': mutation_type,
        'eligible': eligible,
        'eligibility_status': eligibility_status,
        'security_conclusion': security_conclusion,
        'reason': reason,
        'subject_candidates': subject_candidates,
        'object_candidates': object_candidates,
    }
