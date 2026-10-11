# -*- coding: utf-8 -*-
"""P4-fix-5 — classify subject override M0/M7-subject outcomes."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from minidrifter.verification.binding_diff_exporter import (
    _credential_snapshot,
    _request_diff,
)
from minidrifter.verification.chain_strict_runner import HOP_STATUS_OK
from minidrifter.verification.sensitive_api_oracle import analyze_sensitive_response

BLOCKED_OUTCOMES = frozenset({
    'auth_required', 'auth_expired', 'binding_rejected', 'validation_error',
    'business_state_blocked', 'rate_limited', 'server_error', 'transport_error',
    'build_failed',
})


def _subject_values(body: Any, field: str) -> List[str]:
    if not isinstance(body, dict) or not field:
        return []
    vals: List[str] = []
    target = field.lower().replace('_', '')
    for k, v in body.items():
        kn = str(k).lower().replace('_', '')
        if kn == target and v not in (None, ''):
            vals.append(str(v))
    return vals


def classify_subject_override(
    *,
    path: str,
    subject_field: str,
    m0_test_case: Dict[str, Any],
    m7_test_case: Dict[str, Any],
    m0_execution: Dict[str, Any],
    m7_execution: Dict[str, Any],
    m0_analysis: Dict[str, Any],
    m7_analysis: Dict[str, Any],
    mutation_plan: Dict[str, Any],
    oracle_plan: Optional[Dict[str, Any]] = None,
    crypto_preflight: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Classify subject override result — separate from F2 binding drift."""
    req_diff = _request_diff(
        m0_test_case, m7_test_case, m0_execution, m7_execution, anchor_field=subject_field,
    )
    wire_changed = list(req_diff.get('changed_fields') or [])
    m0_params = req_diff.get('m0_request_params') or {}
    m7_params = req_diff.get('m7_request_params') or {}
    anchor_norm = subject_field.lower().replace('_', '')
    m0_anchor = m7_anchor = None
    for k, v in m0_params.items():
        if str(k).lower().replace('_', '') == anchor_norm:
            m0_anchor = v
    for k, v in m7_params.items():
        if str(k).lower().replace('_', '') == anchor_norm:
            m7_anchor = v
    # Accept inject (absent→present) and replace mutations on the subject anchor.
    anchor_changed = str(m0_anchor or '') != str(m7_anchor or '')
    cred_m0 = _credential_snapshot(m0_test_case, m0_execution)
    cred_m7 = _credential_snapshot(m7_test_case, m7_execution)
    credential_same = cred_m0.get('uid') == cred_m7.get('uid') and (
        cred_m0.get('credential_params_redacted') == cred_m7.get('credential_params_redacted')
    )

    m0_ok = (m0_analysis or {}).get('call_outcome') == HOP_STATUS_OK
    m7_outcome = (m7_analysis or {}).get('call_outcome')
    m7_ok = m7_outcome == HOP_STATUS_OK

    m0_body = (m0_execution or {}).get('body_json')
    m7_body = (m7_execution or {}).get('body_json')
    m0_sens = analyze_sensitive_response(path=path, body=m0_body)
    m7_sens = analyze_sensitive_response(path=path, body=m7_body)

    m0_subjects = _subject_values(m0_body, subject_field)
    m7_subjects = _subject_values(m7_body, subject_field)

    reason_codes: List[str] = []

    oracle_cfg = oracle_plan or {}
    use_fp = oracle_cfg.get('type') == 'sensitive_content_fingerprint' or bool(oracle_cfg.get('fields'))
    fp_fields = oracle_cfg.get('fields') or None
    content_fp_drift = False
    invalid_mutant_empty = False
    if use_fp:
        from minidrifter.verification.cats.content_fingerprint import (
            fingerprints_differ,
            m7_empty_but_m0_has_pii,
        )
        invalid_mutant_empty = m7_empty_but_m0_has_pii(m0_body, m7_body, fields=fp_fields)
        content_fp_drift = fingerprints_differ(m0_body, m7_body, fields=fp_fields)
        reason_codes.append('content_fingerprint_checked')
        if invalid_mutant_empty:
            reason_codes.append('invalid_mutant_no_evidence')
        if content_fp_drift:
            reason_codes.append('sensitive_fingerprint_changed')

    if anchor_changed:
        reason_codes.append('subject_anchor_mutated_on_wire')
    else:
        reason_codes.append('subject_anchor_not_mutated_on_wire')

    if not anchor_changed or not wire_changed:
        status = 'subject_override_invalid_test'
        evidence_grade = 'C_invalid'
        reason_codes.append('invalid_wire_mutation')
    elif not credential_same:
        status = 'subject_override_invalid_test'
        evidence_grade = 'C_invalid'
        reason_codes.append('credential_anchor_changed')
    elif invalid_mutant_empty and oracle_cfg.get('empty_response_policy') == 'invalid_mutant_no_evidence':
        status = 'subject_override_inconclusive'
        evidence_grade = 'C_inconclusive'
        reason_codes.append('invalid_mutant_not_clean')
    elif content_fp_drift and anchor_changed and credential_same and (
        m7_ok or m7_sens.get('has_sensitive')
    ):
        status = 'subject_override_accepted_sensitive'
        evidence_grade = 'A_candidate'
        reason_codes.append('drift_sensitive_content_changed_no_echo')
    elif crypto_preflight and not crypto_preflight.get('ok'):
        status = 'subject_override_inconclusive'
        evidence_grade = 'C_inconclusive'
        reason_codes.append('crypto_parity_failed')
    elif m7_outcome in BLOCKED_OUTCOMES or not m7_ok:
        status = 'subject_override_blocked'
        evidence_grade = 'B_clean'
        reason_codes.append('server_blocked_mutated_subject')
    elif m7_ok and m7_sens.get('has_sensitive'):
        if m0_subjects and m7_subjects and m0_subjects != m7_subjects:
            status = 'subject_override_accepted_sensitive'
            evidence_grade = 'A_candidate'
            reason_codes.append('response_subject_differs_from_m0')
        elif m0_sens.get('has_sensitive') and m7_sens.get('has_sensitive'):
            status = 'subject_override_ignored'
            evidence_grade = 'B_clean'
            reason_codes.append('server_returned_sensitive_despite_subject_mutation')
        else:
            status = 'subject_override_accepted_sensitive'
            evidence_grade = 'A_weak'
            reason_codes.append('m7_sensitive_without_subject_diff')
    elif m7_ok and m0_ok:
        # Preliminary drift: subject mutated on wire, credential held, server accepted M7.
        status = 'subject_override_accepted_sensitive'
        evidence_grade = 'A_preliminary'
        reason_codes.append('subject_mutation_accepted_on_business_success')
    elif m7_ok:
        status = 'subject_override_inconclusive'
        evidence_grade = 'C_inconclusive'
        reason_codes.append('m7_success_without_m0_baseline')
    else:
        status = 'subject_override_inconclusive'
        evidence_grade = 'C_inconclusive'
        reason_codes.append('inconclusive_response')

    high_risk = (
        anchor_changed
        and credential_same
        and m0_ok
        and (m7_ok or m7_sens.get('has_sensitive'))
        and status == 'subject_override_accepted_sensitive'
    )

    return {
        'status': status,
        'evidence_grade': evidence_grade,
        'high_risk_candidate': high_risk,
        'wire_changed_fields': wire_changed,
        'anchor_mutated_on_wire': anchor_changed,
        'credential_anchor_same': credential_same,
        'm0_sensitive_read': bool(m0_sens.get('has_sensitive')),
        'm7_sensitive_read': bool(m7_sens.get('has_sensitive')),
        'm0_subject_values': m0_subjects[:3],
        'm7_subject_values': m7_subjects[:3],
        'm0_outcome': m0_analysis.get('call_outcome'),
        'm7_outcome': m7_outcome,
        'mutation_strategy': mutation_plan.get('strategy'),
        'reason_codes': reason_codes,
        'request_diff': req_diff,
    }


def summarize_subject_override_batch(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    counts = {
        'targets_detected': 0,
        'attempted': 0,
        'wire_mutation_valid': 0,
        'blocked': 0,
        'ignored': 0,
        'accepted_no_sensitive': 0,
        'accepted_sensitive': 0,
        'invalid_test': 0,
        'inconclusive': 0,
        'skipped_signature_bound': 0,
        'subject_override_attempted': 0,
        'subject_override_inconclusive': 0,
        'findings': 0,
        'skipped_no_wire_subject': 0,
    }
    for row in results:
        counts['attempted'] += 1
        if row.get('subject_override_attempted'):
            counts['subject_override_attempted'] += 1
        if row.get('subject_override_inconclusive'):
            counts['subject_override_inconclusive'] += 1
        st = row.get('subject_override_status') or ''
        if st == 'subject_override_skipped' or row.get('status') == 'no_wire_subject_field':
            counts['skipped_no_wire_subject'] += 1
        elif st == 'skipped_signature_bound':
            counts['skipped_signature_bound'] += 1
            counts['inconclusive'] += 1
        elif st == 'subject_override_blocked':
            counts['blocked'] += 1
        elif st == 'subject_override_ignored':
            counts['ignored'] += 1
        elif st == 'subject_override_accepted_no_sensitive':
            counts['accepted_no_sensitive'] += 1
        elif st == 'subject_override_accepted_sensitive':
            counts['accepted_sensitive'] += 1
        elif st == 'subject_override_invalid_test':
            counts['invalid_test'] += 1
        elif st == 'subject_override_inconclusive':
            counts['inconclusive'] += 1
        if row.get('wire_mutation_valid'):
            counts['wire_mutation_valid'] += 1
        if row.get('high_risk_candidate'):
            counts['findings'] += 1
    return counts
