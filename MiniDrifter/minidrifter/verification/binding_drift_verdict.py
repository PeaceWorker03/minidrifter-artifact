# -*- coding: utf-8 -*-
"""Final oracle for identity/credential binding drift — rule-only, LLM cannot confirm."""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Set

VERDICT_CONFIRMED = 'confirmed'
VERDICT_LIKELY = 'likely'
VERDICT_HYPOTHESIS = 'hypothesis'
VERDICT_SIGNAL = 'signal'
VERDICT_REJECTED = 'rejected'

SUBJECT_FIELDS = frozenset({
    'userid', 'user_id', 'openid', 'customerid', 'logincustomerid',
    'memberid', 'platformuserid', 'fromcustomerid',
})
OBJECT_FIELDS = frozenset({
    'orderid', 'order_id', 'deviceid', 'vehicleid', 'invoiceid', 'cardid',
    'taskid', 'couponid', 'addressid', 'memberid', 'paymentid', 'deptid',
})


def _all_request_params(test_case: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for bag in (test_case.get('params'), test_case.get('body_params'), test_case.get('query_params')):
        if isinstance(bag, dict):
            out.update(bag)
    return out


def _baseline_value(baseline_context: Optional[Dict[str, Any]], field: str) -> Optional[Any]:
    baseline = (baseline_context or {}).get('resolved_fields') or {}
    base = baseline.get(field)
    if base is None:
        for bk, bv in baseline.items():
            if str(bk).lower() == str(field).lower():
                base = bv
                break
    if isinstance(base, dict):
        return base.get('value')
    return base


def _mutated_subject_fields(
    test_case: Dict[str, Any],
    baseline_context: Optional[Dict[str, Any]] = None,
) -> List[str]:
    mut = test_case.get('mutation_type') or ''
    if not mut.startswith('M7'):
        return []
    params = _all_request_params(test_case)
    out: List[str] = []
    anchor_fields = set(SUBJECT_FIELDS | OBJECT_FIELDS)
    target = test_case.get('target_field')
    if target:
        anchor_fields.add(str(target).lower().replace('_', ''))

    for key, val in params.items():
        kl = str(key).lower().replace('_', '')
        if kl not in anchor_fields and not kl.endswith('id'):
            continue
        base = _baseline_value(baseline_context, key)
        if base is not None and str(val) != str(base):
            out.append(key)
    return out


def assess_binding_drift(
    analysis: Dict[str, Any],
    test_case: Dict[str, Any],
    *,
    baseline_context: Optional[Dict[str, Any]] = None,
    m0_analysis: Optional[Dict[str, Any]] = None,
    m7_analysis: Optional[Dict[str, Any]] = None,
    pair: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Return tiered verdict + reason codes for one hop or M0/M7 pair."""
    signals = list(analysis.get('security_signals') or [])
    suspicious = list((analysis.get('signals') or {}).get('suspicious') or [])
    binding = (analysis.get('binding_observation') or {}).get('binding_status') or 'unknown'
    outcome = analysis.get('call_outcome') or 'unknown'
    mut = test_case.get('mutation_type') or ''
    mutated = _mutated_subject_fields(test_case, baseline_context)
    reasons: List[str] = []
    checks_passed = 0
    checks_total = 5

    from minidrifter.verification.mutation_profiles import is_environment_mutation_field
    target_field = test_case.get('target_field')
    if mut.startswith('M7') and is_environment_mutation_field(target_field):
        if outcome == 'business_success':
            return _verdict(VERDICT_SIGNAL, ['environment_mutation_accepted'], checks_passed=1, checks_total=checks_total)
        if outcome in {'business_state_blocked', 'validation_error', 'binding_rejected'}:
            return _verdict(VERDICT_REJECTED, ['environment_mutation_blocked'], checks_passed=1, checks_total=checks_total)
        return _verdict(VERDICT_SIGNAL, ['environment_consistency_probe'], checks_passed=0, checks_total=checks_total)

    if mut.startswith('M7') and target_field and not mutated:
        return _verdict(VERDICT_REJECTED, ['wire_mutation_not_applied'], checks_passed=0, checks_total=checks_total)

    m0_out = (m0_analysis or {}).get('call_outcome') or (pair or {}).get('m0_outcome')
    m7_out = (m7_analysis or analysis).get('call_outcome') if mut.startswith('M7') else (pair or {}).get('m7_outcome')
    drift_score = float((pair or {}).get('binding_drift_score') or 0)

    if outcome == 'auth_expired' and mut.startswith('M7'):
        return _verdict(VERDICT_REJECTED, ['m7_auth_expired_not_drift'], checks_passed=0, checks_total=checks_total)

    if binding == 'subject_object_binding_mismatch' or 'subject_object_binding_mismatch' in signals:
        reasons.append('explicit_binding_mismatch')
        checks_passed += 1

    if binding == 'server_accepts_mutated_subject':
        reasons.append('server_echoes_mutated_subject')
        checks_passed += 1

    if mut.startswith('M7') and outcome == 'business_success' and mutated:
        reasons.append('m7_success_with_credential_mutation')
        checks_passed += 1

    if analysis.get('produced_fields'):
        reasons.append('sensitive_data_returned')
        checks_passed += 1

    if m0_out == 'business_success' and m7_out == 'business_success' and (mutated or drift_score >= 0.6):
        if 'm0_m7_dual_success_under_mutation' not in reasons:
            reasons.append('m0_m7_dual_success_under_mutation')
            checks_passed += 1

    if m0_out == 'business_success' and m7_out in {'auth_expired', 'validation_error', 'business_state_blocked', 'binding_rejected'}:
        return _verdict(VERDICT_REJECTED, ['m7_properly_rejected'], checks_passed=checks_passed, checks_total=checks_total)

    if mut.startswith('M8') and outcome == 'business_success':
        reasons.append('credential_guard_not_enforced')
        checks_passed += 1
        if checks_passed >= 2:
            return _verdict(VERDICT_SIGNAL, reasons, checks_passed, checks_total)

    if 'credential_guard_bypass' in signals or 'signature_not_enforced' in signals:
        reasons.append('signature_or_replay_guard_weak')
        checks_passed += 1

    if 'binding_anomaly' in suspicious or binding in {
        'subject_object_binding_mismatch', 'server_accepts_mutated_subject',
    }:
        if checks_passed >= 4:
            return _verdict(VERDICT_CONFIRMED, reasons, checks_passed, checks_total)
        if checks_passed >= 3 or drift_score >= 0.6:
            return _verdict(VERDICT_LIKELY, reasons, checks_passed, checks_total)
        if checks_passed >= 2 or (pair and drift_score >= 0.3):
            return _verdict(VERDICT_HYPOTHESIS, reasons, checks_passed, checks_total)
        return _verdict(VERDICT_SIGNAL, reasons, checks_passed, checks_total)

    if mut.startswith('M7') and outcome == 'business_success':
        if not mutated and test_case.get('target_field'):
            reasons.append('environment_or_non_anchor_mutation')
        if m0_out and m7_out == 'business_success' and not m0_out:
            reasons.append('missing_m0_pair')
        elif m0_out != 'business_success' and mut.startswith('M7'):
            reasons.append('missing_m0_baseline_success')
        if mutated and m0_out == 'business_success' and m7_out == 'business_success':
            if checks_passed >= 4:
                return _verdict(VERDICT_CONFIRMED, reasons, checks_passed, checks_total)
            if checks_passed >= 3:
                return _verdict(VERDICT_LIKELY, reasons, checks_passed, checks_total)
            return _verdict(VERDICT_HYPOTHESIS, reasons or ['mutation_bypass_needs_pair'], checks_passed, checks_total)
        if analysis.get('produced_fields'):
            return _verdict(
                VERDICT_HYPOTHESIS,
                reasons or ['mutation_bypass_needs_pair'],
                checks_passed,
                checks_total,
            )

    return _verdict(VERDICT_SIGNAL, reasons or ['insufficient_binding_evidence'], checks_passed, checks_total)


def verdict_to_finding_status(verdict: str) -> str:
    """Map oracle verdict → finding_registry status."""
    return {
        VERDICT_CONFIRMED: 'confirmed',
        VERDICT_LIKELY: 'hypothesis',
        VERDICT_HYPOTHESIS: 'hypothesis',
        VERDICT_SIGNAL: 'signal',
        VERDICT_REJECTED: 'rejected',
    }.get(verdict, 'signal')


def _verdict(
    tier: str,
    reasons: List[str],
    checks_passed: int,
    checks_total: int,
) -> Dict[str, Any]:
    return {
        'verdict': tier,
        'reason_codes': reasons,
        'checks_passed': checks_passed,
        'checks_total': checks_total,
        'oracle': 'binding_drift_verdict',
    }
