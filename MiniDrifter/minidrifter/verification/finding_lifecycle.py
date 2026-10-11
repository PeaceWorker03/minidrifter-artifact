# -*- coding: utf-8 -*-
"""Finding lifecycle — signal → hypothesis → confirmed / rejected / pruned."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from minidrifter.business_chain.schema import (
    CLAIM_BINDING_ENFORCED,
    CLAIM_REPLAY_SIGNAL,
    CLAIM_SENSITIVE_REPLAY_SIGNAL,
    CLAIM_SINGLE_ACCOUNT_BINDING_INCONSISTENCY,
    CLAIM_SINGLE_ACCOUNT_HIGH_CONFIDENCE,
    SCHEMA_VERSION,
    VERIFICATION_SCOPE_SINGLE_ACCOUNT,
)
from minidrifter.verification.finding_classifier import FINDING_F1

VALID_STATUSES = frozenset({'signal', 'hypothesis', 'confirmed', 'rejected', 'pruned'})


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _status_event(status: str, reason: str) -> Dict[str, Any]:
    return {'status': status, 'reason': reason, 'at': _utc_now()}


class FindingRegistry:
    """Track findings across a search session with lifecycle transitions."""

    def __init__(self) -> None:
        self._findings: Dict[str, Dict[str, Any]] = {}
        self._by_dedupe_key: Dict[str, str] = {}

    def ingest(self, findings: List[Dict[str, Any]]) -> None:
        for f in findings:
            fid = f.get('finding_id')
            if not fid:
                continue
            dedupe = _dedupe_key(f)
            if dedupe in self._by_dedupe_key:
                existing_id = self._by_dedupe_key[dedupe]
                if existing_id == fid:
                    self._merge_finding(existing_id, f)
                    continue
                self._mark_pruned(fid, f, duplicate_of=existing_id)
                continue
            f.setdefault('status_history', [_status_event(f.get('status', 'hypothesis'), 'initial_adjudication')])
            self._findings[fid] = f
            self._by_dedupe_key[dedupe] = fid

    def _merge_finding(self, existing_id: str, incoming: Dict[str, Any]) -> None:
        """Re-ingest of same finding — merge evidence, never self-prune."""
        existing = self._findings.get(existing_id)
        if not existing:
            self._findings[existing_id] = incoming
            return
        for tid in incoming.get('evidence_test_ids') or []:
            ids = existing.setdefault('evidence_test_ids', [])
            if tid and tid not in ids:
                ids.append(tid)
        if incoming.get('binding_verdict'):
            existing['binding_verdict'] = incoming['binding_verdict']
        new_status = incoming.get('status')
        if new_status and new_status != existing.get('status'):
            if _status_rank(new_status) > _status_rank(existing.get('status') or 'signal'):
                self._transition(existing_id, new_status, 're_adjudication_merge')

    def _mark_pruned(self, fid: str, finding: Dict[str, Any], *, duplicate_of: str) -> None:
        if fid == duplicate_of:
            return
        finding['status'] = 'pruned'
        finding['pruned_as_duplicate_of'] = duplicate_of
        finding['status_history'] = [_status_event('pruned', f'duplicate_of:{duplicate_of}')]
        self._findings[fid] = finding

    def apply_lifecycle_rules(
        self,
        analyses: List[Dict[str, Any]],
        test_cases_by_id: Dict[str, Dict[str, Any]],
    ) -> None:
        """Promote or reject findings using M0 vs M7 differential on same API."""
        api_ids = {a.get('api_id') for a in analyses if a.get('api_id')}
        for api_id in api_ids:
            self.apply_lifecycle_for_api(api_id, analyses, test_cases_by_id)

    def apply_lifecycle_for_api(
        self,
        api_id: str,
        analyses: List[Dict[str, Any]],
        test_cases_by_id: Dict[str, Dict[str, Any]],
    ) -> None:
        """Incremental M0/M7 lifecycle for one API."""
        api_analyses = [a for a in analyses if a.get('api_id') == api_id]
        if not api_analyses:
            return
        m0 = [a for a in api_analyses if _mutation(a, test_cases_by_id) == 'M0_baseline_replay']
        m7 = [a for a in api_analyses if _mutation(a, test_cases_by_id).startswith('M7')]
        if not m0 or not m7:
            return

        m0_ok = any(a.get('call_outcome') == 'business_success' for a in m0)
        for fid, finding in list(self._findings.items()):
            if finding.get('status') in {'confirmed', 'rejected', 'pruned'}:
                continue
            if finding.get('api_id') != api_id:
                continue
            ftype = finding.get('finding_type') or ''
            verdict = finding.get('binding_verdict') or {}
            if verdict.get('verdict') == 'confirmed':
                finding.setdefault('verification_scope', VERIFICATION_SCOPE_SINGLE_ACCOUNT)
                finding.setdefault('claim_type', CLAIM_SINGLE_ACCOUNT_BINDING_INCONSISTENCY)
                finding.setdefault('requires_dual_account_confirmation', True)
                self._transition(fid, 'hypothesis', 'binding_drift_oracle_single_account')
                continue
            if verdict.get('verdict') == 'rejected':
                finding.setdefault('claim_type', CLAIM_BINDING_ENFORCED)
                self._transition(fid, 'rejected', 'binding_drift_oracle_rejected')
                continue
            if ftype in {'binding_anomaly_hypothesis', 'subject_object_binding_mismatch', 'mutation_accepted_by_server',
                         'single_api_weak_binding', 'chain_consumer_binding_drift', 'capability_consumer_binding_drift'}:
                finding.setdefault('verification_scope', VERIFICATION_SCOPE_SINGLE_ACCOUNT)
                finding.setdefault('requires_dual_account_confirmation', True)
                if finding.get('finding_tier') == FINDING_F1 or finding.get('finding_type') == 'single_api_weak_binding':
                    if _has_confirmed_binding_signal(m7) and m0_ok:
                        finding['claim_type'] = CLAIM_SINGLE_ACCOUNT_BINDING_INCONSISTENCY
                        self._transition(fid, 'hypothesis', 'f1_single_api_weak_binding_auxiliary')
                    continue
                if _has_confirmed_binding_signal(m7) and m0_ok and _m7_business_success_with_data(m7):
                    finding['claim_type'] = CLAIM_SINGLE_ACCOUNT_HIGH_CONFIDENCE
                    self._transition(fid, 'hypothesis', 'single_account_high_confidence_binding')
                elif _has_confirmed_binding_signal(m7) and m0_ok:
                    finding['claim_type'] = CLAIM_SINGLE_ACCOUNT_BINDING_INCONSISTENCY
                    self._transition(fid, 'hypothesis', 'single_account_binding_inconsistency')
                elif m0_ok and _m7_properly_rejected(m7):
                    finding['claim_type'] = CLAIM_BINDING_ENFORCED
                    self._transition(fid, 'rejected', 'm7_rejected_while_m0_success')
                elif not m0_ok:
                    self._transition(fid, 'rejected', 'baseline_not_successful')
                elif finding.get('status') == 'signal':
                    finding['claim_type'] = CLAIM_REPLAY_SIGNAL
                    self._transition(fid, 'hypothesis', 'm0_m7_pair_available')

    def _transition(self, finding_id: str, new_status: str, reason: str) -> None:
        if new_status not in VALID_STATUSES:
            return
        f = self._findings.get(finding_id)
        if not f or f.get('status') == new_status:
            return
        if _status_rank(new_status) <= _status_rank(f.get('status') or 'signal') and new_status != 'rejected':
            return
        f['status'] = new_status
        f['confidence'] = 'high' if new_status == 'confirmed' else (
            'low' if new_status == 'rejected' else f.get('confidence', 'medium')
        )
        f.setdefault('status_history', []).append(_status_event(new_status, reason))
        f['lifecycle_reason'] = reason

    def all_findings(self) -> List[Dict[str, Any]]:
        return list(self._findings.values())

    def active_findings(self) -> List[Dict[str, Any]]:
        return [f for f in self._findings.values() if f.get('status') not in {'pruned', 'rejected'}]

    def summary(self) -> Dict[str, Any]:
        counts: Dict[str, int] = {s: 0 for s in VALID_STATUSES}
        for f in self._findings.values():
            st = f.get('status') or 'hypothesis'
            counts[st] = counts.get(st, 0) + 1
        return {
            'total': len(self._findings),
            'by_status': counts,
            'confirmed': counts.get('confirmed', 0),
            'hypothesis': counts.get('hypothesis', 0),
            'signal': counts.get('signal', 0),
            'rejected': counts.get('rejected', 0),
            'pruned': counts.get('pruned', 0),
        }

    def to_document(self) -> Dict[str, Any]:
        return {
            'schema_version': SCHEMA_VERSION,
            'generated_at': _utc_now(),
            'summary': self.summary(),
            'findings': self.all_findings(),
        }


def _status_rank(status: str) -> int:
    return {'signal': 0, 'hypothesis': 1, 'confirmed': 2, 'rejected': 2, 'pruned': -1}.get(status, 0)


def _dedupe_key(finding: Dict[str, Any]) -> str:
    return '|'.join([
        finding.get('finding_type') or '',
        finding.get('api_id') or '',
        finding.get('chain_id') or '',
        finding.get('mutation_type') or '',
    ])


def _mutation(analysis: Dict[str, Any], tc_by_id: Dict[str, Dict[str, Any]]) -> str:
    tc = tc_by_id.get(analysis.get('test_id') or '') or {}
    return tc.get('mutation_type') or analysis.get('mutation_type') or 'M0_baseline_replay'


def _has_confirmed_binding_signal(m7_analyses: List[Dict[str, Any]]) -> bool:
    for a in m7_analyses:
        if 'subject_object_binding_mismatch' in (a.get('security_signals') or []):
            return True
        binding = (a.get('binding_observation') or {}).get('binding_status')
        if binding in {'subject_object_binding_mismatch', 'server_accepts_mutated_subject'}:
            return True
    return False


def _m7_business_success_with_data(m7_analyses: List[Dict[str, Any]]) -> bool:
    return any(
        a.get('call_outcome') == 'business_success' and (a.get('produced_fields') or [])
        for a in m7_analyses
    )


def _m7_properly_rejected(m7_analyses: List[Dict[str, Any]]) -> bool:
    for a in m7_analyses:
        if a.get('call_outcome') in {'business_success', 'transport_success'}:
            body_hint = a.get('produced_fields') or []
            if body_hint:
                return False
            if (a.get('binding_observation') or {}).get('binding_status') in {
                'subject_object_binding_mismatch', 'server_accepts_mutated_subject',
            }:
                return False
        if a.get('call_outcome') in {'auth_expired', 'validation_error', 'business_state_blocked'}:
            return True
        if a.get('call_outcome') == 'business_success' and not (a.get('produced_fields') or []):
            return True
    return bool(m7_analyses)
