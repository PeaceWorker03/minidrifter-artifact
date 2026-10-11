# -*- coding: utf-8
"""Per-API / path-family guard beliefs — learned from progressive credential probes."""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Set

from minidrifter.verification.transport_family_tracker import path_family

SIGNATURE_FIELDS = frozenset({'signature', 'sign'})
NONCE_FIELDS = frozenset({'nonce', 'random', 'randomstr'})
TIMESTAMP_FIELDS = frozenset({'timestamp', 'timespan', 'time'})
TOKEN_FIELDS = frozenset({'apitoken', 'api_token', 'logincustomertoken', 'customertoken', 'token'})

GUARD_STRICT = 'strict'
GUARD_IGNORED = 'ignored'
GUARD_UNKNOWN = 'unknown'
BINDING_ENFORCED = 'enforced'
BINDING_LOOSE = 'loose'
BINDING_UNKNOWN = 'unknown'


def _norm_field(name: str) -> str:
    return str(name or '').lower().replace('_', '')


def classify_guard_field(name: str) -> Optional[str]:
    nl = _norm_field(name)
    if nl in SIGNATURE_FIELDS or 'signature' in nl:
        return 'signature'
    if nl in NONCE_FIELDS:
        return 'nonce'
    if nl in TIMESTAMP_FIELDS:
        return 'timestamp'
    if nl in TOKEN_FIELDS or nl.endswith('token'):
        return 'token'
    return None


class ApiGuardBeliefs:
    """Accumulates probe outcomes; drives early-stop for credential + identity tests."""

    def __init__(self) -> None:
        self.by_api: Dict[str, Dict[str, Any]] = {}
        self.by_family: Dict[str, Dict[str, Any]] = {}
        self.probe_log: List[Dict[str, Any]] = []

    def _api_key(self, api_id: str, path: str) -> str:
        return api_id or path or 'unknown'

    def _family_key(self, path: str) -> str:
        return path_family(path)

    def _ensure_api(self, api_id: str, path: str) -> Dict[str, Any]:
        key = self._api_key(api_id, path)
        if key not in self.by_api:
            self.by_api[key] = {
                'api_id': api_id,
                'path': path,
                'family': self._family_key(path),
                'signature_guard': GUARD_UNKNOWN,
                'nonce_guard': GUARD_UNKNOWN,
                'timestamp_guard': GUARD_UNKNOWN,
                'token_guard': GUARD_UNKNOWN,
                'identity_binding': BINDING_UNKNOWN,
                'rejected_identity_fields': [],
                'credential_bypass_signals': [],
                'probes_run': 0,
            }
        return self.by_api[key]

    def _ensure_family(self, path: str) -> Dict[str, Any]:
        fam = self._family_key(path)
        if fam not in self.by_family:
            self.by_family[fam] = {
                'family': fam,
                'signature_guard': GUARD_UNKNOWN,
                'identity_binding': BINDING_UNKNOWN,
                'sample_path': path,
            }
        return self.by_family[fam]

    def record_probe(
        self,
        *,
        api_id: str,
        path: str,
        mutation_type: str,
        target_field: Optional[str],
        outcome: str,
        failure_class: Optional[str] = None,
        guard_kind: Optional[str] = None,
        detail: Optional[str] = None,
    ) -> Dict[str, Any]:
        rec = self._ensure_api(api_id, path)
        fam = self._ensure_family(path)
        rec['probes_run'] = int(rec.get('probes_run') or 0) + 1

        entry = {
            'api_id': api_id,
            'path': path,
            'mutation_type': mutation_type,
            'target_field': target_field,
            'outcome': outcome,
            'failure_class': failure_class,
            'guard_kind': guard_kind,
            'detail': detail,
        }
        self.probe_log.append(entry)

        success = outcome == 'business_success'
        mut = mutation_type or ''

        if mut.startswith('M8') or guard_kind:
            gk = guard_kind or classify_guard_field(target_field or '')
            if gk == 'signature':
                rec['signature_guard'] = GUARD_IGNORED if success else GUARD_STRICT
                if success:
                    fam['signature_guard'] = GUARD_IGNORED
                    rec.setdefault('credential_bypass_signals', []).append('signature_ignored')
            elif gk == 'nonce':
                rec['nonce_guard'] = GUARD_IGNORED if success else GUARD_STRICT
            elif gk == 'timestamp':
                rec['timestamp_guard'] = GUARD_IGNORED if success else GUARD_STRICT
            elif gk == 'token':
                rec['token_guard'] = GUARD_IGNORED if success else GUARD_STRICT

        if mut.startswith('M7') and target_field:
            rejected = (
                outcome == 'binding_rejected'
                or failure_class == 'binding_rejected'
                or (
                    not success
                    and failure_class in {'validation_error', 'auth_expired', 'business_state_blocked'}
                )
            )
            if success:
                rec['identity_binding'] = BINDING_LOOSE
                fam['identity_binding'] = BINDING_LOOSE
            elif rejected:
                rec['identity_binding'] = BINDING_ENFORCED
                fam['identity_binding'] = BINDING_ENFORCED
                fields = list(rec.get('rejected_identity_fields') or [])
                if target_field not in fields:
                    fields.append(target_field)
                rec['rejected_identity_fields'] = fields

        return entry

    def signature_guard(self, path: str, api_id: str = '') -> str:
        rec = self.by_api.get(self._api_key(api_id, path)) or {}
        sg = rec.get('signature_guard')
        if sg and sg != GUARD_UNKNOWN:
            return sg
        fam = self.by_family.get(self._family_key(path)) or {}
        return fam.get('signature_guard') or GUARD_UNKNOWN

    def identity_binding(self, path: str, api_id: str = '') -> str:
        rec = self.by_api.get(self._api_key(api_id, path)) or {}
        ib = rec.get('identity_binding')
        if ib and ib != BINDING_UNKNOWN:
            return ib
        fam = self.by_family.get(self._family_key(path)) or {}
        return fam.get('identity_binding') or BINDING_UNKNOWN

    def should_skip_credential_step(
        self,
        path: str,
        *,
        guard_kind: str,
        api_id: str = '',
    ) -> bool:
        """Skip redundant weakening when family already learned guard is ignored."""
        if guard_kind == 'signature' and self.signature_guard(path, api_id) == GUARD_IGNORED:
            return True
        rec = self.by_api.get(self._api_key(api_id, path)) or {}
        key_map = {
            'signature': 'signature_guard',
            'nonce': 'nonce_guard',
            'timestamp': 'timestamp_guard',
            'token': 'token_guard',
        }
        field = key_map.get(guard_kind)
        if field and rec.get(field) == GUARD_IGNORED:
            return True
        return False

    def should_skip_identity_field(
        self,
        path: str,
        field: str,
        *,
        api_id: str = '',
    ) -> bool:
        """Stop identity probes when binding already proven enforced on this API."""
        rec = self.by_api.get(self._api_key(api_id, path)) or {}
        if rec.get('identity_binding') == BINDING_ENFORCED:
            return True
        rejected = set(rec.get('rejected_identity_fields') or [])
        if field in rejected:
            return True
        return False

    def should_skip_api_mutations(
        self,
        path: str,
        *,
        api_id: str = '',
        m0_outcome: Optional[str] = None,
    ) -> Optional[str]:
        if m0_outcome and m0_outcome != 'business_success':
            return 'm0_not_success'
        return None

    def summary(self) -> Dict[str, Any]:
        sig_ignored = sum(
            1 for r in self.by_api.values() if r.get('signature_guard') == GUARD_IGNORED
        )
        binding_enforced = sum(
            1 for r in self.by_api.values() if r.get('identity_binding') == BINDING_ENFORCED
        )
        binding_loose = sum(
            1 for r in self.by_api.values() if r.get('identity_binding') == BINDING_LOOSE
        )
        return {
            'apis_observed': len(self.by_api),
            'families_observed': len(self.by_family),
            'probes_total': len(self.probe_log),
            'signature_ignored_count': sig_ignored,
            'identity_binding_enforced_count': binding_enforced,
            'identity_binding_loose_count': binding_loose,
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            'by_api': self.by_api,
            'by_family': self.by_family,
            'probe_log': self.probe_log[-200:],
            'summary': self.summary(),
        }
