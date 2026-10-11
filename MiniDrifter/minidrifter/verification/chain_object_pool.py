# -*- coding: utf-8 -*-
"""Chain-local object pool — harvested fields only serve the active business chain."""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from minidrifter.core.schema import SCHEMA_VERSION

GLOBAL_CONTEXT_FIELDS = frozenset({
    'token', 'authorization', 'appidentity', 'appversion', 'host', 'openid', 'unionid',
    'timespan', 'timestamp', 'sign', 'signature', 'nonce', 'ticket', 'code',
})


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _norm_field(name: str) -> str:
    return (name or '').strip()


def _field_match(required: str, available: Set[str]) -> bool:
    r = required.lower()
    for a in available:
        if a.lower() == r:
            return True
    return False


class ChainObjectPool:
    """Objects harvested along one static business chain; not shared with BFS."""

    def __init__(self, chain_id: str, *, static_hops: Optional[List[Dict[str, Any]]] = None) -> None:
        self.chain_id = chain_id
        self.objects: Dict[str, str] = {}
        self.missing_objects: List[str] = []
        self.producer_outputs: Dict[str, Dict[str, str]] = {}
        self.consumer_inputs: Dict[str, List[str]] = {}
        self.mutation_targets: List[str] = []
        self._hop_index: Dict[str, Dict[str, Any]] = {}
        for hop in static_hops or []:
            aid = hop.get('api_id')
            if aid:
                self._hop_index[aid] = hop
            self.consumer_inputs[aid or ''] = list(hop.get('consumes') or hop.get('requires') or [])
            for f in hop.get('mutation_targets') or []:
                if f not in self.mutation_targets:
                    self.mutation_targets.append(f)

    def register_hop_requirements(self, api_id: str, consumes: List[str]) -> None:
        self.consumer_inputs[api_id] = list(consumes)

    def missing_for_hop(self, hop: Dict[str, Any]) -> List[str]:
        need = list(hop.get('consumes') or hop.get('requires') or [])
        missing: List[str] = []
        available = set(self.objects.keys())
        for f in need:
            if _norm_field(f).lower() in GLOBAL_CONTEXT_FIELDS:
                continue
            if not _field_match(f, available):
                missing.append(f)
        self.missing_objects = missing
        return missing

    def harvest(self, api_id: str, produced_fields: List[str], values: Optional[Dict[str, str]] = None) -> None:
        """Store producer output for downstream hops on this chain only."""
        values = values or {}
        bucket = self.producer_outputs.setdefault(api_id, {})
        for f in produced_fields or []:
            if not f:
                continue
            val = values.get(f) or values.get(f.lower()) or values.get(f.upper())
            if val is not None:
                self.objects[f] = str(val)
                bucket[f] = str(val)
        self.missing_objects = []

    def param_pool(self) -> Dict[str, str]:
        return dict(self.objects)

    def apply_to_test_case(self, test_case: Dict[str, Any], hop: Dict[str, Any]) -> Dict[str, Any]:
        """Overlay chain-local object values onto request params for this hop."""
        tc = deepcopy(test_case)
        pool = self.param_pool()
        if not pool:
            return tc

        def _overlay(bag: Dict[str, Any]) -> Dict[str, Any]:
            out = dict(bag or {})
            need = set(hop.get('consumes') or hop.get('requires') or [])
            mut = tc.get('mutation_type') or ''
            target = tc.get('target_field') or ''

            def _preserve_m7_target(key: str) -> bool:
                return bool(mut.startswith('M7') and target and str(key).lower() == target.lower())

            for k in list(out.keys()):
                if _preserve_m7_target(k):
                    continue
                matched_field = next((f for f in need if str(k).lower() == f.lower()), k)
                if matched_field in pool:
                    out[k] = pool[matched_field]
                elif k in pool:
                    out[k] = pool[k]
            for f in need:
                if _preserve_m7_target(f):
                    continue
                if f in pool and f not in out:
                    out[f] = pool[f]
                elif f in pool:
                    matched = next((k for k in out if str(k).lower() == f.lower()), None)
                    if matched is None:
                        out[f] = pool[f]
            return out

        tc['params'] = _overlay(tc.get('params') or {})
        tc['body_params'] = _overlay(tc.get('body_params') or {})
        tc['query_params'] = _overlay(tc.get('query_params') or {})
        tc['chain_param_pool'] = pool
        tc['chain_id'] = self.chain_id
        tc['chain_hop_role'] = hop.get('role')
        return tc

    def to_dict(self) -> Dict[str, Any]:
        return {
            'schema_version': SCHEMA_VERSION,
            'generated_at': _utc_now(),
            'chain_id': self.chain_id,
            'objects': dict(self.objects),
            'missing_objects': list(self.missing_objects),
            'producer_outputs': {k: dict(v) for k, v in self.producer_outputs.items()},
            'consumer_inputs': {k: list(v) for k, v in self.consumer_inputs.items()},
            'mutation_targets': list(self.mutation_targets),
        }

    def seed_from_baseline(
        self,
        baseline_context: Dict[str, Any],
        *,
        chain_doc: Optional[Dict[str, Any]] = None,
        intake_report: Optional[Dict[str, Any]] = None,
    ) -> List[str]:
        """Pre-load producer fields from baseline_runtime_context / intake aggregate."""
        seeded: List[str] = []
        resolved = baseline_context.get('resolved_fields') or {}
        agg = ((intake_report or {}).get('decrypted_fields_aggregate') or {}).get('fields') or {}

        def _val(field: str) -> Optional[str]:
            if field in agg and agg[field] not in (None, ''):
                return str(agg[field])
            ent = resolved.get(field) or resolved.get(field.lower())
            if isinstance(ent, dict) and ent.get('value') not in (None, ''):
                return str(ent['value'])
            return None

        want: Set[str] = set(self.mutation_targets)
        for hop in (chain_doc or {}).get('hops') or []:
            want.update(hop.get('produces') or [])
            want.update(hop.get('mutation_targets') or [])

        values: Dict[str, str] = {}
        for field in want:
            if _norm_field(field).lower() in GLOBAL_CONTEXT_FIELDS:
                continue
            v = _val(field)
            if v:
                values[field] = v

        of = (chain_doc or {}).get('object_flow') or {}
        of_field = of.get('object_field')
        if of_field and of.get('object_value') not in (None, ''):
            values[of_field] = str(of['object_value'])

        if values:
            self.harvest('baseline_seed', sorted(values.keys()), values)
            seeded = sorted(values.keys())
        return seeded
