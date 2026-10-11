# -*- coding: utf-8 -*-
"""Prune registry — skip equivalent tests (P1-P4 + IG)."""
from __future__ import annotations

import hashlib
import json
from collections import Counter
from typing import Any, Dict, List, Optional, Set, Tuple

from minidrifter.verification.information_gain import estimate_information_gain, is_mandatory_test
from minidrifter.verification.request_builder import baseline_pool, resolve_params

BORING_OUTCOMES = frozenset({
    'build_failed', 'safety_blocked', 'auth_expired', 'transport_error',
    'business_state_blocked', 'dry_run_ok',
})


class PruneRegistry:
    def __init__(self, *, ig_threshold: float = 0.25, ig_prune_enabled: bool = True) -> None:
        self.ig_threshold = ig_threshold
        self.ig_prune_enabled = ig_prune_enabled
        self._outcome_keys: Set[str] = set()
        self._param_keys: Set[str] = set()
        self._pool_keys: Set[str] = set()
        self._chain_keys: Set[str] = set()
        self._mutation_outcomes: Dict[str, Set[str]] = {}
        self._saturated_mutations: Set[str] = set()
        self.pruned: List[Dict[str, Any]] = []
        self._prune_counts: Counter = Counter()

    def summary(self) -> Dict[str, Any]:
        total = sum(self._prune_counts.values())
        return {
            'total_pruned': total,
            'by_reason': dict(self._prune_counts),
            'ig_threshold': self.ig_threshold,
            'ig_prune_enabled': self.ig_prune_enabled,
        }

    def should_skip(
        self,
        test_case: Dict[str, Any],
        *,
        baseline_context: Dict[str, Any],
        pool_hash: str,
        chain_fingerprint: str = '',
        object_pool: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bool, Optional[str]]:
        api_id = test_case.get('api_id') or ''
        mutation = test_case.get('mutation_type') or 'M0_baseline_replay'
        pool = baseline_pool(baseline_context)
        resolved, _ = resolve_params(test_case.get('params') or {}, pool)
        param_key = hashlib.sha256(json.dumps(resolved, sort_keys=True).encode()).hexdigest()[:16]

        mut_key = f'{api_id}|{mutation}'

        # P1 — mutation saturated with only boring outcomes
        if mut_key in self._saturated_mutations and not is_mandatory_test(test_case):
            return True, 'P1_outcome_saturated'

        outcome_pk = f'{api_id}|{mutation}|{param_key}'
        if outcome_pk in self._outcome_keys:
            return True, 'P1_outcome_equivalent'

        pk = f'{api_id}|{pool_hash}'
        if pk in self._pool_keys and mutation == 'M0_baseline_replay' and not is_mandatory_test(test_case):
            return True, 'P3_pool_unchanged_m0'

        param_pk = f'{api_id}|{param_key}'
        if param_pk in self._param_keys:
            return True, 'P2_param_equivalent'

        if chain_fingerprint:
            ck = f'{chain_fingerprint}|{api_id}|{mutation}'
            if ck in self._chain_keys:
                return True, 'P4_chain_equivalent'

        if self.ig_prune_enabled and not is_mandatory_test(test_case):
            ig = estimate_information_gain(
                test_case, object_pool=object_pool, pool_hash=pool_hash,
            )
            if ig < self.ig_threshold:
                return True, f'P5_ig_below_threshold:{ig}'

        return False, None

    def record(
        self,
        test_case: Dict[str, Any],
        analysis: Dict[str, Any],
        *,
        baseline_context: Dict[str, Any],
        pool_hash: str,
        chain_fingerprint: str = '',
    ) -> None:
        api_id = test_case.get('api_id') or ''
        mutation = test_case.get('mutation_type') or 'M0_baseline_replay'
        outcome = analysis.get('call_outcome') or 'unknown'
        pool = baseline_pool(baseline_context)
        resolved, _ = resolve_params(test_case.get('params') or {}, pool)
        param_key = hashlib.sha256(json.dumps(resolved, sort_keys=True).encode()).hexdigest()[:16]

        mut_key = f'{api_id}|{mutation}'
        self._mutation_outcomes.setdefault(mut_key, set()).add(outcome)
        outcomes = self._mutation_outcomes[mut_key]
        if outcomes and outcomes.issubset(BORING_OUTCOMES) and len(outcomes) >= 1:
            self._saturated_mutations.add(mut_key)

        self._outcome_keys.add(f'{api_id}|{mutation}|{param_key}')
        self._outcome_keys.add(f'{api_id}|{mutation}|{outcome}')
        self._param_keys.add(f'{api_id}|{param_key}')
        self._pool_keys.add(f'{api_id}|{pool_hash}')
        if chain_fingerprint:
            self._chain_keys.add(f'{chain_fingerprint}|{api_id}|{mutation}')

    def record_pruned(self, test_case: Dict[str, Any], reason: str) -> None:
        base_reason = reason.split(':')[0] if reason else 'pruned'
        self._prune_counts[base_reason] += 1
        ig = None
        if reason.startswith('P5_ig_below_threshold:'):
            try:
                ig = float(reason.split(':', 1)[1])
            except ValueError:
                pass
        self.pruned.append({
            'test_id': test_case.get('test_id'),
            'api_id': test_case.get('api_id'),
            'path': test_case.get('path'),
            'mutation_type': test_case.get('mutation_type'),
            'test_stage': test_case.get('test_stage'),
            'reason': reason,
            'information_gain': ig,
        })
