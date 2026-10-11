# -*- coding: utf-8 -*-
"""Failure circuit breaker — generic failure budgets for verification search."""
from __future__ import annotations

from typing import Any, Dict, Optional, Set, Tuple


class FailureCircuitBreaker:
    """Generic failure budget — not pack-specific."""

    THRESHOLDS = {
        'auth_expired': 5,
        'build_failed': 5,
        'unsupported_post_crypto': 5,
        'business_state_blocked': 8,
    }

    AUTH_PATH_HINTS = ('/user/', '/authentication/', '/account/', '/login/')

    def __init__(self) -> None:
        self.counts: Dict[str, int] = {}
        self.open: Dict[str, bool] = {}
        self.freeze_tags: Set[str] = set()
        self.pause_execute = False

    def record(self, failure_class: str) -> None:
        self.counts[failure_class] = self.counts.get(failure_class, 0) + 1
        threshold = self.THRESHOLDS.get(failure_class)
        if threshold and self.counts[failure_class] >= threshold:
            self.open[failure_class] = True
            if failure_class == 'auth_expired':
                self.pause_execute = True
            if failure_class == 'build_failed':
                self.freeze_tags.add('crypto_post_unsupported')

    def is_open(self, failure_class: str) -> bool:
        return self.open.get(failure_class, False)

    def should_skip_test(
        self,
        test_case: Dict[str, Any],
        *,
        template: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bool, str]:
        """Skip tests likely to waste budget on open circuits."""
        path = (test_case.get('path') or '').lower()
        tpl = template or test_case.get('template') or {}

        if self.pause_execute and any(h in path for h in self.AUTH_PATH_HINTS):
            return True, 'auth_circuit_pause'

        if self.is_open('build_failed'):
            method = (tpl.get('method') or test_case.get('method') or 'GET').upper()
            if tpl.get('crypto_required') and method != 'GET':
                return True, 'build_circuit_pause'

        return False, ''

    def to_dict(self) -> Dict[str, Any]:
        return {
            'counts': self.counts,
            'open': self.open,
            'freeze_tags': sorted(self.freeze_tags),
            'pause_execute': self.pause_execute,
        }
