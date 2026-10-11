# -*- coding: utf-8 -*-
"""Progress watchdog — stall detection (circuit breaker lives in circuit_breaker.py)."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List

from minidrifter.verification.circuit_breaker import FailureCircuitBreaker  # noqa: F401 — re-export

__all__ = ['FailureCircuitBreaker', 'ProgressWatchdog']


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


class ProgressWatchdog:
    """Detect global stagnation; trigger replan."""

    def __init__(self, window: int = 10) -> None:
        self.window = window
        self.history: List[Dict[str, Any]] = []
        self.last_progress_at = _utc_now()
        self.stall_count = 0

    def record_step(
        self,
        *,
        new_objects: int = 0,
        new_depth: int = 0,
        new_success_api: int = 0,
        finding_signal: int = 0,
    ) -> None:
        self.history.append({
            'new_objects': new_objects,
            'new_depth': new_depth,
            'new_success_api': new_success_api,
            'finding_signal': finding_signal,
            'at': _utc_now(),
        })
        if len(self.history) > self.window:
            self.history = self.history[-self.window:]

        if any([new_objects, new_depth, new_success_api, finding_signal]):
            self.last_progress_at = _utc_now()
            self.stall_count = 0
        else:
            self.stall_count += 1

    def is_stalled(self) -> bool:
        if len(self.history) < self.window:
            return False
        recent = self.history[-self.window:]
        return all(
            h['new_objects'] == 0 and h['new_depth'] == 0
            and h['new_success_api'] == 0 and h['finding_signal'] == 0
            for h in recent
        )

    def exploration_reset_hint(self) -> Dict[str, Any]:
        return {
            'action': 'exploration_reset',
            'reason': 'no_progress_in_window',
            'suggestions': [
                'switch_domain',
                'acquire_object',
                'llm_replan',
                'downrank_current_families',
            ],
            'stall_count': self.stall_count,
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            'window': self.window,
            'stall_count': self.stall_count,
            'last_progress_at': self.last_progress_at,
            'is_stalled': self.is_stalled(),
        }
