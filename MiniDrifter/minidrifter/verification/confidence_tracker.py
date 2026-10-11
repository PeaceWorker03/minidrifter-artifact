# -*- coding: utf-8 -*-
"""Belief / confidence tracking for API roles, graph edges, and diagnoses."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from minidrifter.verification.pack_loader import load_field_ontology


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


class ConfidenceTracker:
    """Generic confidence store — no pack-specific hardcoding."""

    def __init__(self) -> None:
        self.api_atomic: Dict[str, Dict[str, Any]] = {}
        self.producer_edges: Dict[str, float] = {}
        self.field_mapping: Dict[str, float] = {}
        self.domain_stats: Dict[str, Dict[str, int]] = {}
        self.failure_class_streak: Dict[str, int] = {}
        self._ontology = load_field_ontology()

    def _edge_key(self, api_id: str, field: str) -> str:
        return f'{api_id}|produces|{field}'

    def record_atomic_outcome(
        self,
        api_id: str,
        *,
        path: str = '',
        domain: str = 'general',
        outcome: str,
        failure_class: Optional[str] = None,
        harvested: Optional[List[str]] = None,
    ) -> None:
        entry = self.api_atomic.setdefault(api_id, {
            'api_id': api_id,
            'path': path,
            'domain': domain,
            'attempts': 0,
            'successes': 0,
            'last_outcome': None,
            'atomic_passed': False,
        })
        entry['attempts'] += 1
        entry['last_outcome'] = outcome
        entry['path'] = path or entry.get('path')
        entry['domain'] = domain or entry.get('domain')
        if outcome == 'business_success':
            entry['successes'] += 1
            entry['atomic_passed'] = True
            self.failure_class_streak.clear()
            for f in harvested or []:
                self.producer_edges[self._edge_key(api_id, f)] = min(
                    1.0, self.producer_edges.get(self._edge_key(api_id, f), 0.5) + 0.2,
                )
        elif failure_class:
            self.failure_class_streak[failure_class] = self.failure_class_streak.get(failure_class, 0) + 1

        ds = self.domain_stats.setdefault(domain, {})
        key = failure_class or outcome or 'unknown'
        ds[key] = ds.get(key, 0) + 1

    def atomic_passed(self, api_id: str) -> bool:
        return bool((self.api_atomic.get(api_id) or {}).get('atomic_passed'))

    def expected_success(self, api_id: str, domain: str) -> float:
        entry = self.api_atomic.get(api_id) or {}
        if entry.get('attempts'):
            return entry.get('successes', 0) / max(1, entry['attempts'])
        ds = self.domain_stats.get(domain) or {}
        ok = ds.get('business_success', 0)
        total = sum(ds.values()) or 1
        return ok / total if total else 0.5

    def failure_penalty(self, api_id: str, domain: str) -> float:
        entry = self.api_atomic.get(api_id) or {}
        if entry.get('attempts', 0) >= 2 and not entry.get('atomic_passed'):
            return 0.8
        ds = self.domain_stats.get(domain) or {}
        auth = ds.get('auth_expired', 0)
        build = ds.get('build_failed', 0)
        total = sum(ds.values()) or 1
        return min(1.0, (auth * 0.4 + build * 0.3) / total)

    def producer_confidence(self, api_id: str, field: str) -> float:
        return self.producer_edges.get(self._edge_key(api_id, field), 0.72)

    def downgrade_producer(self, api_id: str, field: str, delta: float = 0.2) -> None:
        key = self._edge_key(api_id, field)
        self.producer_edges[key] = max(0.1, self.producer_edges.get(key, 0.72) - delta)

    def downgrade_field_mapping(self, field: str, delta: float = 0.2) -> None:
        self.field_mapping[field] = max(0.1, self.field_mapping.get(field, 0.81) - delta)

    def failure_streak(self, failure_class: str) -> int:
        return self.failure_class_streak.get(failure_class, 0)

    def high_value_fields(self) -> Set[str]:
        return set(self._ontology.get('high_value_produces') or [])

    def to_document(self) -> Dict[str, Any]:
        return {
            'schema_version': '1.0.0',
            'generated_at': _utc_now(),
            'api_atomic': self.api_atomic,
            'producer_edges': self.producer_edges,
            'field_mapping': self.field_mapping,
            'domain_stats': self.domain_stats,
            'failure_class_streak': self.failure_class_streak,
        }
