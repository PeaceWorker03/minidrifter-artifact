# -*- coding: utf-8 -*-
"""Breadth scheduler — priority queue of seed APIs with retire semantics."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from minidrifter.core.utils import stable_id
from minidrifter.verification.campaign_planner import build_test_case, score_all_templates


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


class BreadthScheduler:
    def __init__(
        self,
        pack_dir,
        *,
        baseline_context: Dict[str, Any],
        only_safe: bool = True,
        max_seeds: int = 30,
    ) -> None:
        self.pack_dir = pack_dir
        self.baseline_context = baseline_context
        self.retired: Dict[str, Dict[str, Any]] = {}
        self.active_seed: Optional[str] = None
        templates = score_all_templates(
            pack_dir, only_safe=only_safe, baseline_context=baseline_context, limit=max_seeds,
        )
        self.queue: List[Dict[str, Any]] = [
            {
                'seed_id': stable_id('seed', t.get('api_id')),
                'api_id': t.get('api_id'),
                'path': t.get('path'),
                'score': t.get('_planner_score'),
                'template': t,
                'status': 'pending',
            }
            for t in templates
        ]

    def pop_next(self) -> Optional[Dict[str, Any]]:
        while self.queue:
            item = self.queue.pop(0)
            api_id = item.get('api_id')
            if api_id in self.retired:
                continue
            item['status'] = 'active'
            self.active_seed = api_id
            return item
        return None

    def retire(self, api_id: str, reason: str, *, tests_consumed: int = 0, findings: int = 0) -> None:
        self.retired[api_id] = {
            'api_id': api_id,
            'retire_reason': reason,
            'retired_at': _utc_now(),
            'tests_consumed': tests_consumed,
            'findings': findings,
        }
        if self.active_seed == api_id:
            self.active_seed = None

    def build_seed_test_case(self, seed: Dict[str, Any], index: int = 0) -> Dict[str, Any]:
        tc = build_test_case(seed['template'], baseline_context=self.baseline_context, index=index)
        tc['test_stage'] = 'seed_baseline'
        tc['seed_id'] = seed.get('seed_id')
        return tc

    def summary(self) -> Dict[str, Any]:
        return {
            'pending': len(self.queue),
            'retired_count': len(self.retired),
            'retired': list(self.retired.values()),
            'next_pending': [{'api_id': q.get('api_id'), 'path': q.get('path'), 'score': q.get('score')} for q in self.queue[:5]],
        }
