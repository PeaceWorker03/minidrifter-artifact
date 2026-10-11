# -*- coding: utf-8 -*-
"""Depth chain — DFS stack for workflow-linked API deepening."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from minidrifter.core.utils import stable_id


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


class DepthChain:
    def __init__(self, seed_api_id: str, *, max_depth: int = 5, max_no_signal: int = 2) -> None:
        self.chain_id = stable_id('chain', seed_api_id)
        self.seed_api_id = seed_api_id
        self.max_depth = max_depth
        self.max_no_signal = max_no_signal
        self.nodes: List[Dict[str, Any]] = []
        self._no_signal_streak = 0
        self.findings: List[str] = []
        self.stop_reason: Optional[str] = None

    def push(self, node: Dict[str, Any]) -> None:
        self.nodes.append({**node, 'depth': len(self.nodes), 'entered_at': _utc_now()})
        self._no_signal_streak = 0

    def record_no_signal(self) -> None:
        self._no_signal_streak += 1

    def record_signal(self, signal: str) -> None:
        self._no_signal_streak = 0
        if signal:
            self.nodes[-1]['signals'] = self.nodes[-1].get('signals', []) + [signal]

    def record_finding(self, finding_id: str) -> None:
        self.findings.append(finding_id)

    def should_stop(self) -> bool:
        if len(self.nodes) >= self.max_depth:
            self.stop_reason = 'max_depth'
            return True
        if self._no_signal_streak >= self.max_no_signal:
            self.stop_reason = 'no_signal_streak'
            return True
        return False

    def fingerprint(self) -> str:
        return '|'.join(n.get('api_id', '') for n in self.nodes)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'chain_id': self.chain_id,
            'seed_api': self.seed_api_id,
            'depth': len(self.nodes),
            'nodes': self.nodes,
            'findings': self.findings,
            'stop_reason': self.stop_reason,
        }
