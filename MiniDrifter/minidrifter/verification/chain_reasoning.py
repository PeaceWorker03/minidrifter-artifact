# -*- coding: utf-8 -*-
"""Per-chain reasoning journal — hypothesis, blockers, and revival plans."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from minidrifter.core.utils import stable_id


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


CHAIN_VERDICTS = frozenset({
    'continuable',
    'blocked_temporary',
    'blocked_baseline',
    'blocked_graph_hypothesis',
    'need_object',
    'completed',
    'finding',
    'dead',
})


class ChainReasoningJournal:
    """One chain's thinking scratchpad — like an agent session for that business path."""

    def __init__(
        self,
        chain_id: str,
        *,
        seed_api_id: str,
        seed_path: str,
        domain: str,
        goal_hypothesis: str = '',
    ) -> None:
        self.chain_id = chain_id
        self.seed_api_id = seed_api_id
        self.seed_path = seed_path
        self.domain = domain
        self.goal_hypothesis = goal_hypothesis or f'Explore {domain} workflow from {seed_path}'
        self.verdict: str = 'continuable'
        self.confidence: float = 0.7
        self.root_cause_layer: Optional[str] = None
        self.root_cause_summary: str = ''
        self.reasoning_steps: List[Dict[str, Any]] = []
        self.blockers: List[Dict[str, Any]] = []
        self.evidence_refs: List[str] = []
        self.recommended_actions: List[str] = []
        self.fallback_actions: List[str] = []
        self.revival_conditions: List[str] = []
        self.planner_errors: List[str] = []
        self.updated_at = _utc_now()

    def record_event(
        self,
        event: str,
        *,
        detail: str = '',
        layer: Optional[str] = None,
        failure_class: Optional[str] = None,
        path: Optional[str] = None,
    ) -> None:
        self.reasoning_steps.append({
            'at': _utc_now(),
            'event': event,
            'detail': detail[:500],
            'layer': layer,
            'failure_class': failure_class,
            'path': path,
        })
        self.updated_at = _utc_now()
        if path and path not in self.evidence_refs:
            self.evidence_refs.append(path)

    def apply_thought(self, thought: Dict[str, Any]) -> None:
        """Merge LLM or rule reasoner output."""
        self.verdict = thought.get('verdict') or self.verdict
        self.confidence = float(thought.get('confidence') or self.confidence)
        self.root_cause_layer = thought.get('root_cause_layer') or self.root_cause_layer
        self.root_cause_summary = str(thought.get('root_cause_summary') or thought.get('reason') or '')[:800]
        for step in thought.get('reasoning_steps') or []:
            if isinstance(step, dict):
                self.reasoning_steps.append({**step, 'at': step.get('at') or _utc_now(), 'source': 'reasoner'})
            elif isinstance(step, str):
                self.reasoning_steps.append({'at': _utc_now(), 'event': 'reason', 'detail': step, 'source': 'reasoner'})
        if thought.get('blocker'):
            self.blockers.append(thought['blocker'])
        self.recommended_actions = list(thought.get('recommended_actions') or thought.get('recommended_action') or [])[:6]
        if isinstance(thought.get('recommended_action'), str):
            self.recommended_actions = [thought['recommended_action']] + self.recommended_actions
        self.fallback_actions = list(thought.get('fallback_actions') or [])[:6]
        if thought.get('fallback'):
            self.fallback_actions.insert(0, str(thought['fallback']))
        self.revival_conditions = list(thought.get('revival_conditions') or [])[:8]
        self.planner_errors = list(thought.get('planner_errors') or [])[:5]
        self.updated_at = _utc_now()

    def to_dict(self) -> Dict[str, Any]:
        return {
            'chain_id': self.chain_id,
            'seed_api_id': self.seed_api_id,
            'seed_path': self.seed_path,
            'domain': self.domain,
            'goal_hypothesis': self.goal_hypothesis,
            'verdict': self.verdict,
            'confidence': self.confidence,
            'root_cause_layer': self.root_cause_layer,
            'root_cause_summary': self.root_cause_summary,
            'reasoning_steps': self.reasoning_steps[-40:],
            'blockers': self.blockers[-10:],
            'evidence_refs': self.evidence_refs[-20:],
            'recommended_actions': self.recommended_actions,
            'fallback_actions': self.fallback_actions,
            'revival_conditions': self.revival_conditions,
            'planner_errors': self.planner_errors,
            'updated_at': self.updated_at,
        }


class ChainReasoningRegistry:
    def __init__(self) -> None:
        self._journals: Dict[str, ChainReasoningJournal] = {}

    def get_or_create(
        self,
        chain_id: str,
        *,
        seed_api_id: str,
        seed_path: str,
        domain: str,
    ) -> ChainReasoningJournal:
        if chain_id not in self._journals:
            self._journals[chain_id] = ChainReasoningJournal(
                chain_id,
                seed_api_id=seed_api_id,
                seed_path=seed_path,
                domain=domain,
            )
        return self._journals[chain_id]

    def get(self, chain_id: str) -> Optional[ChainReasoningJournal]:
        return self._journals.get(chain_id)

    def all_journals(self) -> List[Dict[str, Any]]:
        return [j.to_dict() for j in self._journals.values()]

    def summary_for_llm(self, limit: int = 8) -> List[Dict[str, Any]]:
        rows = sorted(self._journals.values(), key=lambda j: j.updated_at, reverse=True)
        return [
            {
                'chain_id': j.chain_id,
                'domain': j.domain,
                'seed_path': j.seed_path,
                'verdict': j.verdict,
                'root_cause_summary': j.root_cause_summary[:200],
                'recommended_actions': j.recommended_actions[:3],
                'revival_conditions': j.revival_conditions[:3],
            }
            for j in rows[:limit]
        ]

    def to_document(self) -> Dict[str, Any]:
        by_verdict: Dict[str, int] = {}
        for j in self._journals.values():
            by_verdict[j.verdict] = by_verdict.get(j.verdict, 0) + 1
        return {
            'schema_version': '1.0.0',
            'generated_at': _utc_now(),
            'chain_count': len(self._journals),
            'by_verdict': by_verdict,
            'journals': self.all_journals(),
        }
