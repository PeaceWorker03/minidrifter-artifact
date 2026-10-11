# -*- coding: utf-8 -*-
"""Chain lifecycle state machine and scoring for multi-chain beam search."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from minidrifter.core.utils import stable_id


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')

CHAIN_ACTIVE = 'active'
CHAIN_BLOCKED = 'blocked'
CHAIN_QUARANTINED = 'quarantined'
CHAIN_DEAD = 'dead'
CHAIN_COMPLETED = 'completed'
CHAIN_FINDING = 'finding'

PHASE_ATOMIC = 'ATOMIC_PROBING'
PHASE_HARVEST = 'OBJECT_HARVESTED'
PHASE_EXPAND = 'CHAIN_EXPANDING'
PHASE_BINDING = 'BINDING_ASSERTION_READY'
PHASE_FINDING_ESCALATION = 'FINDING_ESCALATION'
PHASE_MUTATION = 'MUTATION_TESTING'
PHASE_DONE = 'ORACLE_ADJUDICATION'


def compute_chain_score(state: Dict[str, Any]) -> float:
    score = 0.0
    score += 1.0 * state.get('depth', 0)
    score += 1.5 * state.get('business_success_count', 0)
    score += 2.0 * state.get('object_harvest_count', 0)
    score += 3.0 * state.get('capability_harvest_count', 0)
    score += 4.0 * (1 if state.get('binding_ready') else 0)
    score += 6.0 * (1 if state.get('escalation_pending') else 0)
    score += 8.0 * state.get('finding_signal', 0)
    score -= 2.0 * state.get('auth_failure_count', 0)
    score -= 1.5 * state.get('build_failure_count', 0)
    score -= 1.0 * state.get('repeated_equivalent', 0)
    score -= 1.0 * len(state.get('missing_objects') or [])
    if state.get('status') == CHAIN_QUARANTINED:
        score -= 3.0
    if state.get('status') == CHAIN_DEAD:
        score -= 100.0
    return round(score, 3)


class ChainState:
    """One candidate business chain in the beam."""

    def __init__(
        self,
        seed_api_id: str,
        *,
        path: str = '',
        domain: str = 'general',
        chain_id: Optional[str] = None,
        max_depth: int = 5,
    ) -> None:
        self.chain_id = chain_id or stable_id('chain', seed_api_id, domain)
        self.seed_api_id = seed_api_id
        self.domain = domain
        self.path = path
        self.max_depth = max_depth
        self.status = CHAIN_ACTIVE
        self.phase = PHASE_ATOMIC
        self.nodes: List[Dict[str, Any]] = []
        self.available_objects: Set[str] = set()
        self.missing_objects: Set[str] = set()
        self.last_outcome: Optional[str] = None
        self.blocked_reason: Optional[str] = None
        self.revive_condition: Optional[List[str]] = None
        self.retry_count = 0
        self.business_success_count = 0
        self.object_harvest_count = 0
        self.capability_harvest_count = 0
        self.auth_failure_count = 0
        self.build_failure_count = 0
        self.repeated_equivalent = 0
        self.binding_ready = False
        self.finding_signal = 0
        self.findings: List[str] = []
        self.skip_streak = 0
        self.preferred_next_api: Optional[str] = None
        self.planned_path: List[str] = []
        self.hypothesis_id: Optional[str] = None
        self.parent_chain_id: Optional[str] = None
        self.static_chain_id: Optional[str] = None
        self.static_hops: List[Dict[str, Any]] = []
        self.static_next_index: int = 0
        self.target_hop: Optional[str] = None
        self.risk_hops: List[str] = []
        self.binding_tested = False
        self.active_findings: List[Dict[str, Any]] = []
        self.escalation_pending = False

    @property
    def depth(self) -> int:
        return len(self.nodes)

    def push_node(self, api_id: str, path: str, role: str = 'hop') -> None:
        self.nodes.append({
            'api_id': api_id,
            'path': path,
            'role': role,
            'depth': len(self.nodes),
            'at': _utc_now(),
        })

    def tested_api_ids(self) -> Set[str]:
        return {n.get('api_id') for n in self.nodes if n.get('api_id')}

    def record_outcome(
        self,
        outcome: str,
        *,
        failure_class: Optional[str] = None,
        harvested: Optional[List[str]] = None,
        finding: bool = False,
    ) -> None:
        self.last_outcome = outcome
        if outcome == 'business_success':
            self.business_success_count += 1
            self.phase = PHASE_HARVEST if self.phase == PHASE_ATOMIC else PHASE_EXPAND
            for f in harvested or []:
                self.available_objects.add(f)
            if harvested:
                self.object_harvest_count += len(harvested)
            self.missing_objects = set()
        elif failure_class == 'auth_expired':
            self.auth_failure_count += 1
        elif failure_class == 'build_failed':
            self.build_failure_count += 1
        if finding:
            self.finding_signal += 1
            self.phase = PHASE_FINDING_ESCALATION
            self.escalation_pending = True
            # Keep chain active for finding-driven deepening (do not terminate at first signal)

    def quarantine(self, reason: str, revive: Optional[List[str]] = None) -> None:
        self.status = CHAIN_QUARANTINED
        self.blocked_reason = reason
        self.revive_condition = revive

    def revive_if(self, available: Set[str]) -> bool:
        if self.status != CHAIN_QUARANTINED:
            return False
        need = set(self.revive_condition or [])
        if need and need <= available:
            self.status = CHAIN_ACTIVE
            self.blocked_reason = None
            self.retry_count += 1
            return True
        return False

    def mark_dead(self, reason: str) -> None:
        self.status = CHAIN_DEAD
        self.blocked_reason = reason

    def record_skip(self) -> None:
        self.skip_streak += 1
        self.repeated_equivalent += 1

    def clear_skip_streak(self) -> None:
        self.skip_streak = 0

    def mark_escalation_dispatched(self) -> None:
        self.escalation_pending = False

    def add_finding_context(self, finding: Dict[str, Any]) -> None:
        self.active_findings.append(finding)
        self.phase = PHASE_FINDING_ESCALATION

    def mark_completed(self) -> None:
        self.status = CHAIN_COMPLETED
        self.phase = PHASE_DONE

    def mark_binding_ready(self) -> None:
        self.binding_ready = True
        self.phase = PHASE_BINDING

    def mark_binding_tested(self) -> None:
        self.binding_tested = True
        self.phase = PHASE_MUTATION

    def score(self) -> float:
        return compute_chain_score({
            'depth': self.depth,
            'status': self.status,
            'business_success_count': self.business_success_count,
            'object_harvest_count': self.object_harvest_count,
            'capability_harvest_count': self.capability_harvest_count,
            'binding_ready': self.binding_ready,
            'finding_signal': self.finding_signal,
            'auth_failure_count': self.auth_failure_count,
            'build_failure_count': self.build_failure_count,
            'repeated_equivalent': self.repeated_equivalent,
            'escalation_pending': self.escalation_pending,
        })

    def to_dict(self) -> Dict[str, Any]:
        return {
            'chain_id': self.chain_id,
            'seed_api_id': self.seed_api_id,
            'domain': self.domain,
            'path': self.path,
            'nodes': self.nodes,
            'depth': self.depth,
            'status': self.status,
            'phase': self.phase,
            'available_objects': sorted(self.available_objects),
            'missing_objects': sorted(self.missing_objects),
            'last_outcome': self.last_outcome,
            'blocked_reason': self.blocked_reason,
            'revive_condition': self.revive_condition,
            'retry_count': self.retry_count,
            'skip_streak': self.skip_streak,
            'business_success_count': self.business_success_count,
            'object_harvest_count': self.object_harvest_count,
            'score': self.score(),
            'findings': self.findings,
            'binding_ready': self.binding_ready,
            'binding_tested': self.binding_tested,
            'preferred_next_api': self.preferred_next_api,
            'planned_path': self.planned_path,
            'hypothesis_id': self.hypothesis_id,
            'parent_chain_id': self.parent_chain_id,
            'static_chain_id': self.static_chain_id,
            'static_hops': self.static_hops,
            'static_next_index': self.static_next_index,
            'target_hop': self.target_hop,
            'risk_hops': self.risk_hops,
            'active_findings': self.active_findings,
            'escalation_pending': self.escalation_pending,
        }
