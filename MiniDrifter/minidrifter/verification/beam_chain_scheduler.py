# -*- coding: utf-8 -*-
"""Multi-chain Beam Search scheduler."""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Set

from minidrifter.core.utils import stable_id
from minidrifter.verification.chain_state import (
    CHAIN_ACTIVE,
    CHAIN_DEAD,
    CHAIN_FINDING,
    CHAIN_QUARANTINED,
    ChainState,
    PHASE_ATOMIC,
    PHASE_EXPAND,
)
from minidrifter.verification.campaign_planner import _infer_domain


class BeamChainScheduler:
    """Maintain parallel candidate chains; expand top-B each round."""

    def __init__(self, *, beam_width: int = 5, max_depth: int = 5) -> None:
        self.beam_width = beam_width
        self.max_depth = max_depth
        self.chains: Dict[str, ChainState] = {}

    def seed_from_atomic(
        self,
        api_id: str,
        *,
        path: str,
        domain: str,
        harvested: Optional[List[str]] = None,
    ) -> ChainState:
        if api_id in {c.seed_api_id for c in self.chains.values() if c.status == CHAIN_ACTIVE}:
            for c in self.chains.values():
                if c.seed_api_id == api_id and c.status == CHAIN_ACTIVE:
                    return c
        chain = ChainState(api_id, path=path, domain=domain, max_depth=self.max_depth)
        chain.push_node(api_id, path, role='seed')
        chain.record_outcome('business_success', harvested=harvested or [])
        chain.phase = PHASE_EXPAND
        self.chains[chain.chain_id] = chain
        return chain

    def seed_from_business_chain(self, chain_doc: Dict[str, Any], *, harvested: Optional[List[str]] = None) -> ChainState:
        """Seed beam from statically recovered business chain."""
        entry = chain_doc.get('entry_api') or ''
        hops = chain_doc.get('hops') or []
        entry_path = chain_doc.get('entry_path') or (hops[0].get('path') if hops else '')
        domain = chain_doc.get('domain') or 'general'
        chain = ChainState(
            entry,
            path=entry_path,
            domain=domain,
            chain_id=chain_doc.get('chain_id'),
            max_depth=self.max_depth,
        )
        chain.static_chain_id = chain_doc.get('chain_id')
        chain.static_hops = list(hops)
        chain.static_next_index = 1 if len(hops) > 1 else 0
        chain.target_hop = chain_doc.get('target_hop')
        chain.risk_hops = list(chain_doc.get('risk_hops') or [])
        chain.planned_path = [h.get('api_id') for h in hops if h.get('api_id')]
        if len(chain.planned_path) > 1:
            chain.preferred_next_api = chain.planned_path[1]
        chain.push_node(entry, entry_path, role='seed')
        chain.record_outcome('business_success', harvested=harvested or [])
        chain.phase = PHASE_EXPAND
        self.chains[chain.chain_id] = chain
        return chain

    def fork_chain(
        self,
        parent: ChainState,
        *,
        preferred_next_api: Optional[str] = None,
        hypothesis_id: Optional[str] = None,
        planned_path: Optional[List[str]] = None,
    ) -> Optional[ChainState]:
        """Branch from seed with alternate first-hop preference (beam diversification)."""
        if not preferred_next_api and not hypothesis_id:
            return None
        fork_id = stable_id('chain', parent.seed_api_id, preferred_next_api or hypothesis_id, 'fork')
        if fork_id in self.chains:
            return self.chains[fork_id]
        child = ChainState(
            parent.seed_api_id,
            path=parent.path,
            domain=parent.domain,
            chain_id=fork_id,
            max_depth=self.max_depth,
        )
        child.parent_chain_id = parent.chain_id
        child.preferred_next_api = preferred_next_api
        child.planned_path = list(planned_path or [])
        child.hypothesis_id = hypothesis_id
        child.available_objects = set(parent.available_objects)
        child.phase = PHASE_EXPAND
        for node in parent.nodes:
            if node.get('role') == 'seed':
                child.push_node(node.get('api_id', ''), node.get('path', ''), role='seed')
                break
        else:
            child.push_node(parent.seed_api_id, parent.path, role='seed')
        child.available_objects = set(parent.available_objects)
        child.last_outcome = parent.last_outcome
        child.business_success_count = parent.business_success_count
        child.object_harvest_count = parent.object_harvest_count
        if parent.last_outcome == 'business_success':
            child.phase = PHASE_EXPAND
        self.chains[child.chain_id] = child
        return child

    def seed_with_branches(
        self,
        api_id: str,
        *,
        path: str,
        domain: str,
        harvested: Optional[List[str]] = None,
        primary_pick: Optional[Dict[str, Any]] = None,
        branch_picks: Optional[List[Dict[str, Any]]] = None,
        max_branches: int = 3,
    ) -> ChainState:
        """Seed primary chain and fork alternate first-hop branches."""
        primary = self.seed_from_atomic(api_id, path=path, domain=domain, harvested=harvested)
        if primary_pick:
            pp = primary_pick.get('planned_path')
            if pp and len(pp) >= 2:
                primary.planned_path = list(pp)
            alt_api = primary_pick.get('api_id')
            if not alt_api and pp and len(pp) >= 2:
                alt_api = pp[1]
            if alt_api and alt_api != api_id:
                primary.preferred_next_api = alt_api
        seen = {primary.chain_id}
        for pick in (branch_picks or [])[:max_branches]:
            alt_api = pick.get('api_id')
            if not alt_api or alt_api == api_id:
                continue
            fork = self.fork_chain(
                primary,
                preferred_next_api=alt_api,
                hypothesis_id=pick.get('hypothesis_id'),
                planned_path=pick.get('planned_path'),
            )
            if fork and fork.chain_id not in seen:
                seen.add(fork.chain_id)
        return primary

    def try_revive_all(self, available: Set[str]) -> int:
        revived = 0
        for chain in self.chains.values():
            if chain.revive_if(available):
                revived += 1
        return revived

    def select_top_b(self) -> List[ChainState]:
        active = [
            c for c in self.chains.values()
            if c.status in {CHAIN_ACTIVE, CHAIN_FINDING}
            or getattr(c, 'escalation_pending', False)
        ]
        active.sort(key=lambda c: c.score(), reverse=True)
        return active[: self.beam_width]

    def quarantine(self, chain_id: str, reason: str, revive: Optional[List[str]] = None) -> None:
        chain = self.chains.get(chain_id)
        if chain:
            chain.quarantine(reason, revive=revive)

    def downrank(self, chain_id: str, penalty: float = 2.0) -> None:
        chain = self.chains.get(chain_id)
        if chain:
            chain.repeated_equivalent += int(penalty)

    def mark_dead(self, chain_id: str, reason: str) -> None:
        chain = self.chains.get(chain_id)
        if chain:
            chain.mark_dead(reason)

    def prune_dead(self) -> None:
        for cid, chain in list(self.chains.items()):
            if chain.auth_failure_count >= 3 and chain.business_success_count == 0:
                chain.mark_dead('auth_exhausted')
            if chain.depth >= self.max_depth and chain.status == CHAIN_ACTIVE:
                chain.mark_completed()

    def all_chains(self) -> List[Dict[str, Any]]:
        return [c.to_dict() for c in self.chains.values()]

    def summary(self) -> Dict[str, Any]:
        by_status: Dict[str, int] = {}
        for c in self.chains.values():
            by_status[c.status] = by_status.get(c.status, 0) + 1
        return {
            'total': len(self.chains),
            'beam_width': self.beam_width,
            'by_status': by_status,
            'top_scores': [
                {'chain_id': c.chain_id, 'domain': c.domain, 'score': c.score(), 'status': c.status}
                for c in sorted(self.chains.values(), key=lambda x: x.score(), reverse=True)[:5]
            ],
        }
