# -*- coding: utf-8 -*-
"""Atomic Probe Scheduler — dynamic API priority for single-point verification."""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Set

from minidrifter.core.utils import stable_id
from minidrifter.materials.intake_param_hints import load_intake_report, normalize_api_path
from minidrifter.verification.campaign_planner import (
    _infer_domain,
    build_test_case,
    score_all_templates,
    score_template,
    _replay_rank_map,
    _domain_entry_paths,
)
from minidrifter.verification.pack_loader import is_high_value_produce
from minidrifter.verification.n_tier_scheduler import schedule_boost, should_skip_tier, runtime_tier_for_api
from minidrifter.verification.binding_risk_planner import load_binding_risk_scores, risk_boost_for_api
from minidrifter.business_chain.chain_ranker import load_chain_priority_index
from minidrifter.verification.workflow_planner import _produces_fields


def _binding_risk(template: Dict[str, Any]) -> float:
    params = (template.get('plain_template') or {}).get('params') or template.get('params') or {}
    keys = {str(k).lower() for k in params}
    risk = 0.0
    for hint in ('userid', 'user_id', 'orderid', 'deviceid', 'customerid'):
        if hint in keys:
            risk += 0.25
    return min(risk, 1.0)


def _expected_object_gain(template: Dict[str, Any], graph: Dict[str, Any]) -> float:
    api_id = template.get('api_id')
    if not api_id:
        return 0.0
    produced = _produces_fields(graph, api_id)
    if not produced:
        return 0.1
    gain = sum(0.2 for f in produced if is_high_value_produce(f))
    return min(gain, 1.0)


def _cost_penalty(template: Dict[str, Any]) -> float:
    cost = 0.0
    if template.get('crypto_required'):
        method = (template.get('method') or 'GET').upper()
        if method != 'GET':
            cost += 0.3
    side = template.get('side_effect_level') or (template.get('safety') or {}).get('side_effect') or ''
    if side not in ('S0_read_only', 'S1_query_like_post', ''):
        cost += 0.5
    return min(cost, 1.0)


def compute_priority(
    template: Dict[str, Any],
    *,
    graph: Dict[str, Any],
    confidence: Any,
    domains_seen: Set[str],
    ir_session: Any = None,
    transport_tracker: Any = None,
) -> float:
    api_id = template.get('api_id') or ''
    path = template.get('path') or ''
    domain = template.get('domain') or _infer_domain(path)
    replay_ranks = {}
    static = score_template(
        template,
        replay_ranks=replay_ranks,
        entry_paths=set(),
        baseline_field_count=10,
    ) / 100.0

    expected_success = confidence.expected_success(api_id, domain) if confidence else 0.5
    object_gain = _expected_object_gain(template, graph)
    binding = _binding_risk(template)
    novelty = 0.3 if domain not in domains_seen else 0.0
    failure_pen = confidence.failure_penalty(api_id, domain) if confidence else 0.0
    cost = _cost_penalty(template)

    priority = (
        0.30 * min(static, 1.0)
        + 0.25 * expected_success
        + 0.25 * object_gain
        + 0.20 * binding
        + 0.10 * novelty
        - 0.30 * failure_pen
        - 0.20 * cost
    )
    if ir_session is not None:
        priority += ir_session.priority_boost(api_id)
        priority += schedule_boost(api_id, ir_session=ir_session)
    if transport_tracker is not None:
        path = template.get('path') or ''
        domain = template.get('domain') or _infer_domain(path)
        priority -= transport_tracker.penalty(path, domain)
    return round(priority, 4)


class AtomicProbeScheduler:
    """Priority queue of APIs awaiting atomic M0 probe."""

    def __init__(
        self,
        pack_dir,
        *,
        baseline_context: Dict[str, Any],
        graph: Dict[str, Any],
        confidence: Any,
        only_safe: bool = True,
        limit: int = 80,
        anchor_api_id: Optional[str] = None,
        ir_session: Any = None,
    ) -> None:
        self.pack_dir = pack_dir
        self.baseline_context = baseline_context
        self.graph = graph
        self.confidence = confidence
        self.only_safe = only_safe
        self.ir_session = ir_session
        self.probed: Dict[str, Dict[str, Any]] = {}
        self.domains_seen: Set[str] = set()
        self.intake_paths: Set[str] = set()
        self.transport_tracker: Any = None
        self.risk_scores: Dict[str, float] = load_binding_risk_scores(self.pack_dir)
        self.chain_index: Dict[str, Dict[str, Any]] = load_chain_priority_index(self.pack_dir)

        intake_report = load_intake_report(self.pack_dir)
        for cap in (intake_report or {}).get('captures') or []:
            norm = normalize_api_path(cap.get('path') or '')
            if norm and norm != '/':
                self.intake_paths.add(norm)

        templates = score_all_templates(
            pack_dir, only_safe=only_safe, baseline_context=baseline_context, limit=None,
        )
        self.queue: List[Dict[str, Any]] = []
        for t in templates:
            api_id = t.get('api_id')
            if not api_id:
                continue
            tier = runtime_tier_for_api(ir_session, api_id)
            if should_skip_tier(tier):
                continue
            domain = t.get('domain') or _infer_domain(t.get('path') or '')
            pri = compute_priority(
                t, graph=graph, confidence=confidence,
                domains_seen=self.domains_seen, ir_session=self.ir_session,
                transport_tracker=self.transport_tracker,
            )
            if anchor_api_id and api_id == anchor_api_id:
                pri += 10.0
            cap_path = normalize_api_path(t.get('path') or '')
            intake_anchor = cap_path in self.intake_paths
            if intake_anchor:
                pri += 100.0
            risk = self.risk_scores.get(api_id)
            if risk:
                pri += risk_boost_for_api(self.pack_dir, api_id, max_boost=50.0)
            chain_meta = self.chain_index.get(api_id)
            if chain_meta:
                pri += 30.0 * float(chain_meta.get('max_score') or 0)
                pri += 2.0 * min(int(chain_meta.get('chain_count') or 0), 10)
                pri += 1.5 * min(int(chain_meta.get('risk_hops') or 0), 10)
            self.queue.append({
                'seed_id': stable_id('seed', api_id),
                'api_id': api_id,
                'path': t.get('path'),
                'domain': domain,
                'runtime_tier': tier,
                'priority': pri,
                'template': t,
                'atomic_passed': False,
                'intake_anchor': intake_anchor,
            })
        if self.intake_paths:
            anchors = [x for x in self.queue if x.get('intake_anchor')]
            others = [x for x in self.queue if not x.get('intake_anchor')]
            others.sort(key=lambda x: x.get('priority', 0), reverse=True)
            cap = max(limit, len(anchors))
            self.queue = anchors + others[: max(0, cap - len(anchors))]
        self._resort()

    def _resort(self) -> None:
        self.queue.sort(key=lambda x: x.get('priority', 0), reverse=True)

    def reprioritize(self) -> None:
        for item in self.queue:
            if item.get('api_id') in self.probed:
                continue
            domain = item.get('domain') or 'general'
            item['priority'] = compute_priority(
                item['template'], graph=self.graph, confidence=self.confidence,
                domains_seen=self.domains_seen, ir_session=self.ir_session,
                transport_tracker=self.transport_tracker,
            )
            if item.get('intake_anchor'):
                item['priority'] += 100.0
            aid = item.get('api_id')
            if aid and aid in self.risk_scores:
                item['priority'] += risk_boost_for_api(self.pack_dir, aid, max_boost=50.0)
            if aid and aid in self.chain_index:
                cm = self.chain_index[aid]
                item['priority'] += 30.0 * float(cm.get('max_score') or 0)
                item['priority'] += 2.0 * min(int(cm.get('chain_count') or 0), 10)
        self._resort()

    def pop_next(self) -> Optional[Dict[str, Any]]:
        while self.queue:
            item = self.queue.pop(0)
            api_id = item.get('api_id')
            if api_id in self.probed:
                continue
            self.domains_seen.add(item.get('domain') or 'general')
            return item
        return None

    def mark_probed(
        self,
        api_id: str,
        *,
        outcome: str,
        failure_class: Optional[str] = None,
        harvested: Optional[List[str]] = None,
        path: str = '',
        domain: str = 'general',
    ) -> None:
        passed = outcome == 'business_success'
        self.probed[api_id] = {
            'api_id': api_id,
            'outcome': outcome,
            'atomic_passed': passed,
            'failure_class': failure_class,
        }
        if self.confidence:
            self.confidence.record_atomic_outcome(
                api_id, path=path, domain=domain, outcome=outcome,
                failure_class=failure_class, harvested=harvested,
            )

    def build_atomic_test(self, item: Dict[str, Any], index: int = 0) -> Dict[str, Any]:
        tc = build_test_case(item['template'], baseline_context=self.baseline_context, index=index)
        tc['test_stage'] = 'atomic_probe'
        tc['mutation_type'] = 'M0_baseline_replay'
        tc['seed_id'] = item.get('seed_id')
        tc['domain'] = item.get('domain')
        return tc

    def inject_front(self, item: Dict[str, Any], boost: float = 5.0) -> None:
        api_id = item.get('api_id')
        if api_id in self.probed:
            return
        if self.transport_tracker and self.transport_tracker.should_skip(
            item.get('path') or '', item.get('domain') or 'general',
        ):
            return
        item = {**item, 'priority': item.get('priority', 0) + boost}
        self.queue.insert(0, item)
        self._resort()

    def set_transport_tracker(self, tracker: Any) -> None:
        self.transport_tracker = tracker
        self.reprioritize()

    def record_transport_outcome(
        self,
        *,
        path: str,
        domain: str,
        outcome: str,
        failure_class: Optional[str] = None,
    ) -> None:
        if self.transport_tracker:
            self.transport_tracker.record(
                path=path, domain=domain, outcome=outcome, failure_class=failure_class,
            )
            self.reprioritize()

    def summary(self) -> Dict[str, Any]:
        passed = sum(1 for p in self.probed.values() if p.get('atomic_passed'))
        return {
            'pending': len(self.queue),
            'probed_count': len(self.probed),
            'atomic_passed': passed,
            'next_pending': [
                {'api_id': q.get('api_id'), 'path': q.get('path'), 'priority': q.get('priority')}
                for q in self.queue[:5]
            ],
        }
