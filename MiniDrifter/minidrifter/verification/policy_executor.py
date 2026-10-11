# -*- coding: utf-8 -*-
"""Execute Apex policy actions — shared by replanner and rescue paths."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional

from minidrifter.verification.object_acquisition_planner import plan_acquire_all_missing

def execute_policy_action(
    policy: Dict[str, Any],
    *,
    atomic: Any,
    object_pool: Dict[str, Any],
    workflow_graph: Dict[str, Any],
    templates_by_id: Dict[str, Any],
    pack_dir: Path,
    confidence: Any,
    progress: Any,
    beam: Optional[Any] = None,
    ticket_registry: Optional[Any] = None,
) -> int:
    """Apply one policy dict; return number of concrete side-effects."""
    action = policy.get('action') or ''
    n = 0

    if action == 'acquire_object':
        target = policy.get('target_field')
        plans = plan_acquire_all_missing(
            object_pool, workflow_graph, templates_by_id,
            pack_dir=pack_dir, confidence_tracker=confidence, limit_per_field=3,
        )
        for plan in plans[:3]:
            if target and plan.get('target_field') != target:
                continue
            tpl = plan.get('template')
            if not tpl:
                continue
            atomic.inject_front({
                'seed_id': f"policy_{plan.get('target_field')}_{plan.get('producer_api_id')}",
                'api_id': plan.get('producer_api_id'),
                'path': plan.get('path'),
                'domain': tpl.get('domain', 'general'),
                'priority': plan.get('score', 0) + 3,
                'template': tpl,
            }, boost=plan.get('score', 0))
            progress.acquire(
                target_field=plan.get('target_field') or '?',
                producer_path=plan.get('path') or '?',
                score=plan.get('score') or 0,
            )
            n += 1
            if target:
                break

    elif action == 'exploration_reset':
        progress.emit('POLICY', 'exploration reset - reprioritize atomic queue')
        atomic.reprioritize()
        n += 1

    elif action == 'switch_domain':
        progress.emit('POLICY', 'switch domain breadth - reprioritize atomic queue')
        atomic.reprioritize()
        if beam is not None:
            available = set(object_pool.get('confirmed_fields') or []) | set(object_pool.get('frontier_unlocks') or [])
            beam.try_revive_all(available)
        n += 1

    elif action == 'refresh_baseline':
        progress.emit(
            'POLICY',
            'baseline refresh required',
            field=policy.get('target_field') or 'Token',
            hint='paste new login capture — see blocking_tickets.json',
        )
        if ticket_registry is not None:
            from minidrifter.verification.user_ticket import build_user_ticket
            from minidrifter.verification.resume_manager import build_resume_plan
            from minidrifter.core.utils import write_json

            ticket = build_user_ticket(
                policy=policy,
                attribution={
                    'failure_class': 'auth_expired',
                    'layer': 'L2_auth',
                    'primary_action': 'refresh_baseline',
                    'diagnosis': policy.get('reason') or 'Token 或业务会话已过期',
                },
            )
            ticket_registry.emit(ticket)
            write_json(pack_dir / 'resume_plan.json', build_resume_plan(pack_dir, ticket))
        n += 1

    elif action == 'stop_chain':
        progress.emit('POLICY', 'stop_chain advisory', reason=(policy.get('reason') or '')[:80])

    return n
