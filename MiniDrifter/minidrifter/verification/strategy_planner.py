# -*- coding: utf-8 -*-
"""Rule + optional LLM seed test strategy."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from minidrifter.core.utils import write_json
from minidrifter.verification.api_guard_beliefs import ApiGuardBeliefs
from minidrifter.verification.campaign_planner import build_test_case
from minidrifter.verification.credential_probe_planner import plan_intelligent_binding_campaign


def _rule_plan_seed_strategy(
    seed: Dict[str, Any],
    *,
    baseline_context: Dict[str, Any],
    object_pool: Dict[str, Any],
    with_mutations: bool = True,
    ir_card: Optional[Dict[str, Any]] = None,
    guard_beliefs: Optional[ApiGuardBeliefs] = None,
    m0_test_case: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Return test cases for initial seed probe: M0 + intelligent M8/M7 ladder."""

    template = seed.get('template') or {}
    api_id = seed.get('api_id')
    cases: List[Dict[str, Any]] = []

    m0 = m0_test_case or build_test_case(template, baseline_context=baseline_context, index=0)
    m0['test_stage'] = 'seed_baseline'
    m0['seed_id'] = seed.get('seed_id')
    if m0_test_case is None:
        cases.append(m0)

    mutation_cases: List[Dict[str, Any]] = []
    campaign: Optional[Dict[str, Any]] = None
    if with_mutations:
        campaign = plan_intelligent_binding_campaign(
            seed,
            m0,
            baseline_context=baseline_context,
            object_pool=object_pool,
            beliefs=guard_beliefs,
            ir_card=ir_card,
        )
        mutation_cases = list(campaign.get('test_cases') or [])

    if m0_test_case is None:
        cases = [m0] + mutation_cases
    else:
        cases = mutation_cases

    return {
        'seed_id': seed.get('seed_id'),
        'api_id': api_id,
        'path': seed.get('path'),
        'test_cases': ([m0] + mutation_cases) if m0_test_case else cases,
        'mutation_attempts': len(mutation_cases),
        'probe_plan': campaign,
        'source': 'credential_probe_planner' if with_mutations else 'rule_strategy_planner',
    }


def plan_seed_strategy(
    seed: Dict[str, Any],
    *,
    baseline_context: Dict[str, Any],
    object_pool: Dict[str, Any],
    with_mutations: bool = True,
    pack_dir: Optional[Path] = None,
    with_llm: bool = False,
    llm_dry_run: bool = False,
    prior_feedback: Optional[List[Dict[str, Any]]] = None,
    llm_traces: Optional[List[Dict[str, Any]]] = None,
    ir_card: Optional[Dict[str, Any]] = None,
    guard_beliefs: Optional[ApiGuardBeliefs] = None,
    m0_test_case: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    result = _rule_plan_seed_strategy(
        seed, baseline_context=baseline_context, object_pool=object_pool,
        with_mutations=with_mutations, ir_card=ir_card,
        guard_beliefs=guard_beliefs, m0_test_case=m0_test_case,
    )

    if not with_llm or not pack_dir or not with_mutations:
        return result

    cases = result.get('test_cases') or []
    m0 = cases[0] if cases else None
    if not m0:
        return result

    from minidrifter.verification.llm_strategy_planner import (
        materialize_strategy_proposals,
        propose_seed_strategy,
    )

    llm_out = propose_seed_strategy(
        Path(pack_dir), seed,
        baseline_context=baseline_context,
        object_pool=object_pool,
        m0_test_case=m0,
        prior_feedback=prior_feedback,
        dry_run=llm_dry_run,
    )

    if llm_out.get('trace') and llm_traces is not None:
        llm_traces.append(llm_out['trace'])

    if pack_dir:
        write_json(
            Path(pack_dir) / f"llm_strategy_{seed.get('seed_id', 'seed')}.json",
            {
                'record': llm_out.get('record'),
                'validation_errors': llm_out.get('validation_errors'),
                'proposal_count': len(llm_out.get('proposals') or []),
            },
        )

    proposals = llm_out.get('proposals') or []
    if proposals:
        by_id = {t['test_id']: t for t in cases if t.get('test_id')}
        extra, blocked = materialize_strategy_proposals(
            proposals, by_id, object_pool, baseline_context, seed_id=seed.get('seed_id'),
        )
        result['llm_materialization_blocked'] = blocked
        result['llm_proposal_count'] = len(proposals)
        # Dedupe by mutation_type + target_field
        existing = {(c.get('mutation_type'), c.get('target_field')) for c in cases}
        for tc in extra:
            key = (tc.get('mutation_type'), tc.get('target_field'))
            if key not in existing:
                cases.append(tc)
                existing.add(key)
        result['test_cases'] = cases
        result['mutation_attempts'] = len(cases) - 1

    result['source'] = 'rule+llm_strategy_planner' if proposals else result.get('source')
    result['llm_strategy_status'] = (llm_out.get('record') or {}).get('status')
    return result
