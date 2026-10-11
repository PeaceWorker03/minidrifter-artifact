# -*- coding: utf-8 -*-
"""Frontier expansion — unlock APIs from harvested business objects."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from minidrifter.graph.runtime_demand_graph import (
    LEGACY_REQUIRES,
    REQUIRES_BUSINESS_OBJECT,
    REQUIRES_CAPABILITY,
    REQUIRES_RUNTIME_CONTEXT,
)
from minidrifter.verification.campaign_planner import build_test_case, score_template, _replay_rank_map, _domain_entry_paths
from minidrifter.verification.graph_loader import load_workflow_graph
from minidrifter.verification.object_pool import GLOBAL_CONTEXT_FIELDS
from minidrifter.verification.safety_policy import evaluate_test_safety

_IGNORED_GRAPH_REQUIRE = frozenset({
    'timestamp', 'timestamps', 'timespan', 'timespanms',
})


def _normalize_require_field(name: str) -> Optional[str]:
    if not name:
        return None
    if name in GLOBAL_CONTEXT_FIELDS:
        return None
    key = name.lower()
    if key in _IGNORED_GRAPH_REQUIRE:
        return None
    if key == 'userid':
        return 'UserId'
    if key == 'orderid':
        return 'OrderId'
    if key == 'openid':
        return 'OpenId'
    return name


def _field_set_satisfied(available: Set[str], required: Set[str]) -> bool:
    if not required:
        return False
    avail = {_normalize_require_field(f) or f for f in available}
    avail |= {f.lower() for f in available}
    for req in required:
        norm = _normalize_require_field(req)
        if norm and norm in avail:
            continue
        if req in avail:
            continue
        if req.lower() in avail:
            continue
        return False
    return True


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _load_json(path: Path) -> Any:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding='utf-8'))


def get_required_business_fields(graph: Dict[str, Any], api_id: str) -> Set[str]:
    fields: Set[str] = set()
    for edge in graph.get('edges') or []:
        etype = edge.get('type') or ''
        if etype == REQUIRES_RUNTIME_CONTEXT:
            continue
        if etype not in {REQUIRES_BUSINESS_OBJECT, REQUIRES_CAPABILITY, LEGACY_REQUIRES}:
            continue
        if edge.get('from') != api_id and edge.get('from_api') != api_id:
            continue
        fname = edge.get('to_field') or edge.get('to')
        norm = _normalize_require_field(fname or '')
        if norm:
            fields.add(norm)
    return fields


def expand_frontier(
    pack_dir: Path,
    *,
    object_pool: Dict[str, Any],
    planner_state: Dict[str, Any],
    baseline_context: Dict[str, Any],
    max_new_tests: int = 10,
    only_safe: bool = True,
) -> Dict[str, Any]:
    pack_dir = Path(pack_dir)
    graph = load_workflow_graph(pack_dir) or {}
    templates_doc = _load_json(pack_dir / 'materialized_api_templates.json') or {}
    templates_by_id = {t.get('api_id'): t for t in (templates_doc.get('templates') or []) if t.get('api_id')}

    confirmed = set(object_pool.get('frontier_unlocks') or object_pool.get('confirmed_fields') or [])
    confirmed -= GLOBAL_CONTEXT_FIELDS
    tested = set(planner_state.get('tested_apis') or [])

    candidates: List[Dict[str, Any]] = []
    replay_ranks = _replay_rank_map(pack_dir)
    entry_paths = _domain_entry_paths(pack_dir)
    field_count = len(baseline_context.get('resolved_fields') or {})

    for node in graph.get('api_nodes') or []:
        api_id = node.get('id')
        if not api_id or api_id in tested:
            continue
        tpl = templates_by_id.get(api_id)
        if not tpl or tpl.get('status') != 'materialized_with_crypto_profile':
            continue
        if only_safe and (tpl.get('side_effect_level') or '') not in {'S0_read_only', 'S1_query_like_post'}:
            continue

        required = get_required_business_fields(graph, api_id)
        if required and not _field_set_satisfied(confirmed, required):
            continue
        if not required and not confirmed:
            continue

        score = score_template(
            tpl,
            replay_ranks=replay_ranks,
            entry_paths=entry_paths,
            baseline_field_count=field_count,
        )
        candidates.append({
            'api_id': api_id,
            'path': node.get('path') or tpl.get('path'),
            'score': score,
            'required_business_fields': sorted(required),
            'unlocked_by': sorted(confirmed & required) if required else sorted(confirmed)[:5],
        })

    candidates.sort(key=lambda x: x['score'], reverse=True)
    selected = candidates[:max_new_tests]

    next_wave: List[Dict[str, Any]] = []
    for i, cand in enumerate(selected):
        tpl = templates_by_id[cand['api_id']]
        tc = build_test_case(tpl, baseline_context=baseline_context, index=1000 + i)
        tc['test_stage'] = 'frontier_wave'
        tc['mutation_type'] = 'M0_baseline_replay'
        tc['unlocked_by_fields'] = cand.get('unlocked_by')
        verdict = evaluate_test_safety(
            tc, baseline_context=baseline_context, only_safe=only_safe, mode='dry-run',
        )
        if verdict.allowed:
            next_wave.append(tc)

    return {
        'schema_version': '1.0.0',
        'generated_at': _utc_now(),
        'confirmed_business_fields': sorted(confirmed),
        'tested_api_count': len(tested),
        'candidate_count': len(candidates),
        'selected_count': len(selected),
        'next_wave_count': len(next_wave),
        'candidates': selected,
        'next_wave_test_cases': next_wave,
    }
