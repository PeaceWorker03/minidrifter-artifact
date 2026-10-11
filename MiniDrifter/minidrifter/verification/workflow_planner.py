# -*- coding: utf-8
"""Workflow linker — rule graph + semantic near-miss + LLM next-hop (A2)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from minidrifter.graph.runtime_demand_graph import (
    LEGACY_PRODUCES,
    PRODUCES_BUSINESS_OBJECT,
    PRODUCES_CAPABILITY,
)
from minidrifter.graph.semantic_workflow_graph import rank_semantic_consumers, list_detail_score
from minidrifter.verification.chain_path_extractor import (
    enumerate_paths_from_seed,
    first_hop_candidates,
    next_from_planned_path,
    match_pattern_paths,
    _is_binding_consumer,
)
from minidrifter.verification.campaign_planner import build_test_case
from minidrifter.verification.frontier_expander import (
    get_required_business_fields,
    _field_set_satisfied,
)
from minidrifter.verification.graph_loader import load_workflow_graph
from minidrifter.verification.object_pool import GLOBAL_CONTEXT_FIELDS
from minidrifter.verification.workflow_schema import workflow_link_from_candidate


def _domain_cluster_boost(from_path: str, candidate_path: str) -> float:
    """Lightweight same-cluster boost without app-specific rules."""
    if not from_path or not candidate_path:
        return 0.0
    fp = from_path.lower().split('/')
    cp = candidate_path.lower().split('/')
    shared = set(fp) & set(cp) - {'wechat', 'api', 'v1', 'v2', ''}
    return min(len(shared) * 1.5, 4.5)


def _account_object_boost(
    candidate: Dict[str, Any],
    object_pool: Dict[str, Any],
) -> float:
    """Prefer consumers whose required fields are confirmed for current account."""
    account = object_pool.get('account_label') or 'A'
    confirmed = set(object_pool.get('confirmed_fields') or [])
    if not confirmed:
        return 0.0
    required = set(candidate.get('required') or [])
    overlap = required & confirmed
    if not overlap:
        return 0.0
    boost = len(overlap) * 0.8
    pools = object_pool.get('pools') or {}
    for field in overlap:
        objs = pools.get(field) or pools.get(field.lower()) or []
        if any(isinstance(o, dict) and o.get('owner_account') == account for o in objs):
            boost += 1.2
    return boost


def _score_candidate(
    candidate: Dict[str, Any],
    *,
    from_path: str,
    object_pool: Dict[str, Any],
    ir_boost: float = 0.0,
) -> float:
    base = float(candidate.get('score') or 0)
    path = candidate.get('path') or ''
    base += _domain_cluster_boost(from_path, path)
    base += _account_object_boost(candidate, object_pool)
    base += ir_boost
    candidate['_planner_total_score'] = round(base, 3)
    return base


def branch_candidates_from_rule_result(
    rule_result: Dict[str, Any],
    *,
    from_path: str,
    object_pool: Dict[str, Any],
    top_k: int = 3,
) -> List[Dict[str, Any]]:
    """Top-K distinct rule/semantic/IR picks for beam fork."""
    pool: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    for source_list in (
        rule_result.get('path_bfs_candidates') or [],
        rule_result.get('rule_candidates') or [],
        rule_result.get('semantic_miss_candidates') or [],
        rule_result.get('ir_candidates') or [],
        rule_result.get('near_miss_candidates') or [],
    ):
        for c in source_list:
            aid = c.get('api_id')
            if not aid or aid in seen or not c.get('template'):
                continue
            ir_boost = float(c.get('ir_score') or 0) * 0.5 if c.get('source') == 'universal_ir' else 0.0
            _score_candidate(c, from_path=from_path, object_pool=object_pool, ir_boost=ir_boost)
            pool.append(c)
            seen.add(aid)
    def _branch_rank(c: Dict[str, Any]) -> float:
        base = float(c.get('_planner_total_score') or c.get('score') or 0)
        if _is_binding_consumer(c.get('path') or ''):
            base += 5.0
        if c.get('planned_path'):
            base += 1.0
        return base

    pool.sort(key=_branch_rank, reverse=True)
    return pool[:top_k]


def _select_hop_pick(
    rule_candidates: List[Dict[str, Any]],
    path_bfs_candidates: List[Dict[str, Any]],
    templates_by_id: Dict[str, Any],
    *,
    preferred_next_api: Optional[str] = None,
    seed_path: str = '',
) -> Dict[str, Any]:
    """Merge rule + BFS candidates; prefer binding-verification hops."""
    pick = rule_candidates[0] if rule_candidates else {}
    pool: List[Dict[str, Any]] = list(rule_candidates)
    for c in path_bfs_candidates:
        if c.get('api_id') and c.get('api_id') not in {x.get('api_id') for x in pool}:
            tpl = templates_by_id.get(c.get('api_id'))
            if tpl:
                pool.append({**c, 'template': tpl})

    if preferred_next_api and pool:
        alt = next((c for c in pool if c.get('api_id') == preferred_next_api), None)
        if alt:
            return alt

    if preferred_next_api and rule_candidates:
        alt = next((c for c in rule_candidates if c.get('api_id') == preferred_next_api), None)
        if alt:
            pick = alt

    def _rank(c: Dict[str, Any]) -> float:
        base = float(c.get('_planner_total_score') or c.get('score') or 0)
        path = c.get('path') or ''
        base += 3.0 if _is_binding_consumer(path) else 0.0
        if str(c.get('candidate_type') or '').startswith('path_bfs'):
            base += 1.0
        return base

    if pool:
        pool.sort(key=_rank, reverse=True)
        pick = pool[0]

    binding_bfs = [
        c for c in path_bfs_candidates
        if _is_binding_consumer(c.get('path') or '') and c.get('api_id')
    ]
    if binding_bfs and not preferred_next_api:
        best_binding = max(binding_bfs, key=lambda c: float(c.get('score') or 0))
        rule_top = rule_candidates[0] if rule_candidates else {}
        if not _is_binding_consumer(rule_top.get('path') or ''):
            tpl = templates_by_id.get(best_binding.get('api_id'))
            if tpl:
                pick = {**best_binding, 'template': tpl, 'candidate_type': best_binding.get('candidate_type') or 'path_bfs_hop2'}
    return pick


def _planned_path_for_pick(
    pick: Dict[str, Any],
    seed_api: Optional[str],
    path_bfs_candidates: List[Dict[str, Any]],
) -> List[str]:
    pp = pick.get('planned_path')
    if pp and len(pp) >= 2:
        return list(pp)
    api = pick.get('api_id')
    if seed_api and api:
        for c in path_bfs_candidates:
            ids = c.get('planned_path') or []
            if len(ids) >= 2 and ids[1] == api:
                return list(ids)
        return [seed_api, api]
    return []


def _load_json(path: Path) -> Any:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding='utf-8'))


def _produces_fields(graph: Dict[str, Any], api_id: str) -> Set[str]:
    fields: Set[str] = set()
    produce_types = {PRODUCES_BUSINESS_OBJECT, PRODUCES_CAPABILITY, LEGACY_PRODUCES}
    for e in graph.get('edges') or []:
        if e.get('type') not in produce_types:
            continue
        if e.get('from') != api_id and e.get('from_api') != api_id:
            continue
        fn = e.get('to_field') or e.get('to')
        if fn and fn not in GLOBAL_CONTEXT_FIELDS:
            fields.add(fn)
    return fields


def _available_fields(
    object_pool: Dict[str, Any],
    last_signals: Dict[str, Any],
    graph: Dict[str, Any],
    last_api: Optional[str],
) -> Set[str]:
    available = set(object_pool.get('frontier_unlocks') or [])
    available |= set(object_pool.get('confirmed_fields') or [])
    available |= set(last_signals.get('harvest') or [])
    if last_api:
        available |= _produces_fields(graph, last_api)
    return available


def _consumers_for_fields(
    graph: Dict[str, Any],
    available_fields: Set[str],
    *,
    exclude_apis: Set[str],
    templates_by_id: Dict[str, Any],
    object_pool: Optional[Dict[str, Any]] = None,
    from_path: str = '',
) -> List[Dict[str, Any]]:
    candidates: List[Dict[str, Any]] = []
    for node in graph.get('api_nodes') or []:
        api_id = node.get('id')
        if not api_id or api_id in exclude_apis:
            continue
        tpl = templates_by_id.get(api_id)
        if not tpl or tpl.get('status') != 'materialized_with_crypto_profile':
            continue
        required = get_required_business_fields(graph, api_id)
        if not required:
            continue
        if not _field_set_satisfied(available_fields, required):
            continue
        overlap = required & available_fields
        if not overlap:
            avail_lower = {a.lower() for a in available_fields}
            overlap = {r for r in required if r.lower() in avail_lower}
        candidates.append({
            'api_id': api_id,
            'path': node.get('path') or tpl.get('path'),
            'required': sorted(required),
            'unlocked_by': sorted(overlap),
            'score': len(overlap) * 10.0 + (tpl.get('_planner_score') or 0),
            'template': tpl,
            'candidate_type': 'rule_exact',
        })
    pool_ctx = object_pool or {}
    for c in candidates:
        sem = list_detail_score(from_path, c.get('path') or '')
        c['semantic_boost'] = sem
        c['score'] = (c.get('score') or 0) + sem * 8.0
        _score_candidate(c, from_path=from_path, object_pool=pool_ctx)
    candidates.sort(key=lambda x: x.get('_planner_total_score', x.get('score', 0)), reverse=True)
    return candidates


def _near_miss_consumers(
    graph: Dict[str, Any],
    available_fields: Set[str],
    *,
    exclude_apis: Set[str],
    templates_by_id: Dict[str, Any],
    max_missing: int = 1,
    limit: int = 8,
) -> List[Dict[str, Any]]:
    near: List[Dict[str, Any]] = []
    for node in graph.get('api_nodes') or []:
        api_id = node.get('id')
        if not api_id or api_id in exclude_apis:
            continue
        tpl = templates_by_id.get(api_id)
        if not tpl or tpl.get('status') != 'materialized_with_crypto_profile':
            continue
        required = get_required_business_fields(graph, api_id)
        if not required:
            continue
        missing = []
        for req in required:
            if req in available_fields:
                continue
            if req.lower() in {a.lower() for a in available_fields}:
                continue
            missing.append(req)
        if not missing or len(missing) > max_missing:
            continue
        near.append({
            'api_id': api_id,
            'path': node.get('path') or tpl.get('path'),
            'required': sorted(required),
            'missing_fields': sorted(missing),
            'score': (tpl.get('_planner_score') or 0) - len(missing) * 5,
            'template': tpl,
            'candidate_type': f'near_miss_{len(missing)}',
        })
    near.sort(key=lambda x: x['score'], reverse=True)
    return near[:limit]


def _rule_plan_next_link(
    pack_dir: Path,
    *,
    chain_nodes: List[Dict[str, Any]],
    object_pool: Dict[str, Any],
    baseline_context: Dict[str, Any],
    last_signals: Dict[str, Any],
    ir_session: Any = None,
    preferred_next_api: Optional[str] = None,
    planned_path: Optional[List[str]] = None,
) -> Dict[str, Any]:
    pack_dir = Path(pack_dir)
    graph = load_workflow_graph(pack_dir) or {}
    tpl_doc = _load_json(pack_dir / 'materialized_api_templates.json') or {}
    templates_by_id = {t.get('api_id'): t for t in (tpl_doc.get('templates') or []) if t.get('api_id')}

    if not last_signals.get('depth_continue') and not last_signals.get('harvest'):
        return {'stop': True, 'reason': 'no_signal_to_extend', 'next_test_cases': []}

    tested_in_chain = {n.get('api_id') for n in chain_nodes if n.get('api_id')}
    last_node = chain_nodes[-1] if chain_nodes else {}
    last_api = last_node.get('api_id')
    from_path = last_node.get('path') or ''
    available = _available_fields(object_pool, last_signals, graph, last_api)

    rule_candidates = _consumers_for_fields(
        graph, available, exclude_apis=tested_in_chain, templates_by_id=templates_by_id,
        object_pool=object_pool, from_path=from_path,
    )
    near_miss_1 = _near_miss_consumers(
        graph, available, exclude_apis=tested_in_chain, templates_by_id=templates_by_id,
        max_missing=1,
    )
    near_miss_2 = _near_miss_consumers(
        graph, available, exclude_apis=tested_in_chain, templates_by_id=templates_by_id,
        max_missing=2, limit=6,
    )
    near_pool = near_miss_1 + [c for c in near_miss_2 if c['api_id'] not in {x['api_id'] for x in near_miss_1}]
    semantic_miss = rank_semantic_consumers(
        from_path, near_pool,
        available_fields=available,
        chain_domain=last_node.get('domain') or 'general',
    ) if near_pool else []

    llm_candidates = rule_candidates + near_miss_1 + semantic_miss

    domain = last_node.get('domain') or 'general'
    seed_api = chain_nodes[0].get('api_id') if chain_nodes else None
    seed_path = (chain_nodes[0].get('path') if chain_nodes else '') or from_path

    # Rule-only multi-hop path extraction from seed (field-bridge BFS)
    path_bfs_candidates: List[Dict[str, Any]] = []
    if seed_api and len(chain_nodes) <= 1:
        baseline_fields = set(baseline_context.get('resolved_fields') or {}) | available
        raw_paths = enumerate_paths_from_seed(
            seed_api, graph, templates_by_id,
            seed_path=seed_path,
            baseline_fields=baseline_fields,
            max_depth=5,
            max_paths=20,
        )
        pattern_paths = match_pattern_paths(seed_path, raw_paths)
        path_bfs_candidates = first_hop_candidates(
            raw_paths,
            exclude_apis=tested_in_chain,
            top_k=5,
            seed_path=seed_path,
        )
        for c in path_bfs_candidates:
            tpl = templates_by_id.get(c.get('api_id'))
            if tpl:
                c['template'] = tpl
        llm_candidates = llm_candidates + [
            c for c in path_bfs_candidates
            if c.get('api_id') not in {x.get('api_id') for x in llm_candidates}
        ]

    # Follow precomputed planned path (beam fork branches)
    if planned_path and len(chain_nodes) >= 1:
        planned_pick = next_from_planned_path(
            planned_path, chain_nodes, templates_by_id=templates_by_id,
        )
        if planned_pick and planned_pick.get('template'):
            tc = build_test_case(
                planned_pick['template'], baseline_context=baseline_context, index=2000 + len(chain_nodes),
            )
            tc['test_stage'] = 'depth_chain'
            tc['chain_role'] = 'consumer'
            tc['planner_source'] = 'planned_path'
            return workflow_link_from_candidate(
                planned_pick, test_cases=[tc], source='planned_path',
                link_hypothesis=f"Planned BFS path hop to {planned_pick.get('path')}",
            ) | {
                'rule_candidates': rule_candidates,
                'path_bfs_candidates': path_bfs_candidates,
                'planned_path': planned_path,
            }

    if ir_session is not None and seed_api:
        hyp_hop = ir_session.next_hypothesis_hop(
            seed_api,
            chain_nodes=chain_nodes,
            available_fields=available,
            templates_by_id=templates_by_id,
            exclude_apis=tested_in_chain,
        )
        if hyp_hop and hyp_hop.get('template'):
            tc = build_test_case(
                hyp_hop['template'], baseline_context=baseline_context, index=2000 + len(chain_nodes),
            )
            tc['test_stage'] = 'depth_chain'
            tc['chain_role'] = 'consumer'
            tc['planner_source'] = 'ir_hypothesis_sequence'
            pick = {
                'api_id': hyp_hop.get('api_id'),
                'path': hyp_hop.get('path'),
                'template': hyp_hop['template'],
                'required': hyp_hop.get('required') or [],
                'unlocked_by': sorted(available),
            }
            return workflow_link_from_candidate(
                pick, test_cases=[tc], source='ir_hypothesis_sequence',
                link_hypothesis=f"IR hypothesis hop to {pick['path']}",
            ) | {
                'rule_candidates': rule_candidates,
                'ir_hypothesis_hop': hyp_hop,
                'path_bfs_candidates': path_bfs_candidates,
            }

    if ir_session is not None:
        from minidrifter.ir.verification_bridge import merge_ir_workflow_candidates
        partial = {
            'stop': not rule_candidates,
            'reason': 'no_linked_consumer' if not rule_candidates else '',
            'rule_candidates': rule_candidates,
            'near_miss_candidates': near_miss_1,
            'near_miss_2': near_miss_2,
            'semantic_miss_candidates': semantic_miss,
            'llm_candidates': llm_candidates,
        }
        partial = merge_ir_workflow_candidates(
            partial, ir_session,
            domain=domain,
            available_fields=available,
            templates_by_id=templates_by_id,
            exclude_apis=tested_in_chain,
        )
        ir_cands = partial.get('ir_candidates') or []
        llm_candidates = llm_candidates + [
            c for c in ir_cands if c.get('api_id') not in {x.get('api_id') for x in llm_candidates}
        ]
        if not rule_candidates and partial.get('ir_frontier_hint'):
            hint = partial['ir_frontier_hint']
            pick = {
                'api_id': hint.get('api_id'),
                'path': hint.get('path'),
                'template': hint.get('template'),
                'required': set(),
                'unlocked_by': sorted(available),
                'score': hint.get('ir_score', 0),
            }
            tc = build_test_case(pick['template'], baseline_context=baseline_context, index=2000 + len(chain_nodes))
            tc['test_stage'] = 'depth_chain'
            tc['chain_role'] = 'consumer'
            tc['planner_source'] = 'universal_ir'
            return workflow_link_from_candidate(
                pick, test_cases=[tc], source='universal_ir',
                link_hypothesis=f"IR chain template hop to {pick['path']}",
            ) | {
                'rule_candidates': rule_candidates,
                'ir_candidates': ir_cands,
                'near_miss_candidates': near_miss_1,
                'semantic_miss_candidates': semantic_miss,
                'llm_candidates': llm_candidates,
            }

    if not rule_candidates:
        return {
            'stop': True,
            'reason': 'no_linked_consumer',
            'available_fields': sorted(available),
            'rule_candidates': rule_candidates,
            'near_miss_candidates': near_miss_1,
            'near_miss_2': near_miss_2,
            'semantic_miss_candidates': semantic_miss,
            'llm_candidates': llm_candidates,
            'missing_materials': sorted({f for c in near_miss_1 for f in c.get('missing_fields') or []}),
            'path_bfs_candidates': path_bfs_candidates,
            'next_test_cases': [],
        }

    pick = _select_hop_pick(
        rule_candidates, path_bfs_candidates, templates_by_id,
        preferred_next_api=preferred_next_api,
        seed_path=seed_path,
    )
    planned = _planned_path_for_pick(pick, seed_api, path_bfs_candidates)
    if planned:
        pick = {**pick, 'planned_path': planned}
    tc = build_test_case(pick['template'], baseline_context=baseline_context, index=2000 + len(chain_nodes))
    tc['test_stage'] = 'depth_chain'
    tc['chain_role'] = 'consumer'
    tc['unlocked_by_fields'] = pick.get('unlocked_by')

    return workflow_link_from_candidate(
        pick,
        test_cases=[tc],
        source='rule_workflow_planner',
        link_hypothesis=f"Consumer {pick['path']} requires {pick.get('required')} ⊆ available",
    ) | {
        'rule_candidates': rule_candidates,
        'near_miss_candidates': near_miss_1,
        'near_miss_2': near_miss_2,
        'semantic_miss_candidates': semantic_miss,
        'llm_candidates': llm_candidates,
        'available_fields': sorted(available),
        'path_bfs_candidates': path_bfs_candidates,
        'planned_path': planned,
        'selected_pick': {'api_id': pick.get('api_id'), 'path': pick.get('path'), 'type': pick.get('candidate_type')},
    }


def plan_next_from_static_chain(
    pack_dir: Path,
    *,
    chain_nodes: List[Dict[str, Any]],
    planned_path: List[str],
    object_pool: Dict[str, Any],
    baseline_context: Dict[str, Any],
    static_hops: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Follow pre-recovered business chain hops when objects are available."""
    if not planned_path or len(planned_path) <= len(chain_nodes):
        return {'status': 'no_static_hop'}
    next_api = planned_path[len(chain_nodes)]
    hop_meta = {}
    if static_hops:
        for h in static_hops:
            if h.get('api_id') == next_api:
                hop_meta = h
                break
    tpl_doc = {}
    tpl_path = Path(pack_dir) / 'materialized_api_templates.json'
    if tpl_path.exists():
        tpl_doc = json.loads(tpl_path.read_text(encoding='utf-8'))
    templates_by_id = {t['api_id']: t for t in (tpl_doc.get('templates') or []) if t.get('api_id')}
    template = templates_by_id.get(next_api)
    if not template:
        return {
            'status': 'blocked_missing_template',
            'source': 'static_business_chain',
            'next_api_id': next_api,
            'missing_fields': hop_meta.get('consumes') or [],
        }
    required = hop_meta.get('consumes') or hop_meta.get('requires') or get_required_business_fields(template)
    available = set(object_pool.get('positive_pool') or {}) | set(object_pool.get('fields') or {})
    for k, v in (object_pool.get('values') or {}).items():
        if v:
            available.add(k)
    missing = [f for f in required if f and not _field_set_satisfied(f, available)]
    if missing:
        return {
            'status': 'blocked_missing_object',
            'source': 'static_business_chain',
            'next_api_id': next_api,
            'missing_fields': missing,
            'recommended_material_request': f'chain_seed_for:{missing[0]}',
        }
    tc = build_test_case(template, baseline_context=baseline_context, index=2000 + len(chain_nodes))
    tc['test_stage'] = 'depth_chain'
    tc['chain_role'] = 'consumer'
    tc['chain_source'] = 'static_business_chain'
    return workflow_link_from_candidate(
        {'api_id': next_api, 'path': template.get('path'), 'template': template, 'candidate_type': 'static_chain'},
        test_cases=[tc],
        source='static_business_chain',
        link_hypothesis=f'Static chain hop {len(chain_nodes)}→{len(chain_nodes)+1}: {next_api}',
    ) | {
        'status': 'ready',
        'planned_path': planned_path,
    }


def plan_next_link(
    pack_dir: Path,
    *,
    chain_nodes: List[Dict[str, Any]],
    object_pool: Dict[str, Any],
    baseline_context: Dict[str, Any],
    last_signals: Dict[str, Any],
    with_llm: bool = False,
    llm_dry_run: bool = False,
    llm_traces: Optional[List[Dict[str, Any]]] = None,
    ir_session: Any = None,
    preferred_next_api: Optional[str] = None,
    planned_path: Optional[List[str]] = None,
    include_planner_meta: bool = False,
    static_hops: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Rule-based next hop; LLM pick among rule + near-miss + semantic + IR candidates."""
    if planned_path and len(planned_path) > len(chain_nodes):
        static = plan_next_from_static_chain(
            pack_dir,
            chain_nodes=chain_nodes,
            planned_path=planned_path,
            object_pool=object_pool,
            baseline_context=baseline_context,
            static_hops=static_hops,
        )
        if static.get('next_test_cases') and not static.get('stop'):
            return static if include_planner_meta else {
                k: v for k, v in static.items()
                if k not in ('rule_candidates', 'near_miss_candidates', 'near_miss_2', 'semantic_miss_candidates')
            }

    rule_result = _rule_plan_next_link(
        pack_dir,
        chain_nodes=chain_nodes,
        object_pool=object_pool,
        baseline_context=baseline_context,
        last_signals=last_signals,
        ir_session=ir_session,
        preferred_next_api=preferred_next_api,
        planned_path=planned_path,
    )

    _meta_keys = (
        'rule_candidates', 'near_miss_candidates', 'near_miss_2',
        'semantic_miss_candidates', 'llm_candidates', 'missing_materials',
    )

    def _strip_meta(result: Dict[str, Any]) -> Dict[str, Any]:
        if include_planner_meta:
            return result
        return {k: v for k, v in result.items() if k not in _meta_keys}

    if not rule_result.get('stop') and rule_result.get('next_test_cases'):
        return _strip_meta(rule_result)

    if not with_llm or llm_dry_run:
        if not rule_result.get('stop'):
            return _strip_meta(rule_result)
        # No exact match — try semantic / near-miss rule pick
        from minidrifter.verification.llm_workflow_miner import mine_workflow_hop
        mined = mine_workflow_hop(
            chain_nodes=chain_nodes,
            rule_candidates=rule_result.get('rule_candidates') or [],
            near_miss_1=rule_result.get('near_miss_candidates') or [],
            near_miss_2=rule_result.get('near_miss_2') or [],
            semantic_miss=rule_result.get('semantic_miss_candidates') or [],
            available_fields=rule_result.get('available_fields') or [],
            with_llm=False,
        )
        if mined.get('stop'):
            out = _strip_meta(rule_result)
            out['frontier_hypothesis'] = mined.get('frontier_hypothesis')
            return out
        pick = mined.get('pick') or {}
        if pick.get('template') and pick.get('missing_fields'):
            return _strip_meta(rule_result)
        if pick.get('template'):
            tc = build_test_case(pick['template'], baseline_context=baseline_context, index=2000 + len(chain_nodes))
            tc['test_stage'] = 'depth_chain'
            tc['chain_role'] = 'consumer'
            return workflow_link_from_candidate(
                pick, test_cases=[tc], source=mined.get('source', 'semantic'),
                link_hypothesis=f"Semantic near-miss hop to {pick.get('path')}",
            ) | {
                'near_miss_candidates': rule_result.get('near_miss_candidates'),
            }
        return _strip_meta(rule_result)

    rule_candidates = rule_result.get('rule_candidates') or []
    near_miss = rule_result.get('near_miss_candidates') or []
    near_miss_2 = rule_result.get('near_miss_2') or []
    semantic = rule_result.get('semantic_miss_candidates') or []

    if rule_result.get('stop') and not (near_miss or near_miss_2 or semantic):
        return _strip_meta(rule_result)

    from minidrifter.verification.llm_workflow_miner import mine_workflow_hop

    mined = mine_workflow_hop(
        chain_nodes=chain_nodes,
        rule_candidates=rule_candidates,
        near_miss_1=near_miss,
        near_miss_2=near_miss_2,
        semantic_miss=semantic,
        available_fields=rule_result.get('available_fields') or [],
        with_llm=True,
    )

    if mined.get('stop'):
        out = _strip_meta(rule_result)
        out['frontier_hypothesis'] = mined.get('frontier_hypothesis')
        out['missing_materials'] = mined.get('acquire_fields') or rule_result.get('missing_materials')
        return out

    pick = mined.get('pick') or (rule_candidates[0] if rule_candidates else {})
    if not pick.get('template'):
        pick = rule_candidates[0] if rule_candidates else {}

    from minidrifter.core.utils import write_json
    from minidrifter.verification.llm_workflow_planner import propose_workflow_link

    llm_pool = rule_result.get('llm_candidates') or rule_candidates + near_miss + semantic
    llm_out = propose_workflow_link(
        Path(pack_dir),
        chain_nodes=chain_nodes,
        object_pool=object_pool,
        baseline_context=baseline_context,
        last_signals=last_signals,
        rule_candidates=llm_pool,
        rule_pick=pick,
        near_miss_candidates=near_miss + near_miss_2 + semantic,
        dry_run=llm_dry_run,
    )

    if llm_out.get('trace') and llm_traces is not None:
        llm_traces.append(llm_out['trace'])

    from minidrifter.verification.llm_health import record_llm_event
    rec = llm_out.get('record') or {}
    record_llm_event(
        Path(pack_dir),
        agent='llm_workflow_planner',
        status=str(rec.get('status') or 'unknown'),
        error=rec.get('error'),
        used_llm=bool(llm_out.get('used_llm_pick')),
    )

    chain_key = chain_nodes[-1].get('api_id') if chain_nodes else 'chain'
    write_json(
        Path(pack_dir) / f'llm_workflow_{chain_key}.json',
        {
            'record': llm_out.get('record'),
            'mined': mined,
            'validation_errors': llm_out.get('validation_errors'),
            'used_llm_pick': llm_out.get('used_llm_pick'),
        },
    )

    link = llm_out.get('link_plan')
    if link and (link.get('next_test_cases') or link.get('stop')):
        out = {k: v for k, v in link.items()}
        out['near_miss_candidates'] = near_miss if link.get('stop') else None
        out['semantic_miss_candidates'] = semantic
        out['llm_candidates'] = llm_pool
        return out

    if pick.get('template') and not pick.get('missing_fields'):
        tc = build_test_case(pick['template'], baseline_context=baseline_context, index=2000 + len(chain_nodes))
        tc['test_stage'] = 'depth_chain'
        return workflow_link_from_candidate(
            pick, test_cases=[tc], source=mined.get('source', 'miner'),
            link_hypothesis=f"LLM/miner hop to {pick.get('path')}",
        ) | {
            'near_miss_candidates': near_miss,
        }

    return _strip_meta(rule_result)
