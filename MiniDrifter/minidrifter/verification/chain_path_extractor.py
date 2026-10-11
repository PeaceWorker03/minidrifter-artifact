# -*- coding: utf-8
"""Rule-based multi-hop chain path extraction — field-bridge BFS on workflow graph."""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Set, Tuple

from minidrifter.graph.runtime_demand_graph import (
    LEGACY_PRODUCES,
    LEGACY_REQUIRES,
    PRODUCES_BUSINESS_OBJECT,
    PRODUCES_CAPABILITY,
    REQUIRES_BUSINESS_OBJECT,
    REQUIRES_CAPABILITY,
    WORKFLOW_PRODUCE_TYPES,
    WORKFLOW_REQUIRE_TYPES,
)
from minidrifter.graph.semantic_workflow_graph import (
    infer_domain_from_path,
    list_detail_score,
    score_semantic_link,
)
from minidrifter.verification.frontier_expander import get_required_business_fields, _field_set_satisfied
from minidrifter.verification.object_pool import GLOBAL_CONTEXT_FIELDS

_REQUIRE_TYPES = WORKFLOW_REQUIRE_TYPES | {LEGACY_REQUIRES}
_PRODUCE_TYPES = WORKFLOW_PRODUCE_TYPES | {LEGACY_PRODUCES, PRODUCES_BUSINESS_OBJECT, PRODUCES_CAPABILITY}


def _api_id(edge: Dict[str, Any], side: str) -> str:
    if side == 'from':
        return edge.get('from') or edge.get('from_api') or ''
    return edge.get('to') or edge.get('to_api') or ''


def _field(edge: Dict[str, Any], *, edge_type: str = '') -> str:
    et = edge_type or edge.get('type') or ''
    if et in _REQUIRE_TYPES or et in _PRODUCE_TYPES:
        return edge.get('to_field') or edge.get('to') or edge.get('field') or ''
    return edge.get('to_field') or edge.get('from_field') or edge.get('to') or edge.get('field') or ''


def build_field_bridge_index(graph: Dict[str, Any]) -> Tuple[Dict[str, Set[str]], Dict[str, Set[str]]]:
    """field -> producer api_ids, field -> consumer api_ids."""
    producers: Dict[str, Set[str]] = {}
    consumers: Dict[str, Set[str]] = {}
    for edge in graph.get('edges') or []:
        et = edge.get('type') or ''
        fld = _field(edge, edge_type=et)
        if not fld or fld in GLOBAL_CONTEXT_FIELDS:
            continue
        if et in _PRODUCE_TYPES:
            api = _api_id(edge, 'from')
            if api:
                producers.setdefault(fld, set()).add(api)
        elif et in _REQUIRE_TYPES:
            # requires: from=api (consumer), to=field
            api = _api_id(edge, 'from')
            if api:
                consumers.setdefault(fld, set()).add(api)
    return producers, consumers


def build_api_transitions(
    graph: Dict[str, Any],
    *,
    templates_by_id: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """API→API transitions via shared business field (producer output → consumer input)."""
    producers, consumers = build_field_bridge_index(graph)
    tpl = templates_by_id or {}
    nodes = {n.get('id'): n for n in (graph.get('api_nodes') or []) if n.get('id')}
    transitions: List[Dict[str, Any]] = []
    seen: Set[str] = set()

    for field, prod_apis in producers.items():
        for cons_api in consumers.get(field, set()):
            for prod_api in prod_apis:
                if prod_api == cons_api:
                    continue
                key = f'{prod_api}|{field}|{cons_api}'
                if key in seen:
                    continue
                seen.add(key)
                prod_path = (nodes.get(prod_api) or {}).get('path') or (tpl.get(prod_api) or {}).get('path') or ''
                cons_path = (nodes.get(cons_api) or {}).get('path') or (tpl.get(cons_api) or {}).get('path') or ''
                transitions.append({
                    'from_api': prod_api,
                    'to_api': cons_api,
                    'via_field': field,
                    'from_path': prod_path,
                    'to_path': cons_path,
                    'requires': sorted(get_required_business_fields(graph, cons_api)),
                    'produces': sorted(_produces_for_api(graph, prod_api)),
                })
    return transitions


def _produces_for_api(graph: Dict[str, Any], api_id: str) -> Set[str]:
    out: Set[str] = set()
    for edge in graph.get('edges') or []:
        if edge.get('type') not in _PRODUCE_TYPES:
            continue
        if _api_id(edge, 'from') != api_id:
            continue
        fld = _field(edge, edge_type=edge.get('type') or '')
        if fld and fld not in GLOBAL_CONTEXT_FIELDS:
            out.add(fld)
    return out


def _consumer_path_boost(path: str, via_field: str, seed_path: str = '') -> float:
    """Prefer binding-relevant consumers (universal heuristics)."""
    low = (path or '').lower()
    seed_low = (seed_path or '').lower()
    boost = 0.0
    if any(k in low for k in ('userassets', 'user/assets', 'authentication/userassets')):
        boost += 0.65
    if 'validate' in low and ('authentication' in low or 'user/' in low):
        boost += 0.45
    if any(k in low for k in ('validate', 'authentication', 'auth/', 'assets')):
        boost += 0.25
    if any(k in low for k in ('detail', 'byuserid', 'lastdigits')):
        boost += 0.15
    if via_field.lower() in ('userid', 'orderid', 'deviceid'):
        boost += 0.15
    # List→detail semantic match is weaker than binding targets for verification
    if any(k in low for k in ('digitalkey', 'hicar')) and 'device' in seed_low:
        boost -= 0.25
    if any(k in low for k in ('list', 'banner', 'count', 'citylist', 'payment', 'native/miniapp')):
        boost -= 0.15
    return boost


def _object_bridge_score(hops: List[Dict[str, Any]]) -> float:
    """Score path by producer→consumer field bridges (primary) vs path keywords (auxiliary)."""
    score = 0.0
    for hop in hops:
        via = hop.get('via_field') or ''
        if via and via not in GLOBAL_CONTEXT_FIELDS:
            score += 1.0
        produces = hop.get('produces_fields') or []
        requires = hop.get('requires_fields') or []
        if produces and requires:
            score += 0.5
    return score


def _is_binding_consumer(path: str) -> bool:
    low = (path or '').lower()
    return any(k in low for k in (
        'userassets', 'validate', 'authentication', 'lastdigits', 'byuserid',
    ))


def enumerate_paths_from_seed(
    seed_api_id: str,
    graph: Dict[str, Any],
    templates_by_id: Dict[str, Any],
    *,
    seed_path: str = '',
    baseline_fields: Optional[Set[str]] = None,
    max_depth: int = 5,
    max_paths: int = 24,
) -> List[Dict[str, Any]]:
    """BFS multi-hop API paths via field bridges (rule-only chain extraction)."""
    transitions = build_api_transitions(graph, templates_by_id=templates_by_id)
    by_from: Dict[str, List[Dict[str, Any]]] = {}
    for tr in transitions:
        by_from.setdefault(tr['from_api'], []).append(tr)

    seed_path = seed_path or (templates_by_id.get(seed_api_id) or {}).get('path') or ''
    baseline = set(baseline_fields or {'Token', 'UserId'})
    seed_produces = _produces_for_api(graph, seed_api_id)
    initial_fields = baseline | seed_produces

    # BFS state: (current_api, hop_api_ids, accumulated_fields, semantic_score)
    queue: List[Tuple[str, List[str], Set[str], float]] = [
        (seed_api_id, [seed_api_id], initial_fields, 0.0),
    ]
    completed: List[Dict[str, Any]] = []
    seen_states: Set[str] = set()

    while queue:
        current, path, fields, sem_score = queue.pop(0)
        state_key = f"{current}|{'/'.join(path)}"
        if state_key in seen_states:
            continue
        seen_states.add(state_key)

        if len(path) > 1:
            hops_detail = _path_to_hops(path, graph, templates_by_id, transitions)
            obj_score = _object_bridge_score(hops_detail)
            completed.append({
                'path_api_ids': list(path),
                'depth': len(path),
                'semantic_score': round(sem_score, 3),
                'object_chain_score': round(obj_score, 3),
                'terminal_api': current,
                'terminal_path': hops_detail[-1]['path'] if hops_detail else '',
                'hops': hops_detail,
                'fields_at_end': sorted(fields),
            })

        if len(path) >= max_depth:
            continue

        for tr in by_from.get(current, []):
            next_api = tr['to_api']
            if next_api in path:
                continue
            tpl = templates_by_id.get(next_api)
            if not tpl or tpl.get('status') != 'materialized_with_crypto_profile':
                continue
            required = set(tr.get('requires') or [])
            if required and not _field_set_satisfied(fields, required):
                continue
            from_p = tr.get('from_path') or seed_path
            to_p = tr.get('to_path') or ''
            link_sem = score_semantic_link(
                from_p, to_p,
                required=required,
                available=fields,
            ).get('semantic_score', 0) * 0.35
            link_sem += _consumer_path_boost(to_p, tr.get('via_field') or '', seed_path) * 0.25
            link_sem += 1.0
            new_fields = fields | set(tr.get('produces') or []) | {tr.get('via_field', '')}
            new_fields.discard('')
            queue.append((
                next_api,
                path + [next_api],
                new_fields,
                sem_score + float(link_sem),
            ))

    completed.sort(
        key=lambda p: (
            p.get('object_chain_score', 0),
            p['depth'],
            p['semantic_score'],
        ),
        reverse=True,
    )
    # Stratified: ensure shallow hop-2 paths available for beam fork
    by_depth: Dict[int, List[Dict[str, Any]]] = {}
    for p in completed:
        by_depth.setdefault(p['depth'], []).append(p)
    prefill: List[Dict[str, Any]] = []
    for depth in sorted(by_depth.keys()):
        prefill.extend(by_depth[depth][: max(8, max_paths // 4)])
    merged: List[Dict[str, Any]] = []
    seen_keys: Set[tuple] = set()
    for p in prefill + completed:
        key = tuple(p.get('path_api_ids') or [])
        if key in seen_keys:
            continue
        seen_keys.add(key)
        merged.append(p)
        if len(merged) >= max_paths:
            break
    return merged[:max_paths]


def _path_to_hops(
    api_ids: List[str],
    graph: Dict[str, Any],
    templates_by_id: Dict[str, Any],
    transitions: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    nodes = {n.get('id'): n for n in (graph.get('api_nodes') or []) if n.get('id')}
    trans_map = {(t['from_api'], t['to_api']): t for t in transitions}
    hops: List[Dict[str, Any]] = []
    for i, api_id in enumerate(api_ids):
        tpl = templates_by_id.get(api_id) or {}
        path = (nodes.get(api_id) or {}).get('path') or tpl.get('path') or ''
        role = 'seed' if i == 0 else 'consumer'
        via = None
        if i > 0:
            via = (trans_map.get((api_ids[i - 1], api_id)) or {}).get('via_field')
        hops.append({
            'order': i + 1,
            'api_id': api_id,
            'path': path,
            'role': role,
            'via_field': via,
            'produces_fields': sorted(_produces_for_api(graph, api_id)),
            'requires_fields': sorted(get_required_business_fields(graph, api_id)),
        })
    return hops


def first_hop_candidates(
    paths: List[Dict[str, Any]],
    *,
    exclude_apis: Optional[Set[str]] = None,
    top_k: int = 5,
    seed_path: str = '',
) -> List[Dict[str, Any]]:
    """Distinct second-hop APIs from enumerated paths (for beam fork)."""
    exclude = exclude_apis or set()
    ranked: List[Dict[str, Any]] = []
    seen: Set[str] = set()

    def _collect(pool: List[Dict[str, Any]]) -> None:
        for p in sorted(pool, key=lambda x: x.get('semantic_score', 0), reverse=True):
            ids = p.get('path_api_ids') or []
            if len(ids) < 2:
                continue
            hop2 = ids[1]
            if hop2 in seen or hop2 in exclude:
                continue
            seen.add(hop2)
            hop_detail = (p.get('hops') or [{}, {}])[1] if len(p.get('hops') or []) > 1 else {}
            ranked.append({
                'api_id': hop2,
                'path': hop_detail.get('path') or p.get('terminal_path'),
                'score': p.get('semantic_score', 0) + 5.0 + _consumer_path_boost(
                    hop_detail.get('path') or '', hop_detail.get('via_field') or '', seed_path,
                ),
                'candidate_type': 'path_bfs_hop2',
                'planned_path': ids,
                'via_field': hop_detail.get('via_field'),
            })
            if len(ranked) >= top_k:
                return

    # Direct hop-2 paths first (seed → consumer), then longer paths' second hop
    _collect([p for p in paths if p.get('depth') == 2])
    if len(ranked) < top_k:
        _collect([p for p in paths if p.get('depth', 0) > 2])
    return ranked[:top_k]


def next_from_planned_path(
    planned_api_ids: List[str],
    chain_nodes: List[Dict[str, Any]],
    *,
    templates_by_id: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    """Return next hop from precomputed path if fields still align."""
    tested = {n.get('api_id') for n in chain_nodes if n.get('api_id')}
    depth = len(tested)
    if depth >= len(planned_api_ids):
        return None
    next_api = planned_api_ids[depth]
    if next_api in tested:
        return None
    tpl = templates_by_id.get(next_api)
    if not tpl or tpl.get('status') != 'materialized_with_crypto_profile':
        return None
    return {
        'api_id': next_api,
        'path': tpl.get('path'),
        'template': tpl,
        'candidate_type': 'planned_path',
        'score': 50.0,
    }


def match_pattern_paths(
    seed_path: str,
    paths: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Tag paths matching list→detail / profile→query universal patterns."""
    seed_dom = infer_domain_from_path(seed_path)
    tagged: List[Dict[str, Any]] = []
    for p in paths:
        hops = p.get('hops') or []
        if len(hops) < 2:
            continue
        pattern = None
        h0, h1 = hops[0].get('path', ''), hops[1].get('path', '')
        ld = list_detail_score(h0, h1)
        if ld >= 0.55 and infer_domain_from_path(h1) == seed_dom:
            pattern = 'list_to_detail'
        elif len(hops) >= 3:
            pattern = 'list_to_detail_to_action'
        if pattern:
            tagged.append({**p, 'chain_pattern': pattern, 'pattern_boost': ld})
    tagged.sort(key=lambda x: x.get('pattern_boost', 0), reverse=True)
    return tagged


def paths_to_deep_chain_proposals(
    paths: List[Dict[str, Any]],
    *,
    domain: str = 'general',
) -> List[Dict[str, Any]]:
    """Convert enumerated paths to deep_chain_planner proposal format."""
    proposals: List[Dict[str, Any]] = []
    for i, p in enumerate(paths[:8]):
        hops_raw = p.get('hops') or []
        hops = []
        for h in hops_raw:
            hops.append({
                'order': h.get('order'),
                'api_id': h.get('api_id'),
                'path': h.get('path'),
                'role': h.get('role'),
                'requires_fields': h.get('requires_fields') or [],
                'produces_fields': h.get('produces_fields') or [],
                'mutation_stage': 'M0',
                'confidence': 0.65,
            })
        if hops:
            hops[-1]['mutation_stage'] = 'binding_mutation'
        proposals.append({
            'chain_id': f'rule_path_{i}_{p.get("terminal_api", "")[:12]}',
            'domain': domain,
            'goal': 'field_bridge_bfs',
            'hops': hops,
            'revival_if_blocked': [],
            'why_deeper_than_static': f'BFS depth={p.get("depth")} semantic={p.get("semantic_score")}',
            'chain_pattern': p.get('chain_pattern'),
        })
    return proposals
