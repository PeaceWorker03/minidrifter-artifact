# -*- coding: utf-8 -*-
"""Field-driven capture anchor planning — dual-plane model."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from minidrifter.materials.intake_param_hints import normalize_api_path
from minidrifter.quality.runtime_reachability.navigation_graph import (
    build_navigation_graph,
    is_user_facing_page,
    navigation_steps_to_page,
    project_root_from_pack,
)
from minidrifter.quality.runtime_reachability.runtime_alias_resolver import (
    alias_trusted_for_material,
    build_runtime_alias_map,
    resolve_material_aliases,
)
from minidrifter.quality.runtime_reachability.static_candidate_preserver import (
    build_static_candidate_test_plan,
)
from minidrifter.quality.runtime_reachability.ui_api_reachability import (
    UI_REACHABLE_DIRECT,
    UI_REACHABLE_VIA_ALIAS,
    UI_REACHABLE_WEAK_FALLBACK,
    _has_direct_user_callsite,
    assess_api_reachability,
    clear_reachability_caches,
    usable_for_capture,
)

_MATERIAL_PLAN_PAGE_EVIDENCE = frozenset({
    'api_call_site_direct',
    'events.json',
    'path_page_hint',
    'page_surface',
})


def _load_json(path: Path) -> Any:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding='utf-8'))


def _hop_api(hop: Dict[str, Any]) -> str:
    return normalize_api_path(hop.get('path') or hop.get('api') or '')


def _chain_field_needs(chain: Dict[str, Any]) -> Dict[str, List[str]]:
    """Map field -> APIs that need it in chain."""
    needs: Dict[str, List[str]] = {}
    for hop in chain.get('hops') or []:
        api = _hop_api(hop)
        for mp in hop.get('mutation_points') or []:
            f = mp.get('field')
            if f:
                needs.setdefault(str(f), [])
                if api not in needs[str(f)]:
                    needs[str(f)].append(api)
        for f in hop.get('produces') or []:
            needs.setdefault(str(f), [])
            if api not in needs[str(f)]:
                needs[str(f)].append(api)
    return needs


def _material_request_for_chain(
    pack_dir: Path,
    chain: Dict[str, Any],
    producer: str,
) -> Optional[Dict[str, Any]]:
    """Match chain_material_request_plan entry for producer/chain."""
    plan = _load_json(pack_dir / 'chain_material_request_plan.json') or {}
    cid = chain.get('chain_id')
    norm_prod = normalize_api_path(producer)
    for req in plan.get('requests') or []:
        paths = [
            normalize_api_path(p)
            for p in (req.get('example_paths') or [])
            if p
        ]
        if req.get('chain_id') == cid or norm_prod in paths:
            return req
    return None


def _material_plan_fallback_anchor(
    pack_dir: Path,
    chain: Dict[str, Any],
    producer: str,
    *,
    consumer: Optional[str],
    expected_fields: List[str],
    nav_graph: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    """Weak-evidence fallback from chain_material_request_plan when callsites miss."""
    req = _material_request_for_chain(pack_dir, chain, producer)
    if not req:
        return None
    page = req.get('entry_page') or req.get('page_hint')
    if not page or not is_user_facing_page(page):
        return None
    evidence = (req.get('entry_page_evidence') or '').strip()
    if evidence not in _MATERIAL_PLAN_PAGE_EVIDENCE and evidence:
        return None
    fields = sorted({
        str(f) for f in (
            req.get('expected_response_fields')
            or req.get('target_fields')
            or expected_fields
            or []
        )
        if f
    })
    nav_steps: List[Dict[str, str]] = []
    if nav_graph:
        for step in navigation_steps_to_page(nav_graph, page):
            nav_steps.append({'action': step, 'evidence': 'material_plan_fallback'})
    nav_steps.append({
        'action': (
            f'进入页面 `{page}`（材料计划推断，callsites 未验证，请结合真机 UI 确认）'
        ),
        'evidence': 'material_plan_fallback',
    })
    if req.get('recommended_user_action'):
        nav_steps.append({
            'action': req['recommended_user_action'][:240],
            'evidence': 'material_plan_hint',
        })
    confidence = 0.68 if evidence == 'api_call_site_direct' else 0.55
    unlocks = [producer]
    if consumer:
        unlocks.append(consumer)
    return {
        'capture_anchor': {
            'api': producer,
            'page': page,
            'ui_reachable': True,
            'evidence': 'material_plan_fallback',
            'purpose': f'harvest {", ".join(fields[:6]) or "runtime credentials"}',
            'confidence': confidence,
        },
        'static_producer': {
            'api': producer,
            'ui_reachable': False,
            'evidence': 'material_plan_fallback',
            'status': 'static_only_candidate',
        },
        'consumer': {
            'api': consumer,
            'mutation_field': fields[0] if fields else None,
        },
        'runtime_alias': None,
        'expected_fields': fields or expected_fields,
        'navigation_steps': nav_steps,
        'unlocks_static_candidates': unlocks,
        'usable_for_capture': True,
        'weak_evidence': True,
        'instruction_mode': 'weak_evidence',
    }


def _runtime_proxy_anchor(pack_dir: Path, static_api: str) -> Optional[Dict[str, Any]]:
    """Find runtime material API via proxy rules + page source scan."""
    from minidrifter.business_chain.ui_capture_surface import (
        _find_runtime_proxies,
        _navigation_steps_verified,
        build_navigation_graph as surface_nav_graph,
        project_root_from_pack as surface_root,
    )
    root = surface_root(pack_dir)
    proxies = _find_runtime_proxies(pack_dir, static_api, project_root=root)
    if not proxies:
        return None
    best = proxies[0]
    page = best.get('ui_page')
    nav_graph = surface_nav_graph(root) if root else {}
    nav_steps = [
        {'action': s, 'evidence': 'navigation_verified'}
        for s in _navigation_steps_verified(pack_dir, page or '', nav_graph)
    ]
    return {
        'api': normalize_api_path(best.get('proxy_path') or ''),
        'page': page,
        'evidence': 'runtime_material_alias',
        'confidence': best.get('confidence', 0.75),
        'purpose': best.get('reason', 'runtime proxy'),
        'navigation_steps': nav_steps,
        'alias_type': 'material_source_alias',
    }


_PICK_CACHE: Dict[str, Dict[str, Any]] = {}


def _cache_pick(cache_key: str, result: Dict[str, Any]) -> Dict[str, Any]:
    _PICK_CACHE[cache_key] = result
    return result


def _pick_capture_anchor_for_chain(
    pack_dir: Path,
    chain: Dict[str, Any],
    *,
    nav_graph: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    """Find best UI capture anchor for chain material needs."""
    producer = normalize_api_path(
        (chain.get('hops') or [{}])[0].get('path')
        or (chain.get('hops') or [{}])[0].get('api')
        or chain.get('entry_path') or ''
    )
    cache_key = f'{pack_dir}::{producer}'
    if cache_key in _PICK_CACHE:
        return dict(_PICK_CACHE[cache_key])

    hops = chain.get('hops') or []
    if not hops:
        return None

    producer = normalize_api_path(
        hops[0].get('path') or hops[0].get('api') or chain.get('entry_path') or ''
    )
    consumer = normalize_api_path(
        hops[-1].get('path') or hops[-1].get('api') or ''
    ) if len(hops) > 1 else None
    field_needs = _chain_field_needs(chain)
    expected_fields = sorted(field_needs.keys())

    # 1) Direct UI reachability on producer (indexed callsite check)
    if _has_direct_user_callsite(pack_dir, producer):
        prod_reach = assess_api_reachability(pack_dir, producer)
        best = next((c for c in prod_reach.get('candidates') or [] if usable_for_capture(c)), None)
        if best:
            page = best['page']
            nav_steps = navigation_steps_to_page(nav_graph or {}, page) if nav_graph else []
            return _cache_pick(cache_key, {
                'capture_anchor': {
                    'api': producer,
                    'page': page,
                    'ui_reachable': True,
                    'evidence': best.get('evidence'),
                    'purpose': f'harvest {", ".join(expected_fields[:6]) or "runtime credentials"}',
                    'confidence': best.get('confidence', 0.9),
                },
                'static_producer': {
                    'api': producer,
                    'ui_reachable': True,
                    'evidence': best.get('evidence'),
                    'status': 'ui_direct',
                },
                'consumer': {'api': consumer, 'mutation_field': expected_fields[0] if expected_fields else None},
                'runtime_alias': None,
                'expected_fields': expected_fields,
                'navigation_steps': nav_steps,
                'usable_for_capture': True,
            })

    # 2) Runtime proxy (field-driven material source) — skip slow alias scan if proxy hits
    proxy = _runtime_proxy_anchor(pack_dir, producer)
    if proxy and proxy.get('page') and proxy.get('api'):
        runtime_api = proxy['api']
        unlocks = [producer]
        if consumer:
            unlocks.append(consumer)
        return _cache_pick(cache_key, {
            'capture_anchor': {
                'api': runtime_api,
                'page': proxy['page'],
                'ui_reachable': True,
                'evidence': 'runtime_material_alias',
                'purpose': f'harvest {", ".join(expected_fields[:6]) or "runtime credentials"}',
                'confidence': proxy.get('confidence', 0.75),
            },
            'static_producer': {
                'api': producer,
                'ui_reachable': False,
                'evidence': 'api_definition_only',
                'status': 'static_only_candidate',
            },
            'consumer': {'api': consumer, 'mutation_field': expected_fields[0] if expected_fields else None},
            'runtime_alias': {
                'from': producer,
                'to': runtime_api,
                'alias_type': 'material_source_alias',
                'confidence': proxy.get('confidence', 0.75),
                'shared_fields': expected_fields,
            },
            'expected_fields': expected_fields,
            'navigation_steps': proxy.get('navigation_steps') or [],
            'unlocks_static_candidates': unlocks,
            'usable_for_capture': True,
        })

    # 3) Fallback alias resolver (token overlap, capped)
    for alias in resolve_material_aliases(pack_dir, producer)[:2]:
        runtime_api = alias['runtime_material_api']
        if not alias_trusted_for_material(runtime_api, alias.get('signals')):
            continue
        page = alias.get('capture_page')
        if not page:
            continue
        unlocks = [producer]
        if consumer:
            unlocks.append(consumer)
        return _cache_pick(cache_key, {
            'capture_anchor': {
                'api': runtime_api,
                'page': page,
                'ui_reachable': True,
                'evidence': 'runtime_material_alias',
                'purpose': f'harvest {", ".join((alias.get("signals") or {}).get("shared_fields") or expected_fields[:6])}',
                'confidence': alias['confidence'],
            },
            'static_producer': {
                'api': producer,
                'ui_reachable': False,
                'evidence': 'api_definition_only',
                'status': 'static_only_candidate',
            },
            'consumer': {'api': consumer, 'mutation_field': expected_fields[0] if expected_fields else None},
            'runtime_alias': {
                'from': producer,
                'to': runtime_api,
                'alias_type': alias.get('alias_type') or 'material_source_alias',
                'confidence': alias['confidence'],
                'shared_fields': (alias.get('signals') or {}).get('shared_fields') or [],
            },
            'expected_fields': expected_fields,
            'navigation_steps': navigation_steps_to_page(nav_graph or {}, page) if nav_graph else [],
            'unlocks_static_candidates': unlocks,
            'usable_for_capture': True,
        })

    # 4) Material-plan fallback — weak evidence when callsites/alias miss
    fallback = _material_plan_fallback_anchor(
        pack_dir, chain, producer,
        consumer=consumer,
        expected_fields=expected_fields,
        nav_graph=nav_graph,
    )
    if fallback:
        return _cache_pick(cache_key, fallback)

    # No UI anchor — keep as static candidate (principle 2)
    return _cache_pick(cache_key, {
        'capture_anchor': None,
        'static_producer': {
            'api': producer,
            'ui_reachable': False,
            'evidence': 'api_definition_only',
            'status': 'static_only_candidate',
        },
        'consumer': {'api': consumer, 'mutation_field': expected_fields[0] if expected_fields else None},
        'runtime_alias': None,
        'expected_fields': expected_fields,
        'usable_for_capture': False,
        'unlocks_static_candidates': [producer] + ([consumer] if consumer else []),
    })


def build_ui_capture_plan(
    pack_dir: Path,
    chains: List[Dict[str, Any]],
    *,
    max_captures: int = 12,
    nav_graph: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Dedupe by producer first, then by capture API — field-driven."""
    pack_dir = Path(pack_dir)
    by_api: Dict[str, Dict[str, Any]] = {}

    producers_seen: Set[str] = set()
    for chain in chains:
        producer = normalize_api_path(
            (chain.get('hops') or [{}])[0].get('path')
            or (chain.get('hops') or [{}])[0].get('api')
            or chain.get('entry_path') or ''
        )
        if producer in producers_seen:
            plan = _PICK_CACHE.get(f'{pack_dir}::{producer}')
            if plan and plan.get('usable_for_capture'):
                anchor = plan.get('capture_anchor') or {}
                api = normalize_api_path(anchor.get('api') or '')
                if api in by_api:
                    by_api[api].setdefault('chain_ids', []).append(chain.get('chain_id'))
                    for u in plan.get('unlocks_static_candidates') or []:
                        if u not in by_api[api].get('unlocks_static_candidates', []):
                            by_api[api].setdefault('unlocks_static_candidates', []).append(u)
            continue
        producers_seen.add(producer)
        plan = _pick_capture_anchor_for_chain(pack_dir, chain, nav_graph=nav_graph)
        if not plan or not plan.get('usable_for_capture'):
            continue
        anchor = plan.get('capture_anchor') or {}
        if not anchor.get('api'):
            continue
        api = normalize_api_path(anchor['api'])
        if api in by_api:
            existing = by_api[api]
            for u in plan.get('unlocks_static_candidates') or []:
                if u not in existing.get('unlocks_static_candidates', []):
                    existing.setdefault('unlocks_static_candidates', []).append(u)
            existing.setdefault('chain_ids', []).append(chain.get('chain_id'))
            continue
        by_api[api] = {
            'capture_id': f"cap_{api.strip('/').replace('/', '_')[:80]}",
            'api': api,
            'page': anchor.get('page'),
            'ui_reachability': (
                UI_REACHABLE_WEAK_FALLBACK if plan.get('weak_evidence')
                else (UI_REACHABLE_VIA_ALIAS if plan.get('runtime_alias') else UI_REACHABLE_DIRECT)
            ),
            'evidence': anchor.get('evidence'),
            'confidence': anchor.get('confidence'),
            'purpose': anchor.get('purpose'),
            'expected_fields': plan.get('expected_fields') or [],
            'unlocks_static_candidates': plan.get('unlocks_static_candidates') or [
                (plan.get('static_producer') or {}).get('api'),
                (plan.get('consumer') or {}).get('api'),
            ],
            'static_producer': plan.get('static_producer'),
            'consumer': plan.get('consumer'),
            'runtime_alias': plan.get('runtime_alias'),
            'navigation_steps': plan.get('navigation_steps') or [],
            'usable_for_capture': True,
            'weak_evidence': bool(plan.get('weak_evidence')),
            'instruction_mode': plan.get('instruction_mode'),
            'chain_ids': [chain.get('chain_id')],
        }

    if not by_api:
        for chain in chains:
            producer = normalize_api_path(
                (chain.get('hops') or [{}])[0].get('path')
                or (chain.get('hops') or [{}])[0].get('api')
                or chain.get('entry_path') or ''
            )
            if not producer:
                continue
            plan = _PICK_CACHE.get(f'{pack_dir}::{producer}')
            if not plan:
                plan = _pick_capture_anchor_for_chain(pack_dir, chain, nav_graph=nav_graph)
            if not plan or not plan.get('usable_for_capture'):
                continue
            anchor = plan.get('capture_anchor') or {}
            if not anchor.get('api'):
                continue
            api = normalize_api_path(anchor['api'])
            if api in by_api:
                continue
            by_api[api] = {
                'capture_id': f"cap_{api.strip('/').replace('/', '_')[:80]}",
                'api': api,
                'page': anchor.get('page'),
                'ui_reachability': UI_REACHABLE_WEAK_FALLBACK,
                'evidence': anchor.get('evidence'),
                'confidence': anchor.get('confidence'),
                'purpose': anchor.get('purpose'),
                'expected_fields': plan.get('expected_fields') or [],
                'unlocks_static_candidates': plan.get('unlocks_static_candidates') or [],
                'static_producer': plan.get('static_producer'),
                'consumer': plan.get('consumer'),
                'runtime_alias': plan.get('runtime_alias'),
                'navigation_steps': plan.get('navigation_steps') or [],
                'usable_for_capture': True,
                'weak_evidence': bool(plan.get('weak_evidence')),
                'instruction_mode': plan.get('instruction_mode'),
                'chain_ids': [chain.get('chain_id')],
            }

    captures = sorted(by_api.values(), key=lambda x: x.get('confidence', 0), reverse=True)[:max_captures]
    return {
        'schema_version': '1.0.0',
        'plane': 'UI_MATERIAL',
        'capture_count': len(captures),
        'captures': captures,
    }


def build_dual_plane_plans(
    pack_dir: Path,
    *,
    max_captures: int = 12,
    top_chains: int = 12,
) -> Dict[str, Any]:
    """Orchestrate dual-plane artifacts from business chains."""
    pack_dir = Path(pack_dir)
    clear_reachability_caches()
    _PICK_CACHE.clear()
    chains_data = _load_json(pack_dir / 'business_chains.json') or {}
    chains = chains_data.get('chains') or (chains_data if isinstance(chains_data, list) else [])
    if not chains:
        return {'ui_capture_plan': {}, 'static_candidate_test_plan': {}, 'runtime_alias_map': {}}

    rank_doc = _load_json(pack_dir / 'chain_rank_plan.json') or {}
    chains_by_id = {c['chain_id']: c for c in chains if c.get('chain_id')}
    ranked_ids = [t['chain_id'] for t in (rank_doc.get('top_chains') or []) if t.get('chain_id')]
    ranked = [chains_by_id[cid] for cid in ranked_ids if cid in chains_by_id]
    if not ranked:
        ranked = sorted(
            chains,
            key=lambda c: float(c.get('chain_score') or c.get('score') or 0),
            reverse=True,
        )
    ranked = ranked[:top_chains]

    root = project_root_from_pack(pack_dir)
    nav_graph = {}  # proxy path supplies navigation; skip full graph scan

    ui_plan = build_ui_capture_plan(pack_dir, ranked, max_captures=max_captures, nav_graph=nav_graph)

    static_apis: List[str] = []
    for c in ranked:
        for hop in c.get('hops') or []:
            api = _hop_api(hop)
            if api:
                static_apis.append(api)

    alias_map = build_runtime_alias_map(
        pack_dir, list(dict.fromkeys(static_apis)), ui_capture_plan=ui_plan,
    )
    static_plan = build_static_candidate_test_plan(pack_dir, ranked, alias_map=alias_map)

    return {
        'ui_capture_plan': ui_plan,
        'static_candidate_test_plan': static_plan,
        'runtime_alias_map': alias_map,
        'navigation_graph_summary': {
            'entry_page': (nav_graph.get('entry_page') if nav_graph else None),
            'edge_count': (nav_graph.get('edge_count', 0) if nav_graph else 0),
        },
    }


def write_dual_plane_artifacts(pack_dir: Path, plans: Optional[Dict[str, Any]] = None) -> Dict[str, Path]:
    """Write ui_capture_plan.json, static_candidate_test_plan.json, runtime_alias_map.json."""
    pack_dir = Path(pack_dir)
    if plans is None:
        plans = build_dual_plane_plans(pack_dir)

    paths = {}
    for name in ('ui_capture_plan', 'static_candidate_test_plan', 'runtime_alias_map'):
        data = plans.get(name) or {}
        out = pack_dir / f'{name}.json'
        out.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')
        paths[name] = out
    return paths
