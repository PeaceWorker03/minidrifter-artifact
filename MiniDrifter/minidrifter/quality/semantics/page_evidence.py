# -*- coding: utf-8 -*-
"""Evidence-graded page–API alignment (P1)."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from minidrifter.materials.intake_param_hints import normalize_api_path
from minidrifter.quality.runtime_reachability.navigation_graph import (
    is_user_facing_page,
    page_role,
)
from minidrifter.quality.semantics.callsite_backtrace import resolve_page_via_callsite_backtrace
from minidrifter.quality.semantics.path_tokens import infer_path_semantic, page_token_overlap

EVIDENCE_WEIGHTS = {
    'api_call_site': 0.95,
    'demand_graph_callsite': 0.88,
    'semantic_path_rule': 0.38,
    'path_page_hint': 0.35,
    'page_filename_token': 0.82,
    'page_surface_token': 0.40,
}

# Generic path→page hints (replaces per-project hardcoding)
_PATH_PAGE_HINTS = [
    (re.compile(r'orders/description/list|orderquiz/apptag|carsubscription.*order.*list', re.I), 'pages/my/orderList/orderList'),
    (re.compile(r'citylist|city/list', re.I), 'package/common/pages/cityList/index'),
    (re.compile(r'deptlist|dept/list|listandmap', re.I), 'package/order/pages/dept-map/index'),
    (re.compile(r'deptdetail', re.I), 'package/order/pages/deptDetail/index'),
    (re.compile(r'order/list|orderdata/list', re.I), 'pages/shop/orderList'),
    (re.compile(r'order/detail', re.I), 'pages/shop/orderDetail'),
    (re.compile(r'purchased/shop/list', re.I), 'pages/shop/orderList'),
    (re.compile(r'personalcore|user/personal', re.I), 'pages/user/person'),
    (re.compile(r'category/good/list|goods/list', re.I), 'pages/index/customGoodsList'),
]

_GENERIC_SEG = frozenset({
    'list', 'detail', 'info', 'get', 'query', 'index', 'v1', 'v2', 'v3', 'v4',
    'wechat', 'action', 'api', 'resource', 'carrctapi', 'order', 'orders',
})


def _load_json(path: Path) -> Any:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding='utf-8'))


def _page_from_source(source: Dict[str, Any]) -> Optional[str]:
    fpath = (source.get('file') or '').replace('\\', '/')
    if fpath.startswith('pages/') or fpath.startswith('package/') or fpath.startswith('third-platform/'):
        return fpath.rsplit('.', 1)[0]
    m = re.search(r'((?:pages|package|third-platform)/[\w./-]+)', fpath)
    return m.group(1).rstrip('/') if m else None


def _url_matches_api(url: str, norm_path: str, tokens: set) -> bool:
    if not url or len(url) < 8:
        return False
    if url == norm_path or norm_path in url:
        return True
    tail = norm_path.rsplit('/', 1)[-1]
    if tail and len(tail) > 2 and tail in url:
        return True
    matched = sum(1 for t in tokens if len(t) > 3 and t in url)
    return matched >= 2


def page_matches_api(page: str, semantic: Dict[str, Any]) -> bool:
    page_low = (page or '').lower()
    if not page_low:
        return False
    if 'sub-vendor' in page_low:
        return False
    if page_token_overlap(page, semantic) >= 0.45:
        return True
    api_tail = (semantic.get('api_tail') or '').lower()
    return bool(api_tail and api_tail in page_low)


def resolve_page_evidence_graded(
    pack_dir: Path,
    api_path: str,
    *,
    api_id: Optional[str] = None,
    semantic: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    """Rank page candidates with graded evidence sources."""
    pack_dir = Path(pack_dir)
    norm = normalize_api_path(api_path)
    semantic = semantic or infer_path_semantic(api_path)
    tokens = set(semantic.get('path_tokens') or [])
    candidates: List[Tuple[float, str, str, Dict[str, Any]]] = []

    for pat, hint_page in _PATH_PAGE_HINTS:
        if pat.search(norm):
            candidates.append((EVIDENCE_WEIGHTS['path_page_hint'], hint_page, 'path_page_hint', {'pattern': pat.pattern[:40]}))

    if semantic.get('rule_matched'):
        for pg in _pages_from_surface(pack_dir):
            ov = page_token_overlap(pg, semantic)
            if ov >= 0.40:
                candidates.append((EVIDENCE_WEIGHTS['semantic_path_rule'] * ov, pg, 'semantic_path_rule', {'overlap': ov}))

    calls = _load_json(pack_dir / 'api_call_sites.json') or []
    if isinstance(calls, dict):
        calls = calls.get('api_call_sites') or calls.get('calls') or []
    for call in calls:
        url = normalize_api_path((call.get('resolved_url') or call.get('url') or '').split('?', 1)[0])
        if not _url_matches_api(url, norm, tokens):
            continue
        from minidrifter.quality.semantics.callsite_backtrace import collect_callsite_page_candidates, project_root_from_pack
        for conf, pg, ev, meta in collect_callsite_page_candidates(
            call, pack_dir=pack_dir, norm_api=norm, semantic=semantic,
            project_root=project_root_from_pack(pack_dir),
        ):
            gate = 0.35 if ev.startswith('chunk_') or ev == 'offset_local_snippet' else 0.45
            if page_token_overlap(pg, semantic) >= gate or ev in {'api_call_site_direct', 'registry_callsite_source'}:
                candidates.append((conf, pg, ev, meta))

    if api_id:
        full = _load_json(pack_dir / 'runtime_demand_graph.full.json') or {}
        for edge in full.get('edges') or []:
            if edge.get('from_api') != api_id and edge.get('from') != api_id:
                continue
            for ref in edge.get('evidence_refs') or []:
                if not isinstance(ref, str) or not ref.startswith('callsite:'):
                    continue
                m = re.search(r'((?:pages|package|third-platform)/[^:]+)\.js', ref.replace('\\', '/'))
                if m:
                    page = m.group(1)
                    if page_matches_api(page, semantic):
                        candidates.append((EVIDENCE_WEIGHTS['demand_graph_callsite'], page, 'demand_graph_callsite', {}))

    for pg in _pages_from_surface(pack_dir):
        ov = page_token_overlap(pg, semantic)
        if ov >= 0.42:
            candidates.append((EVIDENCE_WEIGHTS['page_surface_token'] * ov, pg, 'page_surface_token', {'overlap': ov}))
        fname = pg.rsplit('/', 1)[-1].lower()
        if fname in tokens or any(t in fname for t in semantic.get('page_tokens') or []):
            candidates.append((EVIDENCE_WEIGHTS['page_filename_token'], pg, 'page_filename_token', {'file': fname}))

    if not candidates:
        p3 = resolve_page_via_callsite_backtrace(
            pack_dir, api_path, api_id=api_id, semantic=semantic,
        )
        if p3:
            return p3
        return None
    candidates.sort(key=lambda x: x[0], reverse=True)
    best_score, page, evidence, meta = candidates[0]
    overlap = page_token_overlap(page, semantic)
    p3_evidence = evidence.startswith('chunk_') or evidence in {
        'offset_local_snippet', 'registry_callsite_source', 'demand_graph_callsite_soft',
    }
    if overlap < 0.45 and not p3_evidence and evidence != 'page_surface_token':
        for score, pg, ev, m in candidates[1:]:
            if page_matches_api(pg, semantic):
                best_score, page, evidence, meta = score, pg, ev, m
                break
    role = page_role(page)
    strong = evidence in {
        'api_call_site_direct', 'registry_callsite_source',
        'chunk_require_backtrace', 'chunk_id_backtrace', 'offset_local_snippet',
    }
    return {
        'page': page,
        'evidence': evidence,
        'confidence': round(min(best_score, 0.99), 2),
        'evidence_meta': meta,
        'graded': True,
        'page_role': role,
        'usable_for_capture': (
            role == 'user_page'
            and is_user_facing_page(page)
            and strong
            and best_score >= 0.80
        ),
    }


def resolve_event_evidence_graded(
    pack_dir: Path,
    page_id: Optional[str],
    *,
    semantic: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    if not page_id:
        return None
    events = _load_json(pack_dir / 'events.json') or []
    if isinstance(events, dict):
        events = events.get('events') or events.get('items') or []
    page_low = page_id.lower()
    matched: List[Tuple[float, str, str]] = []
    for ev in events:
        pg = str(ev.get('page') or '')
        if pg.lower() != page_low and page_low not in pg.lower() and pg.lower() not in page_low:
            continue
        et = ev.get('event_type') or ''
        handler = (ev.get('handler') or '').lower()
        score = 0.5
        if et in {'onLoad', 'onShow'}:
            score = 0.92
        elif et in {'bindtap', 'bind:tap', 'tap'}:
            score = 0.75
        if any(k in handler for k in ('load', 'init', 'fetch', 'list', 'search', 'select', 'getdata')):
            score += 0.08
        matched.append((score, f'{et}:{handler}' if handler else et, 'events.json'))
    if not matched:
        return None
    matched.sort(key=lambda x: x[0], reverse=True)
    score, event, evidence = matched[0]
    return {'event': event, 'evidence': evidence, 'confidence': round(score, 2), 'graded': True}


def _pages_from_surface(pack_dir: Path) -> List[str]:
    surface = _load_json(pack_dir / 'page_surface.json') or {}
    return [pg.get('page_id') for pg in (surface.get('pages') or []) if pg.get('page_id')]
