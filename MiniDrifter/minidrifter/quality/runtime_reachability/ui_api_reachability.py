# -*- coding: utf-8 -*-
"""UI reachability classification for APIs — dual-plane model."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from minidrifter.materials.intake_param_hints import normalize_api_path
from minidrifter.quality.runtime_reachability.navigation_graph import (
    is_user_facing_page,
    page_id_from_source_file,
    page_role,
    project_root_from_pack,
)

UI_REACHABLE_DIRECT = 'UI_REACHABLE_DIRECT'
UI_REACHABLE_VIA_WRAPPER = 'UI_REACHABLE_VIA_WRAPPER'
UI_REACHABLE_VIA_ALIAS = 'UI_REACHABLE_VIA_ALIAS'
UI_REACHABLE_WEAK_FALLBACK = 'UI_REACHABLE_WEAK_FALLBACK'
STATIC_ONLY_REPLAYABLE = 'STATIC_ONLY_REPLAYABLE'
STATIC_ONLY_NEEDS_MATERIAL = 'STATIC_ONLY_NEEDS_MATERIAL'
UNREACHABLE_UNKNOWN = 'UNREACHABLE_UNKNOWN'

UI_REACHABILITY = frozenset({
    UI_REACHABLE_DIRECT,
    UI_REACHABLE_VIA_WRAPPER,
    UI_REACHABLE_VIA_ALIAS,
    UI_REACHABLE_WEAK_FALLBACK,
    STATIC_ONLY_REPLAYABLE,
    STATIC_ONLY_NEEDS_MATERIAL,
    UNREACHABLE_UNKNOWN,
})

# Evidence that may NOT drive user capture steps.
_WEAK_CAPTURE_EVIDENCE = frozenset({
    'path_page_hint',
    'page_surface_token',
    'semantic_path_rule',
    'page_filename_token',
    'demand_graph_callsite',
    'demand_graph_callsite_soft',
    'obfuscated_callsite_soft',
    'api_definition_only',
    'bundle_only_callsite',
    'material_plan_fallback',
})

_STRONG_CAPTURE_EVIDENCE = frozenset({
    'api_call_site_direct',
    'registry_callsite_source',
    'navigate_to_call',
    'runtime_material_alias',
    'event_handler_chain',
})

# Backtrace evidence — clue only, not sufficient for capture steps alone.
_BACKTRACE_EVIDENCE = frozenset({
    'chunk_require_backtrace',
    'chunk_id_backtrace',
    'offset_local_snippet',
    'obfuscated_callsite_soft',
    'demand_graph_callsite_soft',
})

_API_LITERAL_RE = re.compile(r'api\s*:\s*["\']([^"\']+)["\']', re.I)
_BUNDLE_MARKERS = ('common.js', 'sub-common/', 'sub-vendors/', 'vendors.js')

_CALLSITE_INDEX: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}
_REACH_CACHE: Dict[str, Dict[str, Any]] = {}


def clear_reachability_caches() -> None:
    """Reset pack-level caches (tests / fresh run)."""
    _CALLSITE_INDEX.clear()
    _REACH_CACHE.clear()


def _callsite_index(pack_dir: Path) -> Dict[str, List[Dict[str, Any]]]:
    key = str(Path(pack_dir).resolve())
    if key in _CALLSITE_INDEX:
        return _CALLSITE_INDEX[key]
    calls = _load_json(pack_dir / 'api_call_sites.json') or []
    if isinstance(calls, dict):
        calls = calls.get('api_call_sites') or calls.get('calls') or []
    idx: Dict[str, List[Dict[str, Any]]] = {}
    for call in calls:
        url = normalize_api_path((call.get('resolved_url') or call.get('url') or '').split('?', 1)[0])
        if url:
            idx.setdefault(url, []).append(call)
    _CALLSITE_INDEX[key] = idx
    return idx


def _load_json(path: Path) -> Any:
    if not path.exists() or path.is_dir():
        return None
    return json.loads(path.read_text(encoding='utf-8'))


def is_weak_evidence(evidence: Optional[str]) -> bool:
    return (evidence or '') in _WEAK_CAPTURE_EVIDENCE


def usable_for_capture(candidate: Dict[str, Any]) -> bool:
    if candidate.get('usable_for_capture') is False:
        return False
    ev = candidate.get('evidence') or ''
    if is_weak_evidence(ev) or ev in _BACKTRACE_EVIDENCE:
        return False
    if page_role(candidate.get('page')) == 'bundle_chunk':
        return False
    if ev == 'api_call_site_direct' and candidate.get('bundle_backtrace'):
        return False
    return bool(candidate.get('usable_for_capture', candidate.get('confidence', 0) >= 0.80))


def _callsites_for_exact_api(pack_dir: Path, api_path: str) -> List[Dict[str, Any]]:
    norm = normalize_api_path(api_path)
    out: List[Dict[str, Any]] = []
    for call in _callsite_index(pack_dir).get(norm, []):
        src = call.get('source') or {}
        out.append({
            'resolved_url': norm,
            'source_file': (src.get('file') or '').replace('\\', '/'),
            'line': src.get('line'),
        })
    return out


def _has_direct_user_callsite(pack_dir: Path, api_path: str) -> bool:
    """O(1) check: API invoked from a user-facing page source file."""
    norm = normalize_api_path(api_path)
    for call in _callsite_index(pack_dir).get(norm, []):
        src_file = ((call.get('source') or {}).get('file') or '').replace('\\', '/')
        if any(m in src_file.lower() for m in _BUNDLE_MARKERS):
            continue
        pg = page_id_from_source_file(src_file)
        if pg and is_user_facing_page(pg):
            return True
    return False


def _api_definition_only(pack_dir: Path, api_path: str) -> bool:
    norm = normalize_api_path(api_path)
    calls = _callsites_for_exact_api(pack_dir, api_path)
    if calls:
        return False
    cards = _load_json(pack_dir / 'all_api_cards.json') or _load_json(pack_dir / 'api_cards.json') or []
    if isinstance(cards, dict):
        cards = cards.get('cards') or cards.get('api_cards') or []
    for card in cards:
        static = card.get('static') or {}
        ep = static.get('endpoint') or {}
        p = normalize_api_path(ep.get('path') or static.get('path') or '')
        if p == norm:
            return True
    return False


def collect_reachability_candidates(
    pack_dir: Path,
    api_path: str,
    *,
    api_id: Optional[str] = None,
    include_weak_hints: bool = False,
) -> List[Dict[str, Any]]:
    """Collect evidence via indexed callsites. Weak hints are opt-in (expensive)."""
    from minidrifter.quality.semantics.path_tokens import infer_path_semantic
    from minidrifter.quality.semantics.callsite_backtrace import (
        collect_callsite_page_candidates,
        project_root_from_pack as p3_root,
    )

    pack_dir = Path(pack_dir)
    norm = normalize_api_path(api_path)
    semantic = infer_path_semantic(api_path)
    candidates: List[Dict[str, Any]] = []
    root = p3_root(pack_dir)

    for call in _callsite_index(pack_dir).get(norm, []):
        src = call.get('source') or {}
        src_file = (src.get('file') or '').replace('\\', '/')
        if any(m in src_file.lower() for m in _BUNDLE_MARKERS):
            if include_weak_hints:
                for conf, pg, ev, meta in collect_callsite_page_candidates(
                    call, pack_dir=pack_dir, norm_api=norm, semantic=semantic, project_root=root,
                ):
                    candidates.append({
                        'page': pg,
                        'evidence': ev,
                        'confidence': round(conf, 2),
                        'usable_for_capture': False,
                        'page_role': page_role(pg),
                        'source_file': src_file,
                        'meta': meta,
                        'bundle_backtrace': True,
                    })
            candidates.append({
                'page': src_file,
                'evidence': 'bundle_only_callsite',
                'confidence': 0.35,
                'usable_for_capture': False,
                'page_role': 'bundle_chunk',
                'source_file': src_file,
            })
            continue
        pg = page_id_from_source_file(src_file)
        if pg and is_user_facing_page(pg):
            candidates.append({
                'page': pg,
                'evidence': 'api_call_site_direct',
                'confidence': 0.95,
                'usable_for_capture': True,
                'page_role': 'user_page',
                'source_file': src_file,
            })

    if include_weak_hints:
        from minidrifter.quality.semantics.page_evidence import resolve_page_evidence_graded
        page_hit = resolve_page_evidence_graded(pack_dir, api_path, api_id=api_id, semantic=semantic)
        if page_hit:
            candidates.append({
                'page': page_hit.get('page'),
                'evidence': page_hit.get('evidence') or 'path_page_hint',
                'confidence': page_hit.get('confidence', 0.4),
                'usable_for_capture': False,
                'page_role': page_role(page_hit.get('page')),
            })

    if _api_definition_only(pack_dir, api_path) and not any(
        c.get('evidence') == 'api_call_site_direct' for c in candidates
    ):
        candidates.append({
            'page': None,
            'evidence': 'api_definition_only',
            'confidence': 0.30,
            'usable_for_capture': False,
            'page_role': 'bundle_chunk',
            'source_file': 'common.js',
        })

    seen: Set[str] = set()
    uniq: List[Dict[str, Any]] = []
    for c in sorted(candidates, key=lambda x: x.get('confidence', 0), reverse=True):
        key = f"{c.get('page')}:{c.get('evidence')}"
        if key in seen:
            continue
        seen.add(key)
        uniq.append(c)
    return uniq


def classify_ui_reachability(
    candidates: List[Dict[str, Any]],
    *,
    has_material_alias: bool = False,
    template_ready: bool = False,
) -> str:
    usable = [c for c in candidates if usable_for_capture(c)]
    if usable:
        ev = usable[0].get('evidence')
        if has_material_alias:
            return UI_REACHABLE_VIA_ALIAS
        if ev == 'api_call_site_direct':
            return UI_REACHABLE_DIRECT
        return UI_REACHABLE_VIA_WRAPPER
    if any(c.get('evidence') == 'api_definition_only' for c in candidates):
        return STATIC_ONLY_NEEDS_MATERIAL if not template_ready else STATIC_ONLY_REPLAYABLE
    if candidates:
        return STATIC_ONLY_NEEDS_MATERIAL
    return UNREACHABLE_UNKNOWN


def assess_api_reachability(
    pack_dir: Path,
    api_path: str,
    *,
    api_id: Optional[str] = None,
    has_material_alias: bool = False,
    template_ready: bool = False,
    include_weak_hints: bool = False,
) -> Dict[str, Any]:
    """Reachability assessment with per-pack caching."""
    pack_key = str(Path(pack_dir).resolve())
    norm = normalize_api_path(api_path)
    cache_key = f'{pack_key}::{norm}::{has_material_alias}::{template_ready}::{include_weak_hints}'
    if cache_key in _REACH_CACHE:
        return dict(_REACH_CACHE[cache_key])

    candidates = collect_reachability_candidates(
        pack_dir, api_path, api_id=api_id, include_weak_hints=include_weak_hints,
    )
    ui_reachability = classify_ui_reachability(
        candidates, has_material_alias=has_material_alias, template_ready=template_ready,
    )
    # Runtime material source: observed in callsites but only in bundle — still valid anchor.
    if (
        has_material_alias
        and ui_reachability in {STATIC_ONLY_NEEDS_MATERIAL, STATIC_ONLY_REPLAYABLE}
        and _callsite_index(pack_dir).get(norm)
    ):
        ui_reachability = UI_REACHABLE_VIA_ALIAS
    best_capture = next((c for c in candidates if usable_for_capture(c)), None)
    result = {
        'api': norm,
        'api_id': api_id,
        'ui_reachability': ui_reachability,
        'candidates': candidates,
        'best_capture_page': (best_capture or {}).get('page'),
        'best_capture_evidence': (best_capture or {}).get('evidence'),
        'usable_for_capture': ui_reachability in {
            UI_REACHABLE_DIRECT, UI_REACHABLE_VIA_WRAPPER, UI_REACHABLE_VIA_ALIAS,
        },
    }
    _REACH_CACHE[cache_key] = result
    return dict(result)
