# -*- coding: utf-8 -*-
"""Material source alias — runtime UI API supplies fields for static producer API."""
from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

from minidrifter.materials.intake_param_hints import normalize_api_path
from minidrifter.quality.runtime_reachability.navigation_graph import (
    is_user_facing_page,
    project_root_from_pack,
)
from minidrifter.quality.runtime_reachability.ui_api_reachability import (
    assess_api_reachability,
)

_ALIAS_TYPE = 'material_source_alias'

# Generic: max runtime APIs to score per static producer (cost cap).
_MAX_ALIAS_CANDIDATES = 20
_MIN_TOKEN_OVERLAP = 0.30


def _observed_api_path(raw: str) -> str:
    """Strip scheme/host from runtime URL observations."""
    raw = (raw or '').split('?', 1)[0].strip()
    if '://' in raw:
        path = urlparse(raw).path or ''
    else:
        path = raw
    norm = normalize_api_path(path)
    if norm in {'/', ''} or norm.startswith('/http'):
        return ''
    return norm


def alias_trusted_for_material(
    runtime_api: str,
    signals: Optional[Dict[str, Any]] = None,
    *,
    from_ui_capture_plan: bool = False,
) -> bool:
    """Reject token-only or host-prefixed aliases for material unlock."""
    if from_ui_capture_plan:
        return True
    norm = normalize_api_path(runtime_api)
    if '://' in runtime_api or norm.startswith('/http'):
        return False
    sig = signals or {}
    if sig.get('shared_fields'):
        return True
    if float(sig.get('object_field_overlap') or 0) > 0:
        return True
    return False


def _load_json(path: Path) -> Any:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding='utf-8'))


def _path_tokens(path: str) -> Set[str]:
    return {t for t in re.split(r'[/._-]+', normalize_api_path(path).lower()) if len(t) > 2}


def _object_fields_for_api(pack_dir: Path, api_path: str) -> Set[str]:
    fields: Set[str] = set()
    cards = _load_json(pack_dir / 'all_api_cards.json') or _load_json(pack_dir / 'api_cards.json') or []
    if isinstance(cards, dict):
        cards = cards.get('cards') or cards.get('api_cards') or []
    norm = normalize_api_path(api_path)
    for card in cards:
        static = card.get('static') or {}
        ep = static.get('endpoint') or {}
        p = normalize_api_path(ep.get('path') or static.get('path') or '')
        if p != norm:
            continue
        replay = card.get('replay') or {}
        for mp in replay.get('mutation_points') or []:
            if mp.get('field'):
                fields.add(str(mp['field']))
        for f in (replay.get('oracle_hints') or {}).get('object_echo_fields') or []:
            fields.add(str(f))
    return fields


@lru_cache(maxsize=8)
def _runtime_observed_apis_cached(pack_dir_str: str) -> tuple:
    pack_dir = Path(pack_dir_str)
    calls = _load_json(pack_dir / 'api_call_sites.json') or []
    if isinstance(calls, dict):
        calls = calls.get('api_call_sites') or calls.get('calls') or []
    seen: Set[str] = set()
    apis: List[str] = []
    for call in calls:
        url = _observed_api_path(call.get('resolved_url') or call.get('url') or '')
        if not url or url in seen:
            continue
        src = (call.get('source') or {}).get('file') or ''
        if 'common.js' in src.lower() and url.count('/') < 3:
            continue
        seen.add(url)
        apis.append(url)
    return tuple(apis)


def _runtime_observed_apis(pack_dir: Path) -> List[str]:
    return list(_runtime_observed_apis_cached(str(Path(pack_dir).resolve())))


def _candidate_runtime_apis(static_api: str, observed: List[str]) -> List[str]:
    """Generic path-token filter — no per-project rules."""
    s_tok = _path_tokens(static_api)
    if not s_tok:
        return observed[:_MAX_ALIAS_CANDIDATES]
    scored: List[tuple] = []
    for runtime_api in observed:
        if runtime_api == normalize_api_path(static_api):
            continue
        r_tok = _path_tokens(runtime_api)
        overlap = len(s_tok & r_tok) / max(len(s_tok | r_tok), 1)
        if overlap >= _MIN_TOKEN_OVERLAP:
            scored.append((overlap, runtime_api))
    scored.sort(reverse=True)
    return [api for _, api in scored[:_MAX_ALIAS_CANDIDATES]]


def score_material_alias(
    pack_dir: Path,
    static_api: str,
    runtime_api: str,
    *,
    s_fields: Optional[Set[str]] = None,
) -> Dict[str, Any]:
    """Cheap alias score — no per-pair reachability scan."""
    pack_dir = Path(pack_dir)
    s_norm = normalize_api_path(static_api)
    r_norm = normalize_api_path(runtime_api)
    if s_norm == r_norm:
        return {'alias_score': 0.0, 'signals': {}}

    s_tok = _path_tokens(s_norm)
    r_tok = _path_tokens(r_norm)
    overlap = len(s_tok & r_tok) / max(len(s_tok | r_tok), 1)

    s_fields = s_fields if s_fields is not None else _object_fields_for_api(pack_dir, s_norm)
    r_fields = _object_fields_for_api(pack_dir, r_norm)
    field_overlap = len(s_fields & r_fields) / max(len(s_fields), 1) if s_fields else 0.0

    rule_match = overlap >= 0.45
    same_domain = (
        s_norm.split('/')[1:3] == r_norm.split('/')[1:3]
        if len(s_norm.split('/')) > 2 else False
    )

    score = 0.0
    if rule_match:
        score += 0.35
    score += 0.25 * overlap
    score += 0.30 * field_overlap
    if same_domain:
        score += 0.10
    score += 0.15  # runtime_api comes from observed callsite list

    return {
        'alias_score': round(min(score, 0.99), 2),
        'signals': {
            'path_token_overlap': round(overlap, 2),
            'object_field_overlap': round(field_overlap, 2),
            'shared_fields': sorted(s_fields & r_fields),
            'same_business_domain': same_domain,
            'runtime_observed': True,
            'rule_match': rule_match,
        },
        'alias_type': _ALIAS_TYPE,
    }


_ALIAS_CACHE: Dict[str, List[Dict[str, Any]]] = {}


def resolve_material_aliases(
    pack_dir: Path,
    static_api: str,
    *,
    min_score: float = 0.65,
) -> List[Dict[str, Any]]:
    """Find runtime APIs that can supply materials for a static producer."""
    pack_dir = Path(pack_dir)
    s_norm = normalize_api_path(static_api)
    cache_key = f'{pack_dir.resolve()}::{s_norm}'
    if cache_key in _ALIAS_CACHE:
        return list(_ALIAS_CACHE[cache_key])

    observed = _runtime_observed_apis(pack_dir)
    candidates = _candidate_runtime_apis(s_norm, observed)
    s_fields = _object_fields_for_api(pack_dir, s_norm)

    scored_pairs: List[Dict[str, Any]] = []
    for runtime_api in candidates:
        scored = score_material_alias(pack_dir, s_norm, runtime_api, s_fields=s_fields)
        if scored['alias_score'] < min_score:
            continue
        if not alias_trusted_for_material(runtime_api, scored.get('signals')):
            continue
        scored_pairs.append({'runtime_api': runtime_api, **scored})

    scored_pairs.sort(key=lambda x: x['alias_score'], reverse=True)
    aliases: List[Dict[str, Any]] = []
    for item in scored_pairs[:3]:
        runtime_api = item['runtime_api']
        aliases.append({
            'static_api': s_norm,
            'runtime_material_api': runtime_api,
            'alias_type': _ALIAS_TYPE,
            'confidence': item['alias_score'],
            'signals': item['signals'],
            'capture_page': None,
            'capture_evidence': None,
            'ui_reachability': None,
        })

    aliases.sort(key=lambda x: x['confidence'], reverse=True)
    result = aliases[:6]
    _ALIAS_CACHE[cache_key] = result
    return list(result)


def build_runtime_alias_map(
    pack_dir: Path,
    static_apis: List[str],
    *,
    ui_capture_plan: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build alias map — prefer captures already planned, resolve rest lazily."""
    entries: List[Dict[str, Any]] = []
    covered_static: Set[str] = set()

    for cap in (ui_capture_plan or {}).get('captures') or []:
        ra = cap.get('runtime_alias') or {}
        static_api = normalize_api_path((cap.get('static_producer') or {}).get('api') or ra.get('from') or '')
        runtime_api = normalize_api_path(cap.get('api') or ra.get('to') or '')
        if not static_api or not runtime_api or static_api == runtime_api:
            continue
        covered_static.add(static_api)
        entries.append({
            'static_api': static_api,
            'runtime_material_api': runtime_api,
            'alias_type': ra.get('alias_type') or _ALIAS_TYPE,
            'shared_fields': ra.get('shared_fields') or cap.get('expected_fields') or [],
            'confidence': ra.get('confidence') or cap.get('confidence'),
            'capture_page': cap.get('page'),
            'signals': {'from_ui_capture_plan': True},
        })

    for api in static_apis:
        norm = normalize_api_path(api)
        if norm in covered_static:
            continue
        reach = assess_api_reachability(pack_dir, norm, has_material_alias=False)
        if reach.get('usable_for_capture'):
            continue
        for alias in resolve_material_aliases(pack_dir, norm)[:2]:
            if not alias_trusted_for_material(
                alias['runtime_material_api'], alias.get('signals'),
            ):
                continue
            entries.append({
                'static_api': alias['static_api'],
                'runtime_material_api': alias['runtime_material_api'],
                'alias_type': alias['alias_type'],
                'shared_fields': alias['signals'].get('shared_fields') or [],
                'confidence': alias['confidence'],
                'capture_page': alias.get('capture_page'),
                'signals': alias['signals'],
            })
            covered_static.add(norm)
            break

    entries.extend(aliases_from_baseline_captures(pack_dir, static_apis, existing=entries))

    return {
        'schema_version': '1.0.0',
        'alias_count': len(entries),
        'aliases': _dedupe_alias_entries(entries),
    }


def aliases_from_baseline_captures(
    pack_dir: Path,
    static_apis: List[str],
    *,
    existing: Optional[List[Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    """Infer runtime material aliases from decrypted baseline intake captures."""
    pack_dir = Path(pack_dir)
    report = _load_json(pack_dir / 'baseline_intake_report.json') or {}
    if not report.get('captures'):
        return []

    plan = _load_json(pack_dir / 'chain_material_request_plan.json') or {}
    target_fields: Set[str] = set()
    static_targets: Dict[str, Set[str]] = {}
    for req in plan.get('requests') or []:
        fields = set(req.get('target_fields') or []) | set(req.get('binding_fields') or [])
        target_fields.update(fields)
        for p in req.get('example_paths') or []:
            static_targets.setdefault(normalize_api_path(p), set()).update(fields)

    for static_api in static_apis:
        static_targets.setdefault(normalize_api_path(static_api), set()).update(target_fields)

    covered = {
        (normalize_api_path(e.get('static_api') or ''), normalize_api_path(e.get('runtime_material_api') or ''))
        for e in (existing or [])
    }
    out: List[Dict[str, Any]] = []

    for cap in report.get('captures') or []:
        runtime_api = normalize_api_path(cap.get('path') or '')
        if not runtime_api:
            continue
        resp_fields = set(cap.get('response_fields') or [])
        resp_proc = cap.get('response_crypto_processing') or {}
        resp_fields.update((resp_proc.get('produces_fields') or {}).keys())
        if not resp_fields:
            continue

        for static_api, need_fields in static_targets.items():
            if not static_api or static_api == runtime_api:
                continue
            shared = sorted(resp_fields & (need_fields or target_fields))
            if not shared:
                continue
            key = (static_api, runtime_api)
            if key in covered:
                continue
            covered.add(key)
            out.append({
                'static_api': static_api,
                'runtime_material_api': runtime_api,
                'alias_type': _ALIAS_TYPE,
                'shared_fields': shared,
                'confidence': 0.92 if 'deptId' in shared else 0.85,
                'capture_page': None,
                'signals': {
                    'from_baseline_intake': True,
                    'capture_index': cap.get('capture_index'),
                    'shared_fields': shared,
                },
            })
    return out


def _dedupe_alias_entries(entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen: Set[tuple] = set()
    merged: List[Dict[str, Any]] = []
    for entry in entries:
        key = (
            normalize_api_path(entry.get('static_api') or ''),
            normalize_api_path(entry.get('runtime_material_api') or ''),
        )
        if not key[0] or not key[1] or key in seen:
            continue
        seen.add(key)
        merged.append(entry)
    merged.sort(key=lambda x: float(x.get('confidence') or 0), reverse=True)
    return merged
