# -*- coding: utf-8 -*-
"""Preserve static-only APIs in candidate verification plane."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from minidrifter.materials.intake_param_hints import normalize_api_path
from minidrifter.quality.runtime_reachability.runtime_alias_resolver import (
    alias_trusted_for_material,
)
from minidrifter.quality.runtime_reachability.ui_api_reachability import (
    STATIC_ONLY_REPLAYABLE,
    UNREACHABLE_UNKNOWN,
    assess_api_reachability,
)


def _required_fields_from_chain(chain: Dict[str, Any], api_path: str) -> List[str]:
    norm = normalize_api_path(api_path)
    fields: List[str] = []
    for hop in chain.get('hops') or []:
        if normalize_api_path(hop.get('path') or hop.get('api') or '') != norm:
            continue
        for mp in hop.get('mutation_points') or []:
            f = mp.get('field')
            if f and f not in fields:
                fields.append(str(f))
        for f in hop.get('produces') or []:
            if f and str(f) not in fields:
                fields.append(str(f))
    return fields


def _static_candidate_record(
    api_path: str,
    reach: Dict[str, Any],
    *,
    chain: Optional[Dict[str, Any]] = None,
    material_sources: Optional[List[str]] = None,
) -> Dict[str, Any]:
    ui = reach.get('ui_reachability') or UNREACHABLE_UNKNOWN
    status = 'WAITING_FOR_CAPTURE'
    if ui == STATIC_ONLY_REPLAYABLE:
        status = 'READY_FOR_REPLAY'
    elif ui == UNREACHABLE_UNKNOWN:
        status = 'DEFERRED'

    return {
        'api': normalize_api_path(api_path),
        'ui_reachability': ui,
        'status': 'static_only_candidate',
        'test_status': status,
        'material_sources': [normalize_api_path(x) for x in (material_sources or [])],
        'required_fields': _required_fields_from_chain(chain or {}, api_path),
        'usable_for_capture': reach.get('usable_for_capture', False),
    }


def build_static_candidate_test_plan(
    pack_dir,
    chains: List[Dict[str, Any]],
    *,
    alias_map: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Collect static-only candidates — one reachability pass per unique API."""
    alias_by_static: Dict[str, List[str]] = {}
    for entry in (alias_map or {}).get('aliases') or []:
        s = normalize_api_path(entry.get('static_api') or '')
        r = normalize_api_path(entry.get('runtime_material_api') or '')
        if s and r and alias_trusted_for_material(
            r, entry.get('signals'), from_ui_capture_plan=bool(entry.get('signals', {}).get('from_ui_capture_plan')),
        ):
            alias_by_static.setdefault(s, [])
            if r not in alias_by_static[s]:
                alias_by_static[s].append(r)

    api_chain: Dict[str, Dict[str, Any]] = {}
    for chain in chains:
        for hop in chain.get('hops') or []:
            api = normalize_api_path(hop.get('path') or hop.get('api') or '')
            if api and api not in api_chain:
                api_chain[api] = chain

    items: List[Dict[str, Any]] = []
    for api, chain in api_chain.items():
        reach = assess_api_reachability(
            pack_dir, api, has_material_alias=bool(alias_by_static.get(api)),
        )
        if reach.get('usable_for_capture'):
            continue
        items.append(_static_candidate_record(
            api, reach, chain=chain, material_sources=alias_by_static.get(api),
        ))

    return {
        'schema_version': '1.0.0',
        'candidate_count': len(items),
        'candidates': items,
    }
