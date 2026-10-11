# -*- coding: utf-8 -*-
"""Resolve adapter profile for a verification pack directory."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional

from minidrifter.adapters.registry import load_profile

_PROFILES_ROOT = Path(__file__).resolve().parents[2] / 'packs' / 'profiles'


def _load_json(path: Path) -> Any:
    if path.exists():
        return json.loads(path.read_text(encoding='utf-8'))
    return None


def _read_profile_raw(profile_id: str) -> Dict[str, Any]:
    path = _PROFILES_ROOT / f'{profile_id}.json'
    if path.exists():
        return json.loads(path.read_text(encoding='utf-8'))
    return {}


def _profile_id_by_alias(*candidates: str) -> Optional[str]:
    """Match pack folder name / miniapp id against profile pack_aliases (no app hardcoding)."""
    keys = {c.lower() for c in candidates if c}
    if not keys:
        return None
    for path in sorted(_PROFILES_ROOT.glob('*.json')):
        raw = json.loads(path.read_text(encoding='utf-8'))
        aliases = {str(a).lower() for a in (raw.get('pack_aliases') or [])}
        pid = (raw.get('profile_id') or path.stem).lower()
        if keys & (aliases | {pid}):
            return raw.get('profile_id') or path.stem
    return None


def default_output_slug(*candidates: str) -> str:
    """Map project/pack name to sample_outputs folder slug via profile pack_aliases."""
    import re

    hit = _profile_id_by_alias(*candidates)
    if hit:
        return hit
    raw = next((c for c in candidates if c), 'pack')
    slug = re.sub(r'[^\w\-]+', '_', raw.strip().lower(), flags=re.UNICODE).strip('_')
    return slug or 'pack'


def resolve_pack_profile(pack_dir: Path, *, profile_id: Optional[str] = None) -> Dict[str, Any]:
    """Pick profile from explicit id, pack_aliases, project shape, or surface_shape."""
    if profile_id:
        return load_profile(profile_id)

    pack_dir = Path(pack_dir)
    name = pack_dir.name.lower()

    alias_hit = _profile_id_by_alias(name, name.replace('-', '_'))
    if alias_hit:
        return load_profile(alias_hit)

    prof = _load_json(pack_dir / 'project_profile.json') or {}
    dash = _load_json(pack_dir / 'project_dashboard.json') or {}
    dedup = _load_json(pack_dir / 'dedup_report.json') or {}
    template = _load_json(pack_dir / 'baseline_material_template.json') or {}

    miniapp = (template.get('miniapp') or template.get('pack_id') or '').lower()
    alias_hit = _profile_id_by_alias(miniapp, name)
    if alias_hit:
        return load_profile(alias_hit)

    shape = prof.get('shape') or dash.get('shape') or ''
    surface = dedup.get('surface_shape') or ''

    if shape == 'app_service_bundle' or surface == 'bundle_inline':
        return load_profile('bundle_inline_service')
    if shape == 'decompiled_config_based' or surface == 'registry_rich':
        return load_profile('registry_rich_crypto')

    if (_PROFILES_ROOT / f'{name}.json').exists():
        return load_profile(name)

    return load_profile('default')


def write_adapter_resolution(pack_dir: Path, *, profile_id: Optional[str] = None) -> Dict[str, Any]:
    """Write adapter_profile.json sidecar for a pack."""
    from minidrifter.core.utils import write_json

    pack_dir = Path(pack_dir)
    profile = resolve_pack_profile(pack_dir, profile_id=profile_id)
    prof_doc = _load_json(pack_dir / 'project_profile.json') or {}
    dedup = _load_json(pack_dir / 'dedup_report.json') or {}
    host_doc = _load_json(pack_dir / 'host_resolution.json') or {}

    business_hosts = [
        h.get('host') for h in (host_doc.get('host_pools') or {}).get('business_explicit') or []
        if h.get('host')
    ]
    if host_doc.get('authoritative_business_host'):
        business_hosts.insert(0, host_doc['authoritative_business_host'])
    elif host_doc.get('default_business_host'):
        business_hosts.insert(0, host_doc['default_business_host'])

    doc = {
        'schema_version': '1.0.0',
        'profile_id': profile.get('profile_id'),
        'display_name': profile.get('display_name'),
        'project_adapter': profile.get('project_adapter'),
        'request_adapter': profile.get('request_adapter'),
        'crypto_profile': profile.get('crypto_profile'),
        'runtime_adapter': profile.get('runtime_adapter'),
        'benchmark_tier': profile.get('benchmark_tier'),
        'oracle_pack': profile.get('oracle_pack') or profile.get('response_oracle_pack'),
        'shape': prof_doc.get('shape'),
        'surface_shape': dedup.get('surface_shape'),
        'host_hints': list(dict.fromkeys((profile.get('host_hints') or []) + business_hosts[:5])),
        'path_prefix_hosts': profile.get('path_prefix_hosts') or host_doc.get('path_prefix_map') or {},
        'host_resolution_strategy': host_doc.get('host_resolution_strategy'),
        'runtime_dynamic_host': host_doc.get('runtime_dynamic_host'),
    }
    write_json(pack_dir / 'adapter_profile.json', doc)
    return doc
