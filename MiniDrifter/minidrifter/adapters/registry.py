# -*- coding: utf-8
"""Adapter registry — load profiles and delegate to concrete adapters."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional

from minidrifter.adapters.base import CryptoAdapter, ProjectAdapter, RequestAdapter, RuntimeAdapter
from minidrifter.adapters.crypto_profile import PackCryptoAdapter
from minidrifter.adapters.runtime_http import HttpRuntimeAdapter
from minidrifter.adapters.taro_bundle_request import TaroBundleRequestAdapter
from minidrifter.adapters.wechat_bundle import WeChatBundleProjectAdapter
from minidrifter.adapters.wechat_http_wrapper import WeChatHttpWrapperAdapter
from minidrifter.adapters.wechat_miniprogram import WeChatProjectAdapter

_PACKS_ROOT = Path(__file__).resolve().parents[2] / 'packs'


def load_profile(profile_id: str = 'default') -> Dict[str, Any]:
    path = _PACKS_ROOT / 'profiles' / f'{profile_id}.json'
    if not path.exists():
        path = _PACKS_ROOT / 'profiles' / 'default.json'
    if path.exists():
        prof = json.loads(path.read_text(encoding='utf-8'))
        extends = prof.get('extends')
        if extends:
            base = load_profile(extends)
            merged = {**base, **prof}
            merged.pop('extends', None)
            return merged
        return prof
    return {'profile_id': 'default', 'platform': 'wechat', 'project_adapter': 'wechat_miniprogram'}


def get_project_adapter(profile: Optional[Dict[str, Any]] = None) -> ProjectAdapter:
    profile = profile or load_profile()
    name = profile.get('project_adapter') or 'wechat_miniprogram'
    if name == 'wechat_bundle':
        return WeChatBundleProjectAdapter()
    if name == 'wechat_miniprogram':
        return WeChatProjectAdapter()
    return WeChatProjectAdapter()


def get_request_adapter(profile: Optional[Dict[str, Any]] = None) -> RequestAdapter:
    profile = profile or load_profile()
    name = profile.get('request_adapter') or 'wechat_http_wrapper'
    if name == 'taro_bundle_request':
        return TaroBundleRequestAdapter(profile)
    if name == 'wechat_http_wrapper':
        return WeChatHttpWrapperAdapter(profile)
    return WeChatHttpWrapperAdapter(profile)


def get_crypto_adapter(profile: Optional[Dict[str, Any]] = None) -> CryptoAdapter:
    return PackCryptoAdapter(profile or load_profile())


def get_runtime_adapter(profile: Optional[Dict[str, Any]] = None) -> RuntimeAdapter:
    return HttpRuntimeAdapter(profile or load_profile())


def load_crypto_profile(profile_id: str) -> Dict[str, Any]:
    path = _PACKS_ROOT / 'crypto_profiles' / f'{profile_id}.json'
    if path.exists():
        return json.loads(path.read_text(encoding='utf-8'))
    return {'profile_id': profile_id}


def load_domain_pack(domain: str) -> Dict[str, Any]:
    for base in (_PACKS_ROOT / 'domain_packs', Path(__file__).resolve().parents[1] / 'refinement' / 'domain_packs'):
        path = base / f'{domain}.json'
        if path.exists():
            return json.loads(path.read_text(encoding='utf-8'))
    return {}


def load_chain_template(template_id: str) -> Dict[str, Any]:
    single = _PACKS_ROOT / 'chain_templates' / f'{template_id}.json'
    if single.exists():
        return json.loads(single.read_text(encoding='utf-8'))
    catalog = _PACKS_ROOT / 'chain_templates' / 'universal_patterns.json'
    if catalog.exists():
        doc = json.loads(catalog.read_text(encoding='utf-8'))
        for t in doc.get('templates') or []:
            if t.get('template_id') == template_id or t.get('chain_type') == template_id:
                return t
    return {}


def analyze_pack_adapters(pack_dir: Path, *, profile_id: Optional[str] = None) -> Dict[str, Any]:
    """Run project + request adapter detection for a pack output directory."""
    from minidrifter.adapters.pack_resolver import resolve_pack_profile

    pack_dir = Path(pack_dir)
    profile = resolve_pack_profile(pack_dir, profile_id=profile_id)
    project_root = None
    prof_doc = pack_dir / 'project_profile.json'
    if prof_doc.exists():
        project_root = Path(json.loads(prof_doc.read_text(encoding='utf-8')).get('project_root') or pack_dir)

    project_adapter = get_project_adapter(profile)
    request_adapter = get_request_adapter(profile)

    project_info = {}
    if project_root and project_root.exists():
        project_info = project_adapter.detect(project_root)

    wrapper = request_adapter.detect_wrapper(project_root or pack_dir, pack_dir)

    sample_callsites = []
    calls_path = pack_dir / 'api_call_sites.json'
    if calls_path.exists():
        calls = json.loads(calls_path.read_text(encoding='utf-8'))
        if isinstance(calls, list):
            for cs in calls[:8]:
                sample_callsites.append(request_adapter.recover_operation(cs))
                if len(sample_callsites) >= 3:
                    break

    if len(sample_callsites) < 2:
        biz_path = pack_dir / 'business_api_operations.json'
        if biz_path.exists():
            ops = json.loads(biz_path.read_text(encoding='utf-8'))
            if isinstance(ops, list):
                for op in ops[:3]:
                    ep = op.get('endpoint') or {}
                    sample_callsites.append(request_adapter.recover_operation({
                        'path': ep.get('path') or '',
                        'resolved_url': ep.get('normalized_url') or ep.get('original_url') or '',
                        'method': op.get('method'),
                        'method_source': op.get('method_source'),
                    }))

    return {
        'profile': profile,
        'project_detection': project_info,
        'primary_wrapper': wrapper,
        'sample_recovered_operations': sample_callsites,
    }
