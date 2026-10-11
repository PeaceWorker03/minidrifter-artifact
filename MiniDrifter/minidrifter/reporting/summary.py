# -*- coding: utf-8 -*-
from __future__ import annotations
from collections import Counter
from typing import Any, Dict, List


def build_summary_md(result: Dict[str, Any]) -> str:
    profile = result.get('project_profile', {})
    page_surface = result.get('page_surface', {})
    url_registry = result.get('url_registry', {})
    api_cards = result.get('api_cards', {})
    cred = result.get('credential_candidates', {})
    lines = []
    lines.append('# MiniDrifter Analysis Summary')
    lines.append('')
    lines.append('## Project profile')
    lines.append(f"- Shape: `{profile.get('shape')}`")
    lines.append(f"- Platform guess: `{profile.get('platform_guess')}`")
    lines.append(f"- Obfuscation: `{profile.get('obfuscation', {}).get('level')}` score={profile.get('obfuscation', {}).get('score')}")
    lines.append(f"- File count: {profile.get('file_count')}")
    lines.append('')
    lines.append('## Recovered surfaces')
    lines.append(f"- Pages: {len(page_surface.get('pages', []))}")
    lines.append(f"- Components: {len(page_surface.get('components', []))}")
    lines.append(f"- WXML events: {len(result.get('events', []))}")
    lines.append(f"- URL registry entries: {url_registry.get('count', len(url_registry.get('entries', {})))}")
    lines.append(f"- Request wrappers: {len(result.get('request_wrappers', []))}")
    lines.append(f"- Crypto cards: {len(result.get('crypto_cards', []))}")
    lines.append('')
    lines.append('## API cards')
    lines.append(f"- Reached API cards: {len(api_cards.get('reached_api_cards', []))}")
    lines.append(f"- Registered-only API cards: {len(api_cards.get('registered_only_api_cards', []))}")
    lines.append(f"- Dynamic API cards: {len(api_cards.get('dynamic_api_cards', []))}")
    raw_replay_count = len(result.get('replay_contracts', []))
    opt = result.get('optimizer_outputs') or {}
    if opt:
        lines.append(f"- Raw replay contracts: {raw_replay_count}")
        lines.append(f"- Optimized replay contracts: {len(opt.get('replay_contracts', []))}")
    else:
        lines.append(f"- Replay contracts: {raw_replay_count}")
    if opt:
        dedup = opt.get('dedup_report') or {}
        lines.append('')
        lines.append('## Normalized / optimized outputs')
        lines.append(f"- URL inventory: {len(opt.get('url_inventory', []))}")
        lines.append(f"- Normalized API operations: {len(opt.get('normalized_api_operations', []))}")
        lines.append(f"- Business API operations: {len(opt.get('business_api_operations', []))}")
        lines.append(f"- Ranked candidates: {len(opt.get('ranked_api_candidates', []))}")
        lines.append(f"- Optimized replay contracts: {len(opt.get('replay_contracts', []))}")
        if dedup:
            lines.append(f"- Raw URL surfaces -> operations reduction: {dedup.get('reduction_ratio_from_raw_surfaces')}")
            lines.append(f"- Method counts after inference: `{dedup.get('method_counts_after_inference')}`")
            if dedup.get('surface_shape'):
                lines.append(f"- Surface shape: `{dedup.get('surface_shape')}`")
            rop = dedup.get('registered_only_policy') or {}
            if rop:
                lines.append(f"- Registered-only policy: `{rop.get('downstream_use')}` (raw={rop.get('raw_count')}, business_like={rop.get('business_like_count')})")
            if dedup.get('replay_readiness_counts'):
                lines.append(f"- Replay readiness: `{dedup.get('replay_readiness_counts')}`")
    lines.append('')
    lines.append('## Credential roles')
    for k, v in (cred.get('role_counts') or {}).items():
        lines.append(f"- {k}: {v}")
    if opt and opt.get('ranked_api_candidates'):
        lines.append('')
        lines.append('## Top optimized API candidates')
        for op in opt.get('ranked_api_candidates', [])[:25]:
            endpoint = (op.get('endpoint') or {}).get('normalized_url') or ''
            reasons = ', '.join(op.get('rank_reason') or [])
            roles = ', '.join(k for k, v in (op.get('credential_roles') or {}).items() if v)
            readiness = (op.get('replay_readiness') or {}).get('readiness') or '-'
            lines.append(f"- #{op.get('rank')} score={op.get('rank_score')} `{op.get('method')}` readiness={readiness} {endpoint} | roles={roles or '-'} | {reasons}")
    else:
        lines.append('')
        lines.append('## High-value reached API examples')
        cards = api_cards.get('reached_api_cards', [])
        high = [c for c in cards if c.get('risk_hints')]
        for c in high[:25]:
            ep = c.get('endpoint', {})
            lines.append(f"- `{ep.get('method')}` `{ep.get('url_key')}` {ep.get('resolved_url')} | {', '.join(c.get('risk_hints', [])[:4])}")
        lines.append('')
        lines.append('## High-value registered-only API examples')
        rop = (opt.get('dedup_report') or {}).get('registered_only_policy') or {}
        if rop.get('actionable'):
            for c in api_cards.get('registered_only_api_cards', [])[:25]:
                ep = c.get('endpoint', {})
                if c.get('business_hints', {}).get('sensitive_hint') or c.get('risk_hints'):
                    lines.append(f"- `{ep.get('url_key')}` {ep.get('resolved_url')} | {', '.join(c.get('risk_hints', [])[:4])}")
        else:
            lines.append('- Registered-only review skipped for bundle-inline project shape.')
    return '\n'.join(lines) + '\n'


def build_summary_json(result: Dict[str, Any]) -> Dict[str, Any]:
    return {
        'project_profile': result.get('project_profile'),
        'counts': {
            'pages': len(result.get('page_surface', {}).get('pages', [])),
            'components': len(result.get('page_surface', {}).get('components', [])),
            'events': len(result.get('events', [])),
            'url_registry': result.get('url_registry', {}).get('count', len(result.get('url_registry', {}).get('entries', {}))),
            'request_wrappers': len(result.get('request_wrappers', [])),
            'crypto_cards': len(result.get('crypto_cards', [])),
            'api_call_sites': len(result.get('api_call_sites', [])),
            'dynamic_api_candidates': len(result.get('dynamic_api_candidates', [])),
            'reached_api_cards': len(result.get('api_cards', {}).get('reached_api_cards', [])),
            'registered_only_api_cards': len(result.get('api_cards', {}).get('registered_only_api_cards', [])),
            'dynamic_api_cards': len(result.get('api_cards', {}).get('dynamic_api_cards', [])),
            'replay_contracts': len(result.get('replay_contracts', [])),
        },
        'credential_role_counts': result.get('credential_candidates', {}).get('role_counts', {}),
        'optimized_counts': {
            'url_inventory': len((result.get('optimizer_outputs') or {}).get('url_inventory', [])),
            'normalized_api_operations': len((result.get('optimizer_outputs') or {}).get('normalized_api_operations', [])),
            'business_api_operations': len((result.get('optimizer_outputs') or {}).get('business_api_operations', [])),
            'ranked_api_candidates': len((result.get('optimizer_outputs') or {}).get('ranked_api_candidates', [])),
            'optimized_replay_contracts': len((result.get('optimizer_outputs') or {}).get('replay_contracts', [])),
        } if result.get('optimizer_outputs') else {},
        'dedup_report': (result.get('optimizer_outputs') or {}).get('dedup_report', {}),
        'surface_shape': (result.get('optimizer_outputs') or {}).get('surface_shape'),
        'registered_only_policy': (result.get('optimizer_outputs') or {}).get('registered_only_policy', {}),
    }
