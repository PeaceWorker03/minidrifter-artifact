# -*- coding: utf-8 -*-
"""Dual-pool host resolution: business_relative vs third_party_explicit."""
from __future__ import annotations

import re
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple

from minidrifter.optimizers.url_utils import clean_raw_url, host_score, is_excluded_business_host, split_url
from minidrifter.quality.resolvers.url_role import (
    detect_runtime_dynamic_host,
    is_third_party_sdk_host,
    is_third_party_sdk_url,
)

_BUSINESS_PREFIX_RE = re.compile(
    r'^/(action|resource|api|gateway|wechat|Wechat|wx|applet|customer|carrctapi|'
    r'admin|cinema|order|card|goods|auth|pay|oauth|member|invoice|coupon|booking|'
    r'verify|store|device)/',
    re.I,
)


def _normalize_host_url(host: str) -> str:
    h = (host or '').strip().rstrip('/')
    if not h:
        return ''
    if not h.startswith('http'):
        h = 'https://' + h.lstrip('/')
    return h


def _score_business_host(host: str) -> float:
    if is_excluded_business_host(host) or is_third_party_sdk_host(host):
        return -100.0
    return host_score(host)


def resolve_host_pools(
    url_inventory: List[Dict[str, Any]],
    *,
    host_constants: Optional[Dict[str, str]] = None,
    request_wrapper_text: str = '',
    baseline_host: Optional[str] = None,
    api_base_hosts: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Build separated host pools and default business host for relative paths."""
    host_constants = host_constants or {}
    api_base_hosts = api_base_hosts or []
    explicit_business: Dict[str, Dict[str, Any]] = {}
    third_party: Dict[str, Dict[str, Any]] = {}
    relative_prefixes = Counter()

    for base_rec in api_base_hosts:
        norm = _normalize_host_url(str(base_rec.get('url') or ''))
        if not norm:
            continue
        h = norm.replace('https://', '').replace('http://', '')
        if is_excluded_business_host(h) or is_third_party_sdk_host(h):
            continue
        rec = explicit_business.setdefault(norm, {'host': norm, 'score': 0.0, 'evidence': []})
        bonus = float(base_rec.get('score') or 8.0)
        rec['score'] += bonus + _score_business_host(h)
        if len(rec['evidence']) < 8:
            rec['evidence'].append({
                'source': 'api_base_config',
                'key': base_rec.get('key'),
                'score': bonus,
            })

    for var, host in host_constants.items():
        norm = _normalize_host_url(host)
        if not norm:
            continue
        h = norm.replace('https://', '').replace('http://', '')
        if is_excluded_business_host(h):
            bucket = third_party
        else:
            bucket = third_party if is_third_party_sdk_host(h) else explicit_business
        rec = bucket.setdefault(norm, {'host': norm, 'score': 0.0, 'evidence': []})
        sc = _score_business_host(h)
        rec['score'] += sc + (0.5 if bucket is explicit_business else 0)
        if len(rec['evidence']) < 8:
            rec['evidence'].append({'source': 'host_constant', 'var': var, 'score': sc})

    for item in url_inventory:
        raw = item.get('raw_url') or ''
        u = clean_raw_url(raw)
        if not u:
            continue
        if u.startswith('http'):
            h, path, _ = split_url(u)
            if not h:
                continue
            norm = _normalize_host_url(h)
            if is_third_party_sdk_url(u) or is_excluded_business_host(h):
                bucket = third_party
            else:
                bucket = explicit_business
            rec = bucket.setdefault(norm, {'host': norm, 'score': 0.0, 'evidence': []})
            sc = _score_business_host(h)
            rec['score'] += sc + 0.3
            if len(rec['evidence']) < 8:
                rec['evidence'].append({'source': 'observed_full_url', 'url': u[:120], 'score': sc})
        else:
            _, path, _ = split_url(u)
            if path and _BUSINESS_PREFIX_RE.search(path):
                parts = [p for p in path.split('/') if p]
                if len(parts) >= 2:
                    relative_prefixes['/' + '/'.join(parts[:2]) + '/'] += 1
                if len(parts) >= 1:
                    relative_prefixes['/' + parts[0] + '/'] += 1

    # Drop noise / excluded hosts from business pool even if they leaked in.
    explicit_business = {
        k: v for k, v in explicit_business.items()
        if v.get('score', 0) > 0 and not is_excluded_business_host(v.get('host') or '')
    }
    business_sorted = sorted(explicit_business.values(), key=lambda x: x['score'], reverse=True)
    third_sorted = sorted(third_party.values(), key=lambda x: x['score'], reverse=True)

    default_business_host = None
    api_default_host = None
    authoritative_host = None
    host_resolution_strategy = 'unresolved'

    if baseline_host:
        authoritative_host = _normalize_host_url(baseline_host)
        if not is_excluded_business_host(authoritative_host):
            default_business_host = authoritative_host
            api_default_host = authoritative_host
            host_resolution_strategy = 'baseline_authoritative'
        else:
            authoritative_host = None

    if not authoritative_host and business_sorted:
        # Compete by score: api_base_config is evidence, not an unconditional override.
        best = business_sorted[0]
        default_business_host = best['host']
        host_resolution_strategy = 'business_explicit_pool'
        if any((e or {}).get('source') == 'api_base_config' for e in (best.get('evidence') or [])):
            host_resolution_strategy = 'api_base_config'
        for h in business_sorted:
            host_l = (h.get('host') or '').lower()
            if re.search(r'(api|proxy|gateway|appmini|server)', host_l):
                api_default_host = h['host']
                break
        if api_default_host is None:
            api_default_host = default_business_host
        # Prefer API-like host as default when it scores competitively.
        if api_default_host and api_default_host != default_business_host:
            api_rec = next((h for h in business_sorted if h['host'] == api_default_host), None)
            best_score = float(best.get('score') or 0)
            api_score = float((api_rec or {}).get('score') or 0)
            if api_score >= best_score * 0.85:
                default_business_host = api_default_host
                host_resolution_strategy = 'business_explicit_pool'

    runtime_dynamic = detect_runtime_dynamic_host(request_wrapper_text)
    if not default_business_host and runtime_dynamic:
        host_resolution_strategy = 'runtime_extconfig_pending'

    # Never emit excluded hosts.
    if default_business_host and is_excluded_business_host(default_business_host):
        default_business_host = None
        api_default_host = None
        host_resolution_strategy = 'unresolved'
    if api_default_host and is_excluded_business_host(api_default_host):
        api_default_host = default_business_host

    prefix_map: Dict[str, Dict[str, Any]] = {}
    chosen = default_business_host or api_default_host
    for pref, count in relative_prefixes.items():
        if pref.lower() in {'/pages/', '/package/', '/packages/', '/subpackages/', '/sub-packages/', '/images/', '/static/'}:
            continue
        if not chosen:
            continue
        strategy = 'business_relative_pool'
        host_for_pref = chosen
        if re.search(r'^/(action|resource|api|gateway|wechat|Wechat|carrctapi)/', pref) and api_default_host:
            host_for_pref = api_default_host
            strategy = 'api_prefix_business_host'
        prefix_map[pref] = {
            'host': host_for_pref,
            'confidence': min(0.95, 0.55 + count / 200.0),
            'support_count': count,
            'strategy': strategy,
            'pool': 'business_relative',
        }

    return {
        'host_pools': {
            'business_explicit': business_sorted[:20],
            'third_party_explicit': third_sorted[:20],
            'business_relative_prefixes': dict(relative_prefixes.most_common(30)),
        },
        'default_business_host': default_business_host,
        'api_default_host': api_default_host,
        'authoritative_business_host': authoritative_host,
        'host_resolution_strategy': host_resolution_strategy,
        'runtime_dynamic_host': runtime_dynamic,
        'path_prefix_map': prefix_map,
        # backward-compatible alias
        'host_candidates': business_sorted[:20],
    }


def infer_host_for_path_pooled(
    raw_url: str,
    host_resolution: Dict[str, Any],
) -> Tuple[Optional[str], Dict[str, Any]]:
    """Infer host using dual-pool resolution; block third-party default for relatives."""
    u = clean_raw_url(raw_url)
    if u.startswith('http'):
        h, _, _ = split_url(u)
        if is_third_party_sdk_host(h):
            return (_normalize_host_url(h) if h else None), {
                'strategy': 'explicit_third_party',
                'confidence': 1.0,
                'pool': 'third_party_explicit',
            }
        return (_normalize_host_url(h) if h else None), {
            'strategy': 'explicit_host',
            'confidence': 1.0,
            'pool': 'business_explicit',
        }

    _, path, _ = split_url(u)
    best = None
    for pref, info in (host_resolution.get('path_prefix_map') or {}).items():
        if path.startswith(pref):
            if best is None or len(pref) > len(best[0]):
                best = (pref, info)
    if best:
        return best[1]['host'], {
            'strategy': best[1].get('strategy', 'prefix_host_inference'),
            'prefix': best[0],
            'confidence': best[1].get('confidence'),
            'pool': 'business_relative',
        }

    host = host_resolution.get('authoritative_business_host') or host_resolution.get('default_business_host')
    if host:
        return host, {
            'strategy': host_resolution.get('host_resolution_strategy', 'project_default_business_host'),
            'confidence': 0.55,
            'pool': 'business_relative',
        }
    return host, {'strategy': 'unresolved', 'confidence': 0.0, 'pool': 'business_relative'}


def _best_business_explicit_host(doc: Dict[str, Any]) -> Optional[str]:
    pools = (doc.get('host_pools') or {}).get('business_explicit') or []
    ranked: List[tuple] = []
    for item in pools:
        if not isinstance(item, dict):
            continue
        h = item.get('host')
        if not h:
            continue
        hs = str(h)
        if is_excluded_business_host(hs) or is_third_party_sdk_host(hs):
            continue
        # Skip path-bearing pool rows (full endpoint URLs mistaken for hosts).
        low = hs.lower().replace('https://', '').replace('http://', '')
        if '/' in low.rstrip('/'):
            # Allow host:port only
            after = low.split('/', 1)[0]
            if not after or '.' not in after:
                continue
            hs = ('https://' if str(h).lower().startswith('https') else 'http://') + after
            if is_excluded_business_host(hs) or is_third_party_sdk_host(hs):
                continue
        ranked.append((float(item.get('score') or 0), _normalize_host_url(hs)))
    if not ranked:
        return None
    ranked.sort(key=lambda x: -x[0])
    return ranked[0][1]


def repair_noise_default_host(pack_dir) -> bool:
    """If default_business_host is telemetry/SDK/noise, or a weaker pool pick, promote best business host."""
    import json
    from pathlib import Path

    from minidrifter.core.utils import write_json

    pack_dir = Path(pack_dir)
    path = pack_dir / 'host_resolution.json'
    if not path.exists():
        return False
    doc = json.loads(path.read_text(encoding='utf-8'))
    default = doc.get('default_business_host') or ''
    fallback = _best_business_explicit_host(doc)
    noise = bool(default and (
        is_excluded_business_host(default) or is_third_party_sdk_host(default)
    ))
    if not default and not fallback:
        return False
    if noise:
        if not fallback:
            doc['default_business_host'] = None
            doc['api_default_host'] = None
            doc['authoritative_business_host'] = None
            doc['host_resolution_strategy'] = 'unresolved_noise_baseline_rejected'
            write_json(path, doc)
            return True
        doc['default_business_host'] = fallback
        doc['api_default_host'] = fallback
        doc['authoritative_business_host'] = fallback
        doc['host_resolution_strategy'] = 'business_explicit_pool_after_noise_baseline'
        doc['rejected_baseline_host'] = default
        write_json(path, doc)
        return True
    # Promote clearly stronger business host (e.g. mapi.* over toc-consolidation.*).
    if fallback and default:
        pools = (doc.get('host_pools') or {}).get('business_explicit') or []
        score_by = {}
        for item in pools:
            if not isinstance(item, dict) or not item.get('host'):
                continue
            norm = _normalize_host_url(str(item['host']))
            score_by[norm] = max(score_by.get(norm, 0.0), float(item.get('score') or 0))
        cur_s = score_by.get(_normalize_host_url(default), 0.0)
        fb_s = score_by.get(_normalize_host_url(fallback), 0.0)
        if fb_s >= cur_s + 8.0 and _normalize_host_url(fallback) != _normalize_host_url(default):
            doc['rejected_weaker_host'] = default
            doc['default_business_host'] = fallback
            doc['api_default_host'] = fallback
            doc['authoritative_business_host'] = fallback
            doc['host_resolution_strategy'] = 'business_explicit_pool_score_promote'
            write_json(path, doc)
            return True
    return False


def apply_baseline_host_override(pack_dir, baseline_context: Dict[str, Any]) -> bool:
    """Patch host_resolution.json when baseline provides authoritative Host."""
    import json
    from pathlib import Path

    from minidrifter.core.utils import write_json

    pack_dir = Path(pack_dir)
    host_entry = (baseline_context.get('resolved_fields') or {}).get('Host') or {}
    host_val = host_entry.get('value')
    if not host_val:
        return False
    norm = _normalize_host_url(str(host_val))
    path = pack_dir / 'host_resolution.json'
    doc: Dict[str, Any] = {}
    if path.exists():
        doc = json.loads(path.read_text(encoding='utf-8'))
    # Never promote telemetry / SDK hosts from a mis-labeled capture sample.
    if is_excluded_business_host(norm) or is_third_party_sdk_host(norm):
        doc['rejected_baseline_host'] = norm
        doc['baseline_host_source'] = host_entry.get('source')
        fallback = _best_business_explicit_host(doc)
        if fallback:
            doc['authoritative_business_host'] = fallback
            doc['default_business_host'] = fallback
            doc['api_default_host'] = fallback
            doc['host_resolution_strategy'] = 'business_explicit_pool_after_noise_baseline'
            write_json(path, doc)
            return True
        return False
    doc['authoritative_business_host'] = norm
    doc['default_business_host'] = norm
    doc['api_default_host'] = norm
    doc['host_resolution_strategy'] = 'baseline_authoritative'
    doc['baseline_host_source'] = host_entry.get('source')
    write_json(path, doc)
    return True
