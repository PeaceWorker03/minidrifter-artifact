# -*- coding: utf-8 -*-
"""Resolve relative API paths via config base URLs (requestUrl + wrapper concat).

Universal pattern for uni-app / registry-rich mini-programs:
  util/api.js:  base = config.urls.requestUrl; url = base + '/' + relativePath
  api/*.js:     myRequest({ url: "admin/m/customer/..." + jointParams(...) })
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

# Config keys that typically hold API gateway hosts (not CDN/asset URLs).
_API_BASE_KEY_RE = re.compile(
    r'^(requestUrl|request_url|baseURL|baseUrl|apiUrl|apiURL|apiHost|serverUrl|'
    r'gatewayUrl|apiBase|hostUrl|serviceUrl|serverURL)$',
    re.I,
)
_CDN_OR_ASSET_KEY_RE = re.compile(
    r'^(imgUrl|imgURL|imageUrl|materialUrl|updateUrl|verifyCodeUrl|cdnUrl|'
    r'staticUrl|ossUrl|fileUrl|avatarUrl|iconUrl|cdn|obs)',
    re.I,
)
# Relative business path: admin/..., cinema/..., order/..., etc. (no hardcoded app names).
_RELATIVE_PATH_LITERAL_RE = re.compile(
    r'\burl\s*:\s*["\']([a-zA-Z][a-zA-Z0-9_./-]*)["\']',
    re.I,
)
_STRING_PATH_RE = re.compile(
    r'["\']((?:admin|cinema|order|card|goods|auth|pay|user|member|customer|'
    r'goods|invoice|coupon|device|store|booking|verify|oauth|wechat|mini|'
    r'goods|resource|gateway|api)/[a-zA-Z0-9_./?&=-]+)["\']',
    re.I,
)
_SKIP_PATH_PREFIXES = ('/pages', '../', './', 'http://', 'https://', '//')


def _normalize_base(url: str) -> str:
    u = (url or '').strip().rstrip('/')
    if not u.startswith('http'):
        return ''
    try:
        sp = urlsplit(u)
        if not sp.netloc:
            return ''
        return f'{sp.scheme}://{sp.netloc}'
    except Exception:
        return u


def _score_api_base_key(key: str) -> float:
    """Score config keys that typically hold API gateway bases.

    Bare ``url`` must NOT score high — marketing / H5 / article links often use it.
    """
    kl = (key or '').lower().replace('_', '')
    if kl in {'requesturl'}:
        return 12.0
    if kl in {'baseurl', 'apiurl', 'apihost', 'serverurl', 'gatewayurl', 'apibase', 'serviceurl', 'hosturl'}:
        return 10.0
    if 'request' in kl and 'url' in kl:
        return 9.0
    if kl.endswith('baseurl') or kl.endswith('apiurl') or kl.endswith('apihost'):
        return 8.0
    # Do not promote generic *url keys (e.g. bare ``url``).
    return 0.0


def _is_noise_api_base_host(base: str) -> bool:
    from minidrifter.optimizers.url_utils import is_excluded_business_host
    return is_excluded_business_host(base)


def extract_api_base_urls(url_registry: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Collect API gateway base URLs from url_registry entries and host_constants."""
    entries = url_registry.get('entries') or {}
    host_constants = url_registry.get('host_constants') or {}
    seen_hosts: Dict[str, Dict[str, Any]] = {}

    def _add(key: str, raw: str, source: str) -> None:
        base = _normalize_base(raw)
        if not base:
            return
        sc = _score_api_base_key(key)
        if sc <= 0 and source != 'host_constant':
            return
        if _CDN_OR_ASSET_KEY_RE.match(key):
            return
        if _is_noise_api_base_host(base):
            return
        host_l = base.lower()
        if any(x in host_l for x in ('obs.', 'cdn.', 'img.', 'static.', 'mmbiz.', 'qpic.')):
            return
        prev = seen_hosts.get(base)
        rec = {
            'key': key,
            'url': base,
            'score': sc if sc > 0 else 5.0,
            'source': source,
        }
        if prev is None or rec['score'] > prev['score']:
            seen_hosts[base] = rec

    for key, entry in entries.items():
        if _CDN_OR_ASSET_KEY_RE.match(key):
            continue
        if _API_BASE_KEY_RE.match(key) or _score_api_base_key(key) >= 8.0:
            _add(key, str(entry.get('resolved_url') or ''), 'url_registry')

    for var, host in host_constants.items():
        if re.search(r'(api|server|gateway|request|host|base)', var, re.I) and not re.search(
            r'(img|cdn|static|oss|avatar|icon|article|share)', var, re.I
        ):
            _add(var, host, 'host_constant')

    return sorted(seen_hosts.values(), key=lambda x: (-x['score'], x['key']))


def extract_relative_api_path(text: str) -> Optional[str]:
    """Pull first relative API path literal from url_expr or snippet."""
    if not text:
        return None
    for pat in (_RELATIVE_PATH_LITERAL_RE, _STRING_PATH_RE):
        m = pat.search(text)
        if not m:
            continue
        path = (m.group(1) or '').strip()
        if not path or any(path.startswith(p) for p in _SKIP_PATH_PREFIXES):
            continue
        if path.startswith('/pages') or '/pages/' in path:
            continue
        # strip query for endpoint key; keep path shape
        path = path.split('?')[0].split('#')[0]
        if '/' not in path:
            continue
        return path.lstrip('/')
    return None


def join_base_and_path(base_url: str, relative_path: str) -> str:
    base = (base_url or '').rstrip('/')
    path = (relative_path or '').lstrip('/')
    return f'{base}/{path}' if base and path else ''


def resolve_wrapper_relative_url(
    *,
    url_expr: str = '',
    snippet: str = '',
    api_bases: List[Dict[str, Any]],
) -> Tuple[Optional[str], Dict[str, Any]]:
    """Try to build full https://host/path from relative path + config base."""
    meta: Dict[str, Any] = {'strategy': 'wrapper_base_concat'}
    path = extract_relative_api_path(url_expr) or extract_relative_api_path(snippet)
    if not path:
        return None, {'strategy': 'unresolved', 'reason': 'no_relative_path'}
    if not api_bases:
        return None, {'strategy': 'unresolved', 'reason': 'no_api_base'}
    base_rec = api_bases[0]
    full = join_base_and_path(base_rec['url'], path)
    meta.update({
        'relative_path': path,
        'api_base_key': base_rec.get('key'),
        'api_base_url': base_rec.get('url'),
        'confidence': 0.82,
    })
    return full, meta


def apply_wrapper_url_resolution(
    api_call_res: Dict[str, Any],
    url_registry: Dict[str, Any],
    wrappers: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Promote resolvable dynamic wrapper calls to concrete api_call_sites."""
    api_bases = extract_api_base_urls(url_registry)
    url_registry['api_base_hosts'] = api_bases

    calls: List[Dict[str, Any]] = list(api_call_res.get('api_call_sites') or [])
    dynamic: List[Dict[str, Any]] = []
    promoted = 0

    for c in api_call_res.get('dynamic_api_candidates') or []:
        if c.get('resolved_url'):
            calls.append(c)
            continue
        snippet = (c.get('source') or {}).get('snippet') or ''
        resolved, meta = resolve_wrapper_relative_url(
            url_expr=str(c.get('url_expr') or ''),
            snippet=snippet,
            api_bases=api_bases,
        )
        if resolved:
            c2 = dict(c)
            c2['resolved_url'] = resolved
            c2['dynamic_url'] = False
            c2['url_resolution'] = meta
            calls.append(c2)
            promoted += 1
        else:
            c2 = dict(c)
            c2['url_resolution'] = meta
            dynamic.append(c2)

    return {
        'api_call_sites': calls,
        'dynamic_api_candidates': dynamic,
        'wrapper_url_bindings': api_bases,
        'wrapper_url_promoted_count': promoted,
    }
