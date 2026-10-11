# -*- coding: utf-8 -*-
"""Generic URL role classification: business vs third-party SDK vs noise."""
from __future__ import annotations

import re
from typing import Any, Dict, Optional

from minidrifter.optimizers.url_utils import classify_url_type, clean_raw_url, is_excluded_business_host, split_url

# Known third-party SDK / map / weather hosts — never business backend for relative paths.
THIRD_PARTY_SDK_HOST_RE = re.compile(
    r'(map\.baidu\.com|api\.map\.baidu\.com|restapi\.amap\.com|'
    r'api\.tianditu\.gov\.cn|apis\.map\.qq\.com|geo\.qq\.com|'
    r'apis\.tencent\.com/map|weather\.|telematics\.|'
    # Platform / AI / map / pay SDKs — never the mini-program business backend.
    r'aip\.baidubce\.com|hmma\.baidu\.com|mbd\.baidu\.com|'
    r'api\.weixin\.qq\.com|cube\.weixinbridge\.com|'
    r'openapi\.alipay\.com|maps\.googleapis\.com|googleapis\.com|'
    r'api\.next\.bspapp\.com|api\.bspapp\.com|'
    r'uniapp\.dcloud\.net\.cn|abtest\.volceapplog\.com)',
    re.I,
)

THIRD_PARTY_SDK_PATH_RE = re.compile(
    r'/(place/v2/|geocoding/|reverse_geocoding/|telematics/|weather/|suggestion)',
    re.I,
)

RUNTIME_HOST_MARKERS_RE = re.compile(
    r'(getServerUrl|getExtConfigSync|extConfig\.server|_replace_server_domain_)',
    re.I,
)

BUSINESS_RELATIVE_PREFIX_RE = re.compile(
    r'^/(wechat|wx|applet|app|customer|wxa|mobile|mini|action|resource|gateway|carrctapi)/',
    re.I,
)


def is_third_party_sdk_host(host: str) -> bool:
    h = (host or '').lower().replace('https://', '').replace('http://', '').strip('/')
    if not h:
        return False
    if THIRD_PARTY_SDK_HOST_RE.search(h):
        return True
    # Align with noise / excluded hosts so quality gates catch mp.weixin.qq.com etc.
    return is_excluded_business_host(h)


def is_third_party_sdk_url(url: str) -> bool:
    u = clean_raw_url(url)
    if not u:
        return False
    if u.startswith('http'):
        host, path, _ = split_url(u)
        return is_third_party_sdk_host(host) or bool(THIRD_PARTY_SDK_PATH_RE.search(path or ''))
    return bool(THIRD_PARTY_SDK_PATH_RE.search(u))


def is_business_relative_path(path: str) -> bool:
    p = clean_raw_url(path)
    if not p.startswith('/'):
        return False
    cls = classify_url_type(p)
    return bool(cls.get('is_business_api')) or bool(BUSINESS_RELATIVE_PREFIX_RE.search(p))


def classify_url_role(
    url: str,
    *,
    inferred_host: Optional[str] = None,
) -> Dict[str, Any]:
    """Return url_role and pool membership for host/graph policies."""
    u = clean_raw_url(url)
    host = inferred_host or ''
    if u.startswith('http'):
        host, path, _ = split_url(u)
    else:
        path = u

    base_cls = classify_url_type(u)
    role = 'unknown'
    pool = 'excluded'

    if is_third_party_sdk_url(u) or is_third_party_sdk_host(host):
        role = 'third_party_sdk'
        pool = 'third_party_explicit'
    elif u.startswith('http'):
        if base_cls.get('is_business_api'):
            role = 'business_explicit'
            pool = 'business_explicit'
        elif base_cls.get('url_type') in {'third_party_or_telemetry', 'telemetry_or_errorlog'}:
            role = 'telemetry'
            pool = 'excluded'
        else:
            role = 'external_full_url'
            pool = 'observed_other'
    elif is_business_relative_path(path):
        role = 'business_relative'
        pool = 'business_relative'
    elif base_cls.get('url_type') == 'frontend_route':
        role = 'frontend_route'
        pool = 'excluded'
    else:
        role = base_cls.get('url_type') or 'unknown'
        pool = 'excluded'

    return {
        'url_role': role,
        'host_pool': pool,
        'is_chain_eligible': role in {'business_explicit', 'business_relative'},
        'is_transition_producer_eligible': role in {'business_explicit', 'business_relative'},
        'is_default_host_candidate': role == 'business_explicit' and not is_third_party_sdk_host(host),
        'classification': base_cls,
    }


def detect_runtime_dynamic_host(snippets: str) -> bool:
    return bool(RUNTIME_HOST_MARKERS_RE.search(snippets or ''))
