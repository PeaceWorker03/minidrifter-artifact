# -*- coding: utf-8 -*-
from __future__ import annotations
import re
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode
from typing import Any, Dict, Iterable, List, Optional, Tuple

BUSINESS_PREFIX_RE = re.compile(
    r'/(api|action|resource|gateway|wechat|mobile|mini|minipro|service|rest|v\d+|carrctapi|'
    r'admin|cinema|order|card|goods|auth|pay|oauth|member|customer|invoice|coupon|'
    r'booking|verify|store|device|shunke|ems|cgi-bin|linker|mtop|applet|dgapi|'
    r'asyapi|boxapi|crm|basic|sc|cg|wx|shop|user|login|account|ticket|mail|'
    r'express|new-generation|newmail|imcloud|busifavor|lifepayment|cloudpay)(/|$)',
    re.I,
)
BUSINESS_TOKEN_RE = re.compile(
    r'(user|member|customer|balance|payment|pay|order|invoice|ticket|coupon|qrcode|'
    r'verify|writeoff|device|vehicle|car|hicar|driver|license|idcard|rescue|account|'
    r'deposit|credit|bank|phone|auth|login|session|door|lock|key|address|store|'
    r'booking|price|cart|shunke|ems|mail|express|gateway|linker|boss|shop)',
    re.I,
)
FRONTEND_ROUTE_RE = re.compile(
    r'^/?(pages|page|package|packages|subpackages|sub-packages|subPackages|'
    r'plugin_|layout|components?|tabbar|miniprogram_npm)(/|$)',
    re.I,
)
# Mini-program page folders often look like /pay/entryPage/index (not backend RPC).
PAGE_FOLDER_RE = re.compile(
    r'(^|/)([A-Za-z0-9_]*[Pp]age[A-Za-z0-9_]*)/index(/|$)',
)
STATIC_ASSET_RE = re.compile(
    r'\.(png|jpe?g|gif|svg|webp|css|wxss|less|scss|ico|ttf|woff2?|mp4|mp3|wav|'
    r'js|map)(\?|#|:|$)',
    re.I,
)
# Cocos / game engine / XML / bundler / polyfill literals — never backend APIs.
ENGINE_NOISE_PATH_RE = re.compile(
    r'(^|/)'
    r'(cocos-js|cocos(/|$)|prerequisite-imports|common/engine|EventIniter|'
    r'XML/\d+|1999/xhtml|2000/xmlns|2000/svg|xmlns|xmldom|audio_effect_|audio_music_|'
    r'battle_|buff_|role_|map_world|ui_[a-z0-9_]+|weui-miniprogram|'
    r'uni_modules|common/js|common/vendor|mp_ecard_sdk|vuejs|'
    r'maps/api/staticmap|restapi\.amap\.com|uniCloud|platformapi/startapp|'
    r'gateway\.do|apps/font|'
    # Node/polyfill / chart SDK / uniCloud ping stems
    r'array/from|function/|object/|number/|string/|math/|internal/|'
    r'set-prototype-of|lib/|support/|type/|node/|locale/|i18n/|js_sdk/|is-buffer|'
    r'system/ping|system/check-function|functions/invokeFunction|'
    # CMS / static HTML fragments often leaked as "API" paths
    r'n\d+/n\d+|'
    # Bare/short non-RPC leftovers
    r'wx$)',
    re.I,
)
# 纯静态 JSON 配置；业务 RPC（/MiniPro/foo.json、/api/x.json）不算静态
STATIC_JSON_RE = re.compile(
    r'(^|/)(app|project|sitemap|package|tsconfig|babel|eslint|prettier|manifest)[^/]*\.json(\?|#|$)',
    re.I,
)
JSON_RPC_PATH_RE = re.compile(
    r'/(MiniPro|LifePayment|account|api|action|resource|service|gateway|mobile|'
    r'pay|member|user|order|invoice|auth|wx|cgi-bin)/[^?]+\.json(\?|#|$)',
    re.I,
)
NOISE_HOST_RE = re.compile(
    r'(reactjs\.org|taro\.com|mp\.weixin\.qq\.com|oa\.m\.tencent\.com|'
    r'servicewechat\.com|captcha|sentry|umeng|errlog|monitor|sensors|analytics|'
    r'badjs|dfs\.|cdn\.|wximg|externalimage|mmbiz\.|qpic\.|'
    r'ks3[-.]|ksyun|ksyuncs\.com|obs[a-z0-9]*\.|aliyuncs\.com/.+\.oss|'
    r'qiniucdn|myqcloud|cos\.ap-|tos-cn-|'
    r'w3\.org|git\.io|github\.com|cocos\-creator|cocos\.com)',
    re.I,
)
THIRD_PARTY_SDK_HOST_RE = re.compile(
    r'(map\.baidu\.com|api\.map\.baidu\.com|restapi\.amap\.com|'
    r'api\.tianditu\.gov\.cn|apis\.map\.qq\.com|geo\.qq\.com|telematics\.|'
    r'mapgis|chinadatapay|h5live|'
    r'aip\.baidubce\.com|hmma\.baidu\.com|mbd\.baidu\.com|'
    r'api\.weixin\.qq\.com|cube\.weixinbridge\.com|'
    r'openapi\.alipay\.com|maps\.googleapis\.com|googleapis\.com|'
    r'api\.next\.bspapp\.com|api\.bspapp\.com|'
    r'uniapp\.dcloud\.net\.cn|abtest\.volceapplog\.com)',
    re.I,
)
BUSINESS_HOST_RE = re.compile(r'(api|gateway|proxy|appmini|mini|wechat|weixin|server|service|carrctapi|ems|qianhub|sanyipos)', re.I)
HTTP_URL_RE = re.compile(r'https?://[^\s"\'<>\\)]+')
# High-recall relative API paths: known prefixes OR multi-segment backend-like paths.
_PATH_KNOWN = (
    r'api|action|resource|gateway|wechat|mobile|mini|service|rest|carrctapi|'
    r'shunke|ems|cgi-bin|linker|mtop|applet|dgapi|asyapi|boxapi|crm|oauth|pay|'
    r'order|member|user|auth|sc|cg|basic|wx|v\d+|shop|login|account|ticket|'
    r'express|mail|boss|busifavor'
)
PATH_URL_RE = re.compile(
    rf'(?<![A-Za-z0-9_])/(?!pages?/|page/|components?/|static/|assets?/|images?/|img/)'
    rf'(?:(?:{_PATH_KNOWN})[A-Za-z0-9_./?=&%:-]*|'
    rf'[A-Za-z][A-Za-z0-9_-]{{1,40}}(?:/[A-Za-z0-9_.-]{{1,64}}){{1,8}}/?)',
    re.I,
)


def strip_js_quotes(s: str | None) -> str:
    if not s:
        return ''
    s = str(s).strip().strip(',;')
    if len(s) >= 2 and s[0] in ('"', "'", '`') and s[-1] == s[0]:
        return s[1:-1]
    return s


def clean_raw_url(url: str | None) -> str:
    if not url:
        return ''
    u = strip_js_quotes(url)
    u = u.replace('\\/', '/')
    # remove common JS concatenation tail noise
    u = re.split(r'["\'`\s<>]', u)[0]
    while u.endswith((')', '}', ']', ',', ';')):
        u = u[:-1]
    return u


def is_probable_url(s: str | None) -> bool:
    u = clean_raw_url(s)
    if not u or len(u) < 2:
        return False
    if u.startswith('http://') or u.startswith('https://'):
        return True
    if u.startswith('/') and not u.startswith('//'):
        return True
    return False


def is_json_rpc_path(path: str | None) -> bool:
    """True for backend RPC that ends with .json (e.g. /MiniPro/queryX.json)."""
    p = clean_raw_url(path) or ''
    if not p:
        return False
    low = p.lower()
    if low.startswith('http'):
        try:
            p = urlsplit(p).path or '/'
            low = p.lower()
        except Exception:
            pass
    if JSON_RPC_PATH_RE.search(p):
        return True
    # Generic: /seg/seg.json with business-ish leaf (query|get|list|save|…)
    if re.search(r'/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\.json(\?|#|$)', p) and re.search(
        r'(query|get|list|save|update|create|delete|bind|pay|login|auth|search|detail|record|info|config)',
        low,
    ):
        return True
    return False


def is_chain_business_path(path: str | None) -> bool:
    """Composer/probe gate: backend business API, not frontend route or static asset."""
    if not path:
        return False
    if is_frontend_route_path(path):
        return False
    if is_json_rpc_path(path):
        return True
    info = classify_url_type(path)
    return bool(info.get('is_business_api'))


def is_frontend_route_path(path: str | None) -> bool:
    """True for mini-program page/package routes (not backend APIs)."""
    p = clean_raw_url(path)
    if not p:
        return False
    low = p.lower()
    # Strip scheme/host if absolute.
    if low.startswith('http'):
        try:
            p = urlsplit(p).path or '/'
            low = p.lower()
        except Exception:
            pass
    if not p.startswith('/'):
        p = '/' + p
        low = p.lower()
    # Backend JSON RPC must not be treated as a page route
    if is_json_rpc_path(p):
        return False
    if FRONTEND_ROUTE_RE.search(p):
        return True
    if PAGE_FOLDER_RE.search(p) and not is_json_rpc_path(p):
        return True
    # Sourcemap / bundled style refs: "...tabbar.wxss:879:1"
    if re.search(r'\.(wxss|wxml|js|ts|css):\d+', low):
        return True
    return bool(
        '/pages/' in low
        or '/page/' in low
        or '/package/' in low
        or '/packages/' in low
        or '/subpackages/' in low
        or '/sub-packages/' in low
        or '/tabbar/' in low
        or '/router/' in low
        or '/miniprogram_npm/' in low
    )


def is_engine_noise_path(path: str | None) -> bool:
    p = clean_raw_url(path)
    if not p:
        return False
    if ENGINE_NOISE_PATH_RE.search(p):
        return True
    # Script modules are never business RPC (JSON RPC uses .json).
    if re.search(r'\.js(\?|#|$)', p, re.I) and not JSON_RPC_PATH_RE.search(p):
        return True
    # Base64 / opaque blob path segments (leaked constants).
    leaf = p.rstrip('/').rsplit('/', 1)[-1]
    if len(leaf) >= 32 and re.fullmatch(r'[A-Za-z0-9+/=_\-]+', leaf or ''):
        return True
    return False


def is_excluded_business_host(host: str | None) -> bool:
    """Hosts that must never be default_business_host / api_base."""
    h = (host or '').lower().replace('https://', '').replace('http://', '').strip('/')
    if not h:
        return False
    if THIRD_PARTY_SDK_HOST_RE.search(h):
        return True
    if NOISE_HOST_RE.search(h):
        return True
    return False


def classify_url_type(url: str | None, url_key: str | None = None, source_file: str | None = None) -> Dict[str, Any]:
    u = clean_raw_url(url)
    key = url_key or ''
    source_file = source_file or ''
    if not u:
        return {'url_type': 'unknown', 'is_business_api': False, 'noise_score': 1.0, 'reason': 'empty_url'}
    low = u.lower()
    if is_json_rpc_path(u):
        return {'url_type': 'business_backend_api', 'is_business_api': True, 'noise_score': 0.0, 'reason': 'json_rpc_path'}
    if is_frontend_route_path(u):
        return {'url_type': 'frontend_route', 'is_business_api': False, 'noise_score': 0.85, 'reason': 'mini_program_route'}
    if ENGINE_NOISE_PATH_RE.search(u):
        return {'url_type': 'engine_or_bundle_noise', 'is_business_api': False, 'noise_score': 0.95, 'reason': 'engine_or_bundle_noise'}
    if STATIC_JSON_RE.search(u):
        return {'url_type': 'static_asset', 'is_business_api': False, 'noise_score': 0.9, 'reason': 'static_json_config'}
    if STATIC_ASSET_RE.search(u) or re.search(r'/(images?|img|static|assets?)/', low):
        return {'url_type': 'static_asset', 'is_business_api': False, 'noise_score': 0.9, 'reason': 'static_asset'}
    # Bare *.json that is not RPC → treat as non-business config/noise
    if re.search(r'\.json(\?|#|$)', low) and not BUSINESS_PREFIX_RE.search(u) and not BUSINESS_TOKEN_RE.search(u):
        return {'url_type': 'static_asset', 'is_business_api': False, 'noise_score': 0.85, 'reason': 'json_non_rpc'}
    # Static / legal HTML pages are not backend API operations.
    if re.search(r'\.(html?|htm)(\?|#|$)', low) or '/agreement/' in low or low.endswith('/index.html'):
        return {'url_type': 'webview_h5_or_marketing', 'is_business_api': False, 'noise_score': 0.8, 'reason': 'html_or_agreement_page'}
    if re.search(r'(^|/)h5(/|$)|_h5(/|$)|/webview/', low):
        return {'url_type': 'webview_h5_or_marketing', 'is_business_api': False, 'noise_score': 0.78, 'reason': 'h5_webview_path'}
    host = ''
    if u.startswith('http'):
        try:
            host = urlsplit(u).netloc
        except Exception:
            host = ''
    if host and (NOISE_HOST_RE.search(host) or THIRD_PARTY_SDK_HOST_RE.search(host)):
        reason = f'third_party_sdk_host:{host}' if THIRD_PARTY_SDK_HOST_RE.search(host) else f'noise_host:{host}'
        return {'url_type': 'third_party_or_telemetry', 'is_business_api': False, 'noise_score': 0.95, 'reason': reason}
    # Map / GIS / live-stream third parties often look like "api" hosts.
    if host and re.search(r'(mapgis|amap|tianditu|chinadatapay|h5live|livev\d)', host, re.I):
        return {'url_type': 'third_party_or_telemetry', 'is_business_api': False, 'noise_score': 0.92, 'reason': f'third_party_specialized_host:{host}'}
    # H5/webview hosts can belong to the same company but are not backend APIs unless the path itself is API-like.
    try:
        parsed_path = urlsplit(u).path if u.startswith('http') else u
    except Exception:
        parsed_path = u
    if host and re.search(r'(^|\.)(m|p|appmarket|market|trip)\.', host, re.I) and not BUSINESS_PREFIX_RE.search(parsed_path):
        return {'url_type': 'webview_h5_or_marketing', 'is_business_api': False, 'noise_score': 0.75, 'reason': f'h5_or_marketing_host:{host}'}
    if host and parsed_path in ['', '/'] and not BUSINESS_PREFIX_RE.search(parsed_path):
        return {'url_type': 'host_root_or_h5', 'is_business_api': False, 'noise_score': 0.7, 'reason': f'host_without_api_path:{host}'}
    if re.search(
        r'(errlog|monitor|apm|analytics|sensors|beacon|telemetry)|'
        r'(^|/)(track|tracking|log|logs|logging)(/|$|\.)',
        low,
    ):
        return {'url_type': 'telemetry_or_errorlog', 'is_business_api': False, 'noise_score': 0.9, 'reason': 'telemetry_keyword'}
    if BUSINESS_PREFIX_RE.search(u) or BUSINESS_TOKEN_RE.search(' '.join([u, key])):
        return {'url_type': 'business_backend_api', 'is_business_api': True, 'noise_score': 0.0, 'reason': 'business_prefix_or_token'}
    if u.startswith('http') and host and BUSINESS_HOST_RE.search(host) and not STATIC_ASSET_RE.search(u):
        return {'url_type': 'business_backend_api', 'is_business_api': True, 'noise_score': 0.15, 'reason': 'business_like_host'}
    # Multi-segment relative paths are common in URL-builder tables (e.g. /shunke/... /ems/search/...).
    try:
        path_only = urlsplit(u).path if u.startswith('http') else (u.split('?')[0] if u.startswith('/') else '')
    except Exception:
        path_only = ''
    if path_only.startswith('/') and not is_frontend_route_path(path_only) and not STATIC_ASSET_RE.search(path_only):
        segs = [s for s in path_only.split('/') if s]
        if len(segs) >= 2 and all(re.match(r'^[A-Za-z0-9_.-]+$', s) for s in segs[:6]):
            return {
                'url_type': 'business_backend_api',
                'is_business_api': True,
                'noise_score': 0.2,
                'reason': 'multi_segment_relative_path',
            }
    return {'url_type': 'unknown', 'is_business_api': False, 'noise_score': 0.45, 'reason': 'no_business_signal'}


def split_url(url: str | None) -> Tuple[str, str, Tuple[str, ...]]:
    u = clean_raw_url(url)
    if not u:
        return '', '', tuple()
    try:
        sp = urlsplit(u if u.startswith('http') else 'http://placeholder' + (u if u.startswith('/') else '/' + u))
        host = '' if sp.netloc == 'placeholder' else sp.netloc.lower()
        path = re.sub(r'/+', '/', sp.path or '/')
        if path != '/' and path.endswith('/'):
            path = path[:-1]
        query_keys = tuple(sorted(set(k for k, _ in parse_qsl(sp.query, keep_blank_values=True))))
        return host, path, query_keys
    except Exception:
        return '', u.split('?')[0], tuple()


def normalize_endpoint(url: str | None, host: str | None = None) -> Dict[str, Any]:
    u = clean_raw_url(url)
    inferred_host = (host or '').strip().rstrip('/')
    original = u
    if not u:
        return {'normalized_url': None, 'host': inferred_host, 'path': None, 'query_schema': [], 'endpoint_key': None}
    if u.startswith('http'):
        h, path, q = split_url(u)
        normalized_host = h
    else:
        h, path, q = split_url(u)
        normalized_host = re.sub(r'^https?://', '', inferred_host).strip('/') if inferred_host else ''
    if normalized_host:
        scheme = 'https'
        normalized_url = f'{scheme}://{normalized_host}{path}'
    else:
        normalized_url = path
    endpoint_key = normalized_url + (('?' + '&'.join(f'{k}=*' for k in q)) if q else '')
    return {'normalized_url': normalized_url, 'host': normalized_host, 'path': path, 'query_schema': list(q), 'endpoint_key': endpoint_key, 'original_url': original}


def extract_urls_from_text(text: str) -> List[str]:
    out: List[str] = []
    out.extend(m.group(0) for m in HTTP_URL_RE.finditer(text or ''))
    out.extend(m.group(0) for m in PATH_URL_RE.finditer(text or ''))
    # preserve order de-duplicated
    seen, ret = set(), []
    for u in out:
        cu = clean_raw_url(u)
        if cu and cu not in seen:
            seen.add(cu); ret.append(cu)
    return ret


def host_score(host: str) -> float:
    h = (host or '').lower().strip('/').replace('https://','').replace('http://','')
    if not h:
        return 0.0
    if is_excluded_business_host(h):
        return -100.0
    score = 0.0
    if BUSINESS_HOST_RE.search(h):
        score += 3.0
    if re.search(r'(api|gateway|proxy|appmini|mini|service)', h):
        score += 3.0
    if re.search(r'(apiproxy|api\.|gateway)', h):
        score += 4.0
    if NOISE_HOST_RE.search(h):
        score -= 4.0
    if re.search(r'(^|\.)(m|p|appmarket|market|trip)\.', h):
        score -= 1.5
    if re.search(r'(cdn|image|img|static|dfs)', h):
        score -= 2.0
    if re.search(r'(errlog|monitor|apm|analytics|sensors)', h):
        score -= 3.0
    return score
