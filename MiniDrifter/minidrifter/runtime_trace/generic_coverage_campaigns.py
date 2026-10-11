# -*- coding: utf-8 -*-
"""Generic coverage campaigns for single-subject RR-Drift probe (v1.3+).

Families (not app-specific):
  phone_enum, wallet_by_userid, order_lookup, partner_tenant_read,
  zero_auth_write, store_file_export, oauth_cc_zero_auth,
  plus plane_seed from api_plane_index.
"""
from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from minidrifter.materials.har_sequence import (
    filter_har_entries,
    har_entry_to_request,
    looks_like_har,
)

# Import shared selectors / helpers from the probe module (avoid circular import of run_*).
from minidrifter.runtime_trace import single_subject_probe as ssp


PHONE_FIELD_RE = re.compile(
    r'(^phone$|^mobile$|^telephone$|^phoneno$|^phone_no$|^tel$|手机|phoneNo)',
    re.I,
)
PHONE_PATH_RE = re.compile(
    r'(ByPhoneNo|ByPhone|lookupByPhone|bindPhone|bindphone|getPhone|'
    r'phoneLogin|phone-login|check-bind-mobile|reg-bind-mobile|'
    r'sendSMSByMobile|sendToMobile|用户资讯)',
    re.I,
)
WALLET_PATH_RE = re.compile(
    r'(wallet|getBalance|getWallet|coinAccount|membership|/balance|'
    r'beercard/getBalance|银卡|钱包|/user/info|ncoin|accountId)',
    re.I,
)
ORDER_PATH_RE = re.compile(
    r'(findByOrderCode|orderDetail|queryOrderList|queryOrder|'
    r'dgfOrder|MyOrderAll|OrderAll|OrderQuery|order/list|'
    r'/order/.*orderCode|/order/.*orderNo|orderPage|listMiniIndex|'
    r'listRentalPurchase|listMini/v2)',
    re.I,
)
PARTNER_PATH_RE = re.compile(
    r'(partner-info|partnerInfo|tenant|store-partner|corp|企业|租户|'
    r'stock/partner|/partner/)',
    re.I,
)
STORE_EXPORT_PATH_RE = re.compile(
    r'(retailStore|storeInfo|getCinemaRetail|营业执照|businessLicen|'
    r'distributeReward|getCustomerDistribute|goodsSalesGroup|salesDetail|'
    r'priceList|价体|/transactions|流水)',
    re.I,
)
ZERO_AUTH_WRITE_PATH_RE = re.compile(
    r'(offConsultation|closeConsultation|add_patient|updatePatient|'
    r'health.*(?:write|add|update|save)|putOn|putOff)',
    re.I,
)
OAUTH_TOKEN_PATH_RE = re.compile(
    r'(/auth/oauth/token|/oauth/token|/oauth2/token|/oauth/access_token|/connect/token)',
    re.I,
)
# High-value surfaces often opened by server-scope CC tokens (zero user auth)
OAUTH_CC_LEAK_PATH_RE = re.compile(
    r'(cardAmountFlow|amountFlowRecord|flowRecordPage|交易流水|'
    r'getDefaultCardInfo|DefaultCardInfo|cinemaCardInfo|'
    r'intentionletter|intentionLetter|/crm/|销售意向|'
    r'cinema/mobile/info$|cinema/mobile/info\b|getCinemaRetail|retailStoreInfo|'
    r'goodsSalesGroup|getSalesGroupList|salesDetail|StoreCardSales|'
    r'hdfiles|businessLicen|营业执照|license)',
    re.I,
)
NOISE_PATH_RE = re.compile(
    r'(prerequisite-imports|facebook/regenerator|/blob/main/LICENSE|'
    r'world_city|world_effect|ui_hero|ui_login|ui_pay|ui_profile|ui_setting|'
    r'authorization-page|phone-regist/phone-regist|license-regist/license-regist|'
    r'wxaintp/retail|/cube/report|jscode2session|/auth$|w3\.org|'
    r'node_modules|vue-loader|exportHelper|\.vue$|\.wxml$)',
    re.I,
)
USERID_FIELD_RE = re.compile(
    r'^(user_?id|userid|uid|member_?id|customer_?id|operator_?id)$',
    re.I,
)
ORDER_FIELD_RE = re.compile(
    r'(orderCode|orderNo|OrderCode|OrderNo|order_id|orderId)',
    re.I,
)
PARTNER_FIELD_RE = re.compile(
    r'(partnerId|tenantId|partnerCode|storeId|corpId|enterpriseId)',
    re.I,
)
WRITE_OBJ_FIELD_RE = re.compile(
    r'(consultationId|patientId|orderId|memberId|userId|userid|id)$',
    re.I,
)

HIGH_PLANE_IDS = frozenset({
    'account_state_wallet',
    'user_profile_personal_info',
    'realname_verification',
    'action_operation',
    'contact_address_invoice',
})

COVERAGE_FAMILY_SPECS: Dict[str, Dict[str, Any]] = {
    'partner_tenant_pii': {
        'campaigns': {'partner_tenant_read'},
        'path_re': PARTNER_PATH_RE,
    },
    'wallet_by_userid': {
        'campaigns': {'wallet_by_userid'},
        'path_re': WALLET_PATH_RE,
    },
    'order_lookup': {
        'campaigns': {'order_lookup'},
        'path_re': ORDER_PATH_RE,
    },
    'zero_auth_write': {
        'campaigns': {'zero_auth_write'},
        'path_re': ZERO_AUTH_WRITE_PATH_RE,
    },
    'phone_enum': {
        'campaigns': {'phone_enum'},
        'path_re': PHONE_PATH_RE,
    },
    'schema_error_leak': {
        'campaigns': set(),
        'path_re': re.compile(r'.'),
        'signal': 'schema_leak_hit',
    },
    'store_license_export': {
        'campaigns': {'store_file_export'},
        'path_re': STORE_EXPORT_PATH_RE,
    },
    'transaction_bd_pii': {
        'campaigns': {'store_file_export', 'oauth_cc_probe'},
        'path_re': re.compile(
            r'(transaction|distribute|bd|流水|sales|cardAmountFlow|intentionletter)',
            re.I,
        ),
    },
    'oauth_cc_zero_auth': {
        'campaigns': {'oauth_cc_probe'},
        'path_re': OAUTH_CC_LEAK_PATH_RE,
    },
}


def synthetic_phone_donors(primary: Optional[str], *, n: int = 5) -> List[str]:
    """Generate plausible CN mobile neighbors for enum probes."""
    out: List[str] = []
    seen: Set[str] = set()

    def _add(v: str) -> None:
        if v and v not in seen and ssp.PHONE_RE.fullmatch(v):
            seen.add(v)
            out.append(v)

    base = str(primary or '').strip()
    if not ssp.PHONE_RE.fullmatch(base):
        base = '13800138000'
    _add(base)
    try:
        num = int(base)
        for delta in (1, 2, 3, 7, 11, -1, -2, 100, 1000):
            cand = str(num + delta)
            if len(cand) == 11 and cand.startswith('1'):
                _add(cand)
            if len(out) >= n + 1:
                break
    except ValueError:
        pass
    for seed in ('13900139000', '13700137000', '18600000000', '15800000000'):
        _add(seed)
        if len(out) >= n + 1:
            break
    return [x for x in out if x != base][:n] or ['13900139001', '13700137002']


def _load_plane_doc(pack: Path) -> Dict[str, Any]:
    doc = ssp._load_api_plane_index(pack)
    if doc:
        return doc
    for alt in (
        Path(pack).parent / 'api_plane_index.json',
        Path(pack) / 'OUTPUT' / 'api_plane_index.json',
    ):
        raw = ssp._load(alt)
        if isinstance(raw, dict) and (raw.get('path_index') or raw.get('entries')):
            return raw
    return {}


def _har_host_templates(har_path: Path) -> Dict[str, Dict[str, Any]]:
    """Map host -> a representative HAR request item for session reuse."""
    text = har_path.read_text(encoding='utf-8', errors='replace')
    if not looks_like_har(text):
        return {}
    har = json.loads(text)
    entries = filter_har_entries(har.get('log', {}).get('entries') or [], api_only=True)
    by_host: Dict[str, Dict[str, Any]] = {}
    for i, entry in enumerate(entries):
        req = har_entry_to_request(entry)
        url = req.get('url') or ''
        host = urlparse(url).netloc
        if not host:
            continue
        status = int((entry.get('response') or {}).get('status') or 0)
        item = {
            'har_index': i + 1,
            'request': req,
            'response_status': status,
            'response_body': None,
            'path': req.get('path') or '/',
        }
        prev = by_host.get(host)
        if prev is None or (
            status in range(200, 300)
            and int(prev.get('response_status') or 0) not in range(200, 300)
        ):
            by_host[host] = item
    return by_host


def _path_prefix_score(a: str, b: str) -> int:
    sa = [x for x in (a or '').lower().split('/') if x]
    sb = [x for x in (b or '').lower().split('/') if x]
    n = 0
    for x, y in zip(sa, sb):
        if x != y:
            break
        n += 1
    return n


def _pick_host_template(
    host_templates: Dict[str, Dict[str, Any]],
    *,
    path: str,
    preferred_host: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    if not host_templates:
        return None
    if preferred_host and preferred_host in host_templates:
        return host_templates[preferred_host]
    # Prefer hosts whose captured paths share the longest prefix with target
    best: Optional[Dict[str, Any]] = None
    best_score = -1
    for host, item in host_templates.items():
        score = _path_prefix_score(path, item.get('path') or '')
        # slight boost for api-ish hosts
        if re.search(r'(api|gateway|service|h5)', host, re.I):
            score += 1
        if score > best_score:
            best_score = score
            best = item
    return best or next(iter(host_templates.values()))


def _synth_item_from_template(
    template: Dict[str, Any],
    *,
    path: str,
    method: str,
    field: str,
    value: str,
) -> Dict[str, Any]:
    req = copy.deepcopy(template.get('request') or {})
    url = req.get('url') or ''
    parsed = urlparse(url)
    scheme = parsed.scheme or 'https'
    host = parsed.netloc
    method_u = (method or req.get('method') or 'GET').upper()
    query = dict(req.get('query') or {})
    body_form = dict(req.get('body_form') or {})
    body_json = req.get('body_json')
    headers = dict(req.get('headers') or {})
    # Coerce numeric-looking values for JSON bodies
    coerced: Any = value
    if re.fullmatch(r'-?\d+', str(value)):
        try:
            coerced = int(value)
        except ValueError:
            coerced = value
    if method_u == 'GET':
        query = {field: value}
        body_form = {}
        body_json = None
    else:
        want_json = isinstance(body_json, dict) or any(
            'json' in str(v).lower()
            for k, v in headers.items()
            if k.lower() == 'content-type'
        )
        if want_json or method_u in {'POST', 'PUT', 'PATCH'}:
            body_json = {field: coerced}
            body_form = {}
            if not any(k.lower() == 'content-type' for k in headers):
                headers['Content-Type'] = 'application/json;charset=UTF-8'
            else:
                # ensure json content-type when we emit JSON
                for k in list(headers):
                    if k.lower() == 'content-type' and 'json' not in str(headers[k]).lower():
                        headers[k] = 'application/json;charset=UTF-8'
        else:
            body_form = {field: value}
            body_json = None
        query = {}
    new_url = f'{scheme}://{host}{path}'
    req.update({
        'url': new_url,
        'path': path,
        'method': method_u,
        'query': query,
        'body_form': body_form,
        'body_json': body_json,
        'headers': headers,
    })
    return {
        'har_index': 0,
        'request': req,
        'response_status': 200,
        'response_body': None,
        'synthetic': True,
    }


def _paths_from_sources(
    crypto: Optional[Dict[str, Any]],
    har_path: Optional[Path],
    plane: Dict[str, Any],
) -> List[Tuple[str, Optional[Dict[str, Any]], str]]:
    """Yield (path, har_item_or_None, source)."""
    seen: Set[str] = set()
    out: List[Tuple[str, Optional[Dict[str, Any]], str]] = []

    def _add(path: str, item: Optional[Dict[str, Any]], source: str) -> None:
        p = path or '/'
        if NOISE_PATH_RE.search(p):
            return
        key = p.lower()
        if key in seen:
            return
        seen.add(key)
        out.append((p, item, source))

    if crypto:
        for p in crypto.get('paths') or []:
            _add(str(p), None, 'crypto')
    if har_path and har_path.exists():
        text = har_path.read_text(encoding='utf-8', errors='replace')
        if looks_like_har(text):
            har = json.loads(text)
            for i, entry in enumerate(har.get('log', {}).get('entries') or []):
                req = har_entry_to_request(entry)
                path = req.get('path') or '/'
                item = {
                    'har_index': i + 1,
                    'request': req,
                    'response_status': (entry.get('response') or {}).get('status'),
                    'response_body': None,
                }
                _add(path, item, 'har')
    path_index = plane.get('path_index') or {}
    for _k, meta in path_index.items():
        if isinstance(meta, dict):
            _add(meta.get('path') or _k, None, 'plane')
        elif isinstance(meta, str):
            _add(meta, None, 'plane')
    for ent in plane.get('entries') or []:
        if isinstance(ent, dict) and ent.get('path'):
            _add(ent['path'], None, 'plane')
    return out


def _request_bind_fields(req: Dict[str, Any]) -> Dict[str, str]:
    return ssp._request_bind_fields(req)


def _pick_field(req: Dict[str, Any], prefer: re.Pattern) -> Tuple[Optional[str], Optional[str]]:
    binds = _request_bind_fields(req)
    for name, val in binds.items():
        if prefer.search(name):
            return name, str(val)
    for bag in (req.get('query') or {}, req.get('body_form') or {}):
        for k, v in bag.items():
            if prefer.search(str(k)) and v not in (None, ''):
                vv = v[0] if isinstance(v, list) and v else v
                return str(k), str(vv)
    body = req.get('body_json')
    if isinstance(body, dict):
        for k, v in body.items():
            if prefer.search(str(k)) and v not in (None, '') and not isinstance(v, (dict, list)):
                return str(k), str(v)
    return None, None


def _mk_target(
    *,
    campaign: str,
    path: str,
    field: str,
    primary: str,
    donor: str,
    donor_class: str,
    item: Dict[str, Any],
    method: str,
    score: float,
    is_write: bool = False,
    allow_weak_m0: bool = True,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    t: Dict[str, Any] = {
        'kind': 'har_plain' if not item.get('synthetic') else 'plane_seed',
        'campaign': campaign,
        'score': score,
        'path': path,
        'field': field,
        'primary': primary,
        'donor': donor,
        'donor_class': donor_class,
        'item': item,
        'method': method,
        'require_response_delta': True,
        'is_write': is_write,
        'allow_weak_m0': allow_weak_m0,
        'content_oracle': campaign in {
            'phone_enum', 'partner_tenant_read', 'store_file_export', 'order_lookup',
            'oauth_cc_probe',
        },
    }
    if extra:
        t.update(extra)
    return t


def select_phone_enum_targets(
    paths: List[Tuple[str, Optional[Dict[str, Any]], str]],
    multiset: Dict[str, List[str]],
    host_templates: Dict[str, Dict[str, Any]],
    *,
    max_targets: int = 6,
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for path, item, _src in paths:
        if OAUTH_TOKEN_PATH_RE.search(path):
            continue
        field = None
        primary = None
        method = 'GET'
        if item:
            req = item.get('request') or {}
            method = (req.get('method') or 'GET').upper()
            field, primary = _pick_field(req, PHONE_FIELD_RE)
            if not field and not PHONE_PATH_RE.search(path):
                continue
            if not field:
                if not re.search(r'ByPhone|phone|mobile|telephone', path, re.I):
                    continue
                field = 'phoneNo'
                primary = (multiset.get('phoneNo') or multiset.get('mobile') or ['13800138000'])[0]
        else:
            if not PHONE_PATH_RE.search(path):
                continue
            field = 'phoneNo'
            primary = (multiset.get('phoneNo') or multiset.get('mobile') or ['13800138000'])[0]
            if not host_templates:
                continue
            tmpl = _pick_host_template(host_templates, path=path)
            if not tmpl:
                continue
            item = _synth_item_from_template(
                tmpl, path=path, method='GET', field=field, value=str(primary),
            )
            item['synthetic'] = True
        donors = synthetic_phone_donors(primary)
        if not donors:
            continue
        out.append(_mk_target(
            campaign='phone_enum',
            path=path,
            field=field or 'phoneNo',
            primary=str(primary),
            donor=donors[0],
            donor_class='synthetic',
            item=item,
            method=method,
            score=16.0,
            allow_weak_m0=True,
            extra={'phone_donors': donors[:4]},
        ))
        if len(out) >= max_targets:
            break
    return out


def _oauth_cc_prepare_item(
    *,
    path: str,
    item: Optional[Dict[str, Any]],
    host_templates: Dict[str, Dict[str, Any]],
    field: str,
    primary: str,
    method: str,
    preferred_hosts: Optional[List[str]] = None,
) -> Optional[Dict[str, Any]]:
    if item and not item.get('synthetic') and (item.get('request') or {}).get('url'):
        # Rebind host if capture was on CDN/noise but path is API
        req = item.get('request') or {}
        host = urlparse(req.get('url') or '').netloc
        if preferred_hosts and host and host not in preferred_hosts:
            pass  # still usable if it worked in HAR
        else:
            return item
    if not host_templates:
        return None
    tmpl = None
    for host in preferred_hosts or []:
        if host in host_templates:
            tmpl = host_templates[host]
            break
    if tmpl is None:
        # Prefer API-ish hosts over CDN/analytics
        best_score = -1
        for host, cand in host_templates.items():
            score = 0
            if re.search(r'(api|center|gateway|service|bruts)', host, re.I):
                score += 5
            if re.search(r'(obs|cdn|hmma|baidu|report|wxgateway)', host, re.I):
                score -= 5
            cpath = cand.get('path') or ''
            if re.search(r'(card|cinema|goods|admin|order|auth)', cpath, re.I):
                score += 3
            if int(cand.get('response_status') or 0) in range(200, 300):
                score += 2
            if score > best_score:
                best_score = score
                tmpl = cand
    if tmpl is None:
        tmpl = _pick_host_template(host_templates, path=path)
    if not tmpl:
        return None
    prefer_post = bool(re.search(
        r'(Page|page|List|list|Flow|flow|intention|SalesGroup|salesDetail|'
        r'cinema/mobile/info$)',
        path,
    ))
    method_u = 'POST' if prefer_post else (method or 'GET').upper()
    if re.search(r'getDefaultCardInfo', path, re.I):
        method_u = 'GET'
    syn = _synth_item_from_template(
        tmpl, path=path, method=method_u, field=field, value=str(primary),
    )
    syn['synthetic'] = True
    req = syn.get('request') or {}
    if method_u == 'POST':
        body: Dict[str, Any] = {'current': 1, 'size': 5}
        if re.search(r'intention', path, re.I):
            body['entity'] = {}
        if re.search(r'cinema/mobile/info$', path, re.I):
            body = {'domain': str(primary)}
        if re.search(r'SalesGroupList|getSalesGroupList', path, re.I):
            body = {}
        if re.search(r'cardAmountFlow|FlowRecordPage', path, re.I):
            body = {'current': 1, 'size': 5}
        req['body_json'] = body
        req['body_form'] = {}
        req['body_raw'] = json.dumps(body, ensure_ascii=False)
        headers = dict(req.get('headers') or {})
        headers['Content-Type'] = 'application/json;charset=UTF-8'
        req['headers'] = headers
        req['method'] = 'POST'
        syn['request'] = req
    return syn


def select_oauth_cc_targets(
    paths: List[Tuple[str, Optional[Dict[str, Any]], str]],
    multiset: Dict[str, List[str]],
    host_templates: Dict[str, Dict[str, Any]],
    *,
    max_targets: int = 8,
    oauth_material: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """High-value APIs under minted OAuth client_credentials Bearer (zero user auth)."""
    preferred_hosts: List[str] = []
    for u in (oauth_material or {}).get('token_urls') or []:
        h = urlparse(u).netloc
        if h and h not in preferred_hosts:
            preferred_hosts.append(h)
    out: List[Dict[str, Any]] = []
    for path, item, _src in paths:
        if NOISE_PATH_RE.search(path) or OAUTH_TOKEN_PATH_RE.search(path):
            continue
        if not OAUTH_CC_LEAK_PATH_RE.search(path):
            continue
        # CDN / broken placeholders are low value for CC mint probes
        if re.search(r'undefined|/hdFiles/|/hdfiles/|\.png$|\.jpg$', path, re.I):
            continue
        # Prefer concrete leak endpoints over parent stubs
        if re.search(r'/intentionletter$', path, re.I):
            continue
        if re.search(r'intentionletter/addItem', path, re.I):
            continue
        field = 'customerId'
        primary = (
            (multiset.get('customerId') or multiset.get('CustomerId')
             or multiset.get('userId') or multiset.get('userid')
             or multiset.get('domain') or ['1'])[0]
        )
        method = 'GET'
        if item:
            req = item.get('request') or {}
            method = (req.get('method') or 'GET').upper()
            f2, p2 = _pick_field(
                req,
                re.compile(
                    r'(customerId|CustomerId|userId|userid|storeId|domain|current|salesId)',
                    re.I,
                ),
            )
            if f2:
                field, primary = f2, p2 or primary
        prepared = _oauth_cc_prepare_item(
            path=path, item=item, host_templates=host_templates,
            field=field, primary=str(primary), method=method,
            preferred_hosts=preferred_hosts,
        )
        if not prepared:
            continue
        req2 = prepared.get('request') or {}
        method = (req2.get('method') or method or 'GET').upper()
        donors = ssp._synthetic_object_donors(str(primary), extra=(
            (multiset.get(field) or [])[1:6]
        ))
        if not donors:
            donors = [d for d in ('2', '3', '9') if d != str(primary)] or ['9']
        score = 18.0
        if re.search(r'(getDefaultCardInfo|cardAmountFlow|intentionletter/page)', path, re.I):
            score = 22.0
        elif re.search(r'(cinema/mobile/info$|getSalesGroupList|salesDetail)', path, re.I):
            score = 20.0
        out.append(_mk_target(
            campaign='oauth_cc_probe',
            path=path,
            field=field,
            primary=str(primary),
            donor=str(donors[0]),
            donor_class='synthetic',
            item=prepared,
            method=method,
            score=score,
            allow_weak_m0=True,
            extra={
                'attach_cc_bearer': True,
                'content_oracle': True,
                'require_response_delta': False,
                'strip_auth': False,
                'zero_auth': False,
            },
        ))
    out.sort(key=lambda x: -float(x.get('score') or 0))
    return out[:max_targets]


def select_wallet_by_userid_targets(
    paths: List[Tuple[str, Optional[Dict[str, Any]], str]],
    multiset: Dict[str, List[str]],
    host_templates: Dict[str, Dict[str, Any]],
    *,
    max_targets: int = 6,
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for path, item, _src in paths:
        if not WALLET_PATH_RE.search(path) and not re.search(
            r'getUserInfoByUid|getBalance|wallet', path, re.I,
        ):
            continue
        field = 'userid'
        primary = (
            (multiset.get('userid') or multiset.get('userId') or multiset.get('user_id')
             or multiset.get('customerId') or ['10001'])[0]
        )
        method = 'GET'
        if item:
            req = item.get('request') or {}
            method = (req.get('method') or 'GET').upper()
            f2, p2 = _pick_field(req, USERID_FIELD_RE)
            if f2:
                field, primary = f2, p2 or primary
        else:
            if not host_templates:
                continue
            tmpl = _pick_host_template(host_templates, path=path)
            if not tmpl:
                continue
            item = _synth_item_from_template(
                tmpl, path=path, method='GET', field=field, value=str(primary),
            )
            item['synthetic'] = True
        donors = ssp._synthetic_object_donors(str(primary), extra=(
            (multiset.get(field) or [])[1:6]
        ))
        if not donors:
            continue
        out.append(_mk_target(
            campaign='wallet_by_userid',
            path=path,
            field=field,
            primary=str(primary),
            donor=donors[0],
            donor_class='synthetic',
            item=item,
            method=method,
            score=17.0,
            allow_weak_m0=True,
        ))
        if len(out) >= max_targets:
            break
    return out


def select_order_lookup_targets(
    paths: List[Tuple[str, Optional[Dict[str, Any]], str]],
    multiset: Dict[str, List[str]],
    host_templates: Dict[str, Dict[str, Any]],
    *,
    max_targets: int = 6,
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for path, item, _src in paths:
        if not ORDER_PATH_RE.search(path):
            continue
        field = 'orderCode'
        primary = (
            (multiset.get('orderCode') or multiset.get('orderNo')
             or multiset.get('orderId') or ['ORD10001'])[0]
        )
        method = 'GET'
        # Order list/query surfaces are usually keyed by subject uid, not a fake ORD*.
        if re.search(r'(OrderQuery|MyOrderAll|OrderAll|dgfOrderQuery|/order/list)', path, re.I):
            if multiset.get('uid') or multiset.get('userId') or multiset.get('userid'):
                field = 'uid' if multiset.get('uid') else ('userId' if multiset.get('userId') else 'userid')
                primary = (multiset.get(field) or [primary])[0]
            elif multiset.get('orderId'):
                field, primary = 'orderId', multiset['orderId'][0]
        if item:
            req = item.get('request') or {}
            method = (req.get('method') or 'GET').upper()
            f2, p2 = _pick_field(req, ORDER_FIELD_RE)
            if f2:
                field, primary = f2, p2 or primary
            elif not re.search(r'findByOrderCode|orderDetail|orderNo|orderCode', path, re.I):
                binds = _request_bind_fields(req)
                for cand in ('orderId', 'OrderId', 'customerId', 'orderCode', 'orderNo'):
                    if cand in binds:
                        field, primary = cand, binds[cand]
                        break
                else:
                    if not binds:
                        continue
                    field, primary = next(iter(binds.items()))
        else:
            if not host_templates:
                continue
            tmpl = _pick_host_template(host_templates, path=path)
            if not tmpl:
                continue
            item = _synth_item_from_template(
                tmpl, path=path, method='GET', field=field, value=str(primary),
            )
            item['synthetic'] = True
        donors = ssp._synthetic_object_donors(str(primary), extra=(
            (multiset.get(field) or [])[1:6]
        ))
        if not donors:
            continue
        out.append(_mk_target(
            campaign='order_lookup',
            path=path,
            field=field,
            primary=str(primary),
            donor=donors[0],
            donor_class='synthetic',
            item=item,
            method=method,
            score=15.5,
            allow_weak_m0=True,
        ))
        if len(out) >= max_targets:
            break
    return out


def select_partner_tenant_targets(
    paths: List[Tuple[str, Optional[Dict[str, Any]], str]],
    multiset: Dict[str, List[str]],
    host_templates: Dict[str, Dict[str, Any]],
    *,
    max_targets: int = 8,
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    # Prefer partner-info / tenant PII surfaces first
    ordered = sorted(
        paths,
        key=lambda t: (
            0 if re.search(r'partner-info|partnerInfo|tenant', t[0] or '', re.I) else 1,
            0 if t[1] is not None else 1,
            t[0] or '',
        ),
    )
    for path, item, _src in ordered:
        if not PARTNER_PATH_RE.search(path):
            continue
        field = 'partnerId'
        primary = (
            (multiset.get('partnerId') or multiset.get('tenantId')
             or multiset.get('storeId') or multiset.get('customerId') or ['1'])[0]
        )
        method = 'GET'
        if item:
            req = item.get('request') or {}
            method = (req.get('method') or 'GET').upper()
            f2, p2 = _pick_field(req, PARTNER_FIELD_RE)
            if f2:
                field, primary = f2, p2 or primary
            else:
                binds = _request_bind_fields(req)
                if binds:
                    field, primary = next(iter(binds.items()))
        else:
            if not host_templates:
                continue
            tmpl = _pick_host_template(host_templates, path=path)
            if not tmpl:
                continue
            item = _synth_item_from_template(
                tmpl, path=path, method='GET', field=field, value=str(primary),
            )
            item['synthetic'] = True
        donors = ssp._synthetic_object_donors(str(primary), extra=(
            (multiset.get(field) or [])[1:6]
        ))
        # Prefer nearby numeric IDs (foreign stock/partner often clustered).
        # Keep ascending neighbor order so primary-3/-2 are tried before empty holes.
        nearby: List[str] = []
        if str(primary).isdigit():
            base = int(primary)
            for delta in (-3, -2, -1, 1, 2, 3, 5, 10, 17, 37):
                cand = str(base + delta)
                if int(cand) > 0 and cand != str(primary) and cand not in nearby:
                    nearby.append(cand)
        merged = nearby + [d for d in donors if d not in nearby and d != str(primary)]
        donors = merged
        if not donors:
            continue
        # Emit up to 2 donors for partner-info style surfaces (raise DataLeak odds)
        for di, donor in enumerate(donors[:2]):
            out.append(_mk_target(
                campaign='partner_tenant_read',
                path=path,
                field=field,
                primary=str(primary),
                donor=donor,
                donor_class='synthetic',
                item=item,
                method=method,
                score=18.0 - di * 0.1,
                allow_weak_m0=True,
                extra={'content_oracle': True},
            ))
            if len(out) >= max_targets:
                break
        if len(out) >= max_targets:
            break
    return out


def select_zero_auth_write_targets(
    paths: List[Tuple[str, Optional[Dict[str, Any]], str]],
    multiset: Dict[str, List[str]],
    host_templates: Dict[str, Dict[str, Any]],
    *,
    max_targets: int = 3,
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for path, item, _src in paths:
        if not (ZERO_AUTH_WRITE_PATH_RE.search(path) or ssp.WRITE_PATH_RE.search(path)):
            continue
        if re.search(r'unbind|UnBind', path) and not ZERO_AUTH_WRITE_PATH_RE.search(path):
            continue
        field = 'consultationId'
        primary = (
            (multiset.get('consultationId') or multiset.get('patientId')
             or multiset.get('userId') or multiset.get('userid') or ['1'])[0]
        )
        method = 'GET'
        if item:
            req = item.get('request') or {}
            method = (req.get('method') or 'GET').upper()
            f2, p2 = _pick_field(req, WRITE_OBJ_FIELD_RE)
            if f2:
                field, primary = f2, p2 or primary
            else:
                binds = _request_bind_fields(req)
                if binds:
                    field, primary = next(iter(binds.items()))
        else:
            if not host_templates:
                continue
            method = 'GET'
            tmpl = _pick_host_template(host_templates, path=path)
            if not tmpl:
                continue
            item = _synth_item_from_template(
                tmpl, path=path, method=method, field=field, value=str(primary),
            )
            item['synthetic'] = True
        donors = ssp._synthetic_object_donors(str(primary))
        if not donors:
            continue
        out.append(_mk_target(
            campaign='zero_auth_write',
            path=path,
            field=field,
            primary=str(primary),
            donor=donors[0],
            donor_class='synthetic',
            item=item,
            method=method,
            score=19.0,
            is_write=True,
            allow_weak_m0=True,
            extra={
                'session_override_primary': {'token': ''},
                'session_override_donor': {'token': ''},
                'strip_auth': True,
                'zero_auth': True,
            },
        ))
        if len(out) >= max_targets:
            break
    return out


def select_store_file_export_targets(
    paths: List[Tuple[str, Optional[Dict[str, Any]], str]],
    multiset: Dict[str, List[str]],
    host_templates: Dict[str, Dict[str, Any]],
    *,
    max_targets: int = 8,
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for path, item, _src in paths:
        if not STORE_EXPORT_PATH_RE.search(path):
            continue
        field = 'storeId'
        primary = (
            (multiset.get('storeId') or multiset.get('cinemaId')
             or multiset.get('customerId') or multiset.get('id') or ['1'])[0]
        )
        method = 'GET'
        if item:
            req = item.get('request') or {}
            method = (req.get('method') or 'GET').upper()
            binds = _request_bind_fields(req)
            if binds:
                for cand in (
                    'storeId', 'cinemaId', 'customerId', 'id', 'userId', 'goodsId', 'titleId',
                ):
                    if cand in binds:
                        field, primary = cand, binds[cand]
                        break
                else:
                    field, primary = next(iter(binds.items()))
            else:
                field, primary = 'page', '1'
        else:
            if not host_templates:
                continue
            tmpl = _pick_host_template(host_templates, path=path)
            if not tmpl:
                continue
            item = _synth_item_from_template(
                tmpl, path=path, method='GET', field=field, value=str(primary),
            )
            item['synthetic'] = True
        donors = ssp._synthetic_object_donors(str(primary), extra=(
            (multiset.get(field) or [])[1:4]
        ))
        donor = donors[0] if donors else (str(int(primary) + 1) if str(primary).isdigit() else '2')
        out.append(_mk_target(
            campaign='store_file_export',
            path=path,
            field=field,
            primary=str(primary),
            donor=donor,
            donor_class='synthetic',
            item=item,
            method=method,
            score=16.5,
            allow_weak_m0=True,
        ))
        if len(out) >= max_targets:
            break
    return out


def select_plane_seed_targets(
    pack: Path,
    har_path: Path,
    *,
    multiset: Optional[Dict[str, List[str]]] = None,
    max_targets: int = 12,
) -> List[Dict[str, Any]]:
    """Seed probes for high-sensitivity plane paths missing from HAR."""
    plane = _load_plane_doc(pack)
    if not plane:
        return []
    host_templates = _har_host_templates(har_path)
    if not host_templates:
        return []
    multiset = multiset or {}
    har_paths: Set[str] = set()
    text = har_path.read_text(encoding='utf-8', errors='replace')
    if looks_like_har(text):
        har = json.loads(text)
        for entry in har.get('log', {}).get('entries') or []:
            req = har_entry_to_request(entry)
            har_paths.add((req.get('path') or '/').lower())

    out: List[Dict[str, Any]] = []
    entries = list(plane.get('entries') or [])
    if not entries and plane.get('path_index'):
        for _k, meta in (plane.get('path_index') or {}).items():
            if isinstance(meta, dict):
                entries.append(meta)
            elif isinstance(meta, str):
                entries.append({'path': meta, 'primary_plane': 'business_object'})

    for ent in entries:
        if not isinstance(ent, dict):
            continue
        path = ent.get('path') or ''
        if not path or path.lower() in har_paths:
            continue
        if NOISE_PATH_RE.search(path):
            continue
        # Do not graft SDK-template paths (e.g. APIFM /partner, /deposit) onto a
        # live host unless the first path segment was actually seen in τ_A.
        segs = [s.lower() for s in path.split('/') if s]
        first = segs[0] if segs else ''
        if first and not any(
            [h for h in hp.split('/') if h][:1] == [first]
            for hp in har_paths
        ):
            continue
        plane_id = ent.get('primary_plane') or ''
        sens = float(ent.get('sensitivity_score') or 0)
        if plane_id not in HIGH_PLANE_IDS and sens < 0.7 and not ssp.HIGH_VALUE_PATH_RE.search(path):
            continue
        # Skip generic plane_seed for low-signal action/environment without family regex
        family_hit = bool(
            WALLET_PATH_RE.search(path) or PARTNER_PATH_RE.search(path)
            or ZERO_AUTH_WRITE_PATH_RE.search(path) or PHONE_PATH_RE.search(path)
            or ORDER_PATH_RE.search(path) or STORE_EXPORT_PATH_RE.search(path)
            or plane_id in {
                'account_state_wallet', 'user_profile_personal_info', 'realname_verification',
            }
        )
        if not family_hit:
            continue
        method = str(ent.get('method') or 'GET').upper()
        if method == 'UNKNOWN':
            method = 'GET'
        if plane_id == 'account_state_wallet' or WALLET_PATH_RE.search(path):
            field = 'userid'
            primary = (multiset.get('userid') or multiset.get('userId') or ['10001'])[0]
            campaign = 'wallet_by_userid'
            score = 14.0
        elif PARTNER_PATH_RE.search(path):
            field = 'partnerId'
            primary = (multiset.get('partnerId') or ['1'])[0]
            campaign = 'partner_tenant_read'
            score = 14.5
        elif ZERO_AUTH_WRITE_PATH_RE.search(path):
            field = 'consultationId'
            primary = (multiset.get('consultationId') or ['1'])[0]
            campaign = 'zero_auth_write'
            score = 15.0
            method = method if method in {'GET', 'POST'} else 'GET'
        elif PHONE_PATH_RE.search(path):
            field = 'phoneNo'
            primary = (multiset.get('phoneNo') or ['13800138000'])[0]
            campaign = 'phone_enum'
            score = 14.0
        elif ORDER_PATH_RE.search(path):
            field = 'orderCode'
            primary = (multiset.get('orderCode') or ['ORD1'])[0]
            campaign = 'order_lookup'
            score = 13.5
        elif STORE_EXPORT_PATH_RE.search(path):
            field = 'storeId'
            primary = (multiset.get('storeId') or ['1'])[0]
            campaign = 'store_file_export'
            score = 14.0
        else:
            field = 'userId'
            primary = (multiset.get('userId') or multiset.get('userid') or ['1'])[0]
            campaign = 'plane_seed'
            score = 12.0
        tmpl = _pick_host_template(host_templates, path=path)
        if not tmpl:
            continue
        item = _synth_item_from_template(
            tmpl, path=path, method=method, field=field, value=str(primary),
        )
        item['synthetic'] = True
        donors = (
            synthetic_phone_donors(primary)
            if campaign == 'phone_enum'
            else ssp._synthetic_object_donors(str(primary))
        )
        if not donors:
            continue
        extra: Dict[str, Any] = {'plane_id': plane_id, 'plane_seeded': True}
        if campaign == 'zero_auth_write':
            extra.update({
                'strip_auth': True,
                'zero_auth': True,
                'session_override_donor': {'token': ''},
            })
        out.append(_mk_target(
            campaign=campaign,
            path=path,
            field=field,
            primary=str(primary),
            donor=donors[0],
            donor_class='synthetic',
            item=item,
            method=method,
            score=score,
            is_write=(campaign == 'zero_auth_write'),
            allow_weak_m0=True,
            extra=extra,
        ))
        if len(out) >= max_targets:
            break
    return out


def select_generic_coverage_campaigns(
    *,
    crypto: Optional[Dict[str, Any]],
    pack: Path,
    har_path: Path,
    multiset: Dict[str, List[str]],
    max_targets: int = 20,
    oauth_material: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    plane = _load_plane_doc(pack)
    host_templates = _har_host_templates(har_path)
    paths = _paths_from_sources(crypto, har_path, plane)
    if not plane:
        print('[ss] api_plane_index missing — generic campaigns use HAR/crypto paths only', flush=True)

    buckets: List[List[Dict[str, Any]]] = []
    if oauth_material and oauth_material.get('ok'):
        buckets.append(
            select_oauth_cc_targets(
                paths, multiset, host_templates, max_targets=8,
                oauth_material=oauth_material,
            ),
        )
    buckets.extend([
        select_partner_tenant_targets(paths, multiset, host_templates, max_targets=8),
        select_wallet_by_userid_targets(paths, multiset, host_templates, max_targets=4),
        select_order_lookup_targets(paths, multiset, host_templates, max_targets=4),
        select_phone_enum_targets(paths, multiset, host_templates, max_targets=4),
        select_store_file_export_targets(paths, multiset, host_templates, max_targets=5),
        select_zero_auth_write_targets(paths, multiset, host_templates, max_targets=3),
        select_plane_seed_targets(pack, har_path, multiset=multiset, max_targets=8),
    ])
    merged: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    for bucket in buckets:
        for t in bucket:
            key = f"{t.get('campaign')}::{t.get('path')}::{t.get('field')}::{t.get('donor')}"
            if key in seen:
                continue
            seen.add(key)
            merged.append(t)
    merged.sort(key=lambda x: -float(x.get('score') or 0))
    return merged[:max_targets]


def build_coverage_families(
    targets: List[Dict[str, Any]],
    results: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Summarize whether each vuln family was targeted / hit / blocked."""
    families: Dict[str, Dict[str, Any]] = {}
    for fam, spec in COVERAGE_FAMILY_SPECS.items():
        families[fam] = {
            'status': 'not_targeted',
            'paths': [],
            'campaigns': [],
            'labels': [],
        }

    def _touch(fam: str, path: str, campaign: Optional[str], status: str, label: Optional[str] = None) -> None:
        row = families[fam]
        if path and path not in row['paths']:
            row['paths'].append(path)
        if campaign and campaign not in row['campaigns']:
            row['campaigns'].append(campaign)
        if label and label not in row['labels']:
            row['labels'].append(label)
        order = {
            'not_targeted': 0, 'attempted': 1, 'blocked_m0': 2,
            'blocked_mint': 2, 'hit': 3,
        }
        if order.get(status, 0) > order.get(row['status'], 0):
            row['status'] = status

    for t in targets:
        path = t.get('path') or ''
        camp = t.get('campaign') or ''
        for fam, spec in COVERAGE_FAMILY_SPECS.items():
            if fam == 'schema_error_leak':
                continue
            if camp in (spec.get('campaigns') or set()) or (spec.get('path_re') and spec['path_re'].search(path)):
                _touch(fam, path, camp or None, 'attempted')

    for r in results:
        path = r.get('path') or ''
        camp = r.get('campaign') or ''
        label = r.get('label') or r.get('status')
        st = r.get('status')
        positive = bool(r.get('positive'))
        schema_hit = bool(r.get('schema_leak_hit') or (r.get('leak_summary') or {}).get('m5_schema'))
        if schema_hit:
            _touch('schema_error_leak', path, camp or None, 'hit' if (positive or schema_hit) else 'attempted', label)
        for fam, spec in COVERAGE_FAMILY_SPECS.items():
            if fam == 'schema_error_leak':
                continue
            matched = camp in (spec.get('campaigns') or set()) or (
                spec.get('path_re') and spec['path_re'].search(path)
            )
            if not matched:
                continue
            if positive:
                _touch(fam, path, camp or None, 'hit', label)
            elif st in {'m0_failed', 'mint_failed'}:
                _touch(
                    fam, path, camp or None,
                    'blocked_mint' if st == 'mint_failed' else 'blocked_m0',
                    label,
                )
            else:
                _touch(fam, path, camp or None, 'attempted', label)

    return families


def m0_ladder_eligible(target: Dict[str, Any]) -> bool:
    camp = str(target.get('campaign') or '')
    if camp == 'oauth_cc_probe' or target.get('attach_cc_bearer'):
        return False  # CC Bearer path — never strip-auth ladder
    if camp in ssp.M0_LADDER_CAMPAIGNS or camp.startswith('invoice_'):
        return True
    if target.get('strip_auth') or target.get('zero_auth') or target.get('allow_weak_m0'):
        if camp or ssp.HIGH_VALUE_PATH_RE.search(target.get('path') or ''):
            return True
    path = target.get('path') or ''
    if target.get('is_write') and not (
        camp == 'zero_auth_write' or ZERO_AUTH_WRITE_PATH_RE.search(path)
    ):
        return False
    return bool(ssp.HIGH_VALUE_PATH_RE.search(path))


def strip_auth_from_test_case(test_case: Dict[str, Any]) -> Dict[str, Any]:
    tc = copy.deepcopy(test_case)
    headers = dict(tc.get('headers') or {})
    for k in list(headers):
        if ssp.IDENTITY_RE.match(k) or k.lower() in {'cookie', 'token', 'x-token'}:
            headers.pop(k, None)
    tc['headers'] = headers
    for bag_name in ('params', 'body_params'):
        bag = tc.get(bag_name)
        if isinstance(bag, dict):
            for k in list(bag):
                if ssp.IDENTITY_RE.match(str(k)) or str(k).lower() in {
                    'token', 'access_token', 'session', 'authorization',
                }:
                    bag[k] = ''
    return tc
