# -*- coding: utf-8 -*-
"""Executable node-level (M_i) and workflow-level (W_t) alternatives.

RCR ``materialization`` is a transform *inventory* (AES/HMAC/...). Fig.4 Node
feedback needs finite request-construction alternatives. Path-level feedback
needs another evidence-supported r_j in the RPGraph / Cross-API Business Credential Dependency Graph, not a
stub ``return None``.
"""
from __future__ import annotations

import re
import time
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from minidrifter.verification.subject_override_mutation import (
    refine_source_from_feedback,
)

MAX_NODE_ALTS = 8
MAX_WORKFLOW_ALTS = 8

_FILL_SKIP = frozenset({
    'token', 'authorization', 'appidentity', 'appversion', 'appplatform',
    'channelid', 'bycityid',
})
_CANON_PARAM = {
    'titleid': 'titleId',
    'bindid': 'BindId',
    'unionid': 'unionId',
    'userid': 'userId',
    'byuserid': 'ByUserId',
    'openid': 'openId',
    'phonenumber': 'phoneNumber',
}

EXECUTABLE_KINDS = {
    'method_switch',
    'transport',
    'placement',
    'drop_nulls',
    'fill_har',
    'fill_missing_ids',
    'fill_session',
    'field_alias',
    'transform',
    'drift_source',
    'rebuild_fresh',
    'restore_binding',
}

_FRESH_FIELDS = frozenset({
    'timestamp', 'ts', 'time', 'nonce', 'noncestr', 'requesttime', '_t',
})
_SIGN_FIELDS = frozenset({'sign', 'signature'})
_IDENTITY_HINT = re.compile(r'身份|不一致|identity|subject|绑定人', re.I)
_FRESH_HINT = re.compile(r'过期|timestamp|nonce|签名|signature|sign invalid', re.I)
_MAX_DRIFT_DISTANCE = 3


def norm_path(path: str) -> str:
    return (path or '').rstrip('/').lower()


def _norm_method(method: Any) -> str:
    m = str(method or 'GET').upper().strip()
    return m or 'GET'


def _har_query_keys(har_entry: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    req = (har_entry or {}).get('request') or {}
    out: Dict[str, Any] = {}
    for bag in (req.get('query') or {}, req.get('body_form') or {}, req.get('body_json') or {}):
        if isinstance(bag, dict):
            for k, v in bag.items():
                if v in (None, '', [], {}):
                    continue
                out[str(k)] = v[0] if isinstance(v, list) and v else v
    return out


def _ccr_fields(ccrs: Optional[Iterable[Dict[str, Any]]]) -> List[str]:
    names: List[str] = []
    for RCR in ccrs or []:
        rs = RCR.get('request_semantics') or {}
        for item in rs.get('credentials') or []:
            names.append(str(item))
        for item in RCR.get('binding_credentials') or []:
            names.append(str(item))
        for ev in RCR.get('evidence') or []:
            if isinstance(ev, dict) and ev.get('field'):
                names.append(str(ev['field']))
        for p in RCR.get('params') or []:
            if isinstance(p, dict) and p.get('name'):
                names.append(str(p['name']))
            elif isinstance(p, str):
                names.append(p)
    return names


def _alias_pairs(current_keys: Iterable[str], candidate_keys: Iterable[str]) -> List[Tuple[str, str]]:
    """userId↔UserId; userId↔ByUserId when one is a suffix of the other."""
    pairs: List[Tuple[str, str]] = []
    seen: Set[Tuple[str, str]] = set()
    cur = [str(k) for k in current_keys if k]
    cand = [str(k) for k in candidate_keys if k]
    pool = list(dict.fromkeys(cur + cand))
    for src in cur:
        sl = src.lower()
        for dst in pool:
            if src == dst:
                continue
            dl = dst.lower()
            if sl == dl:
                key = (src, dst)
            elif len(sl) >= 4 and len(dl) >= 4 and (sl.endswith(dl) or dl.endswith(sl)):
                key = (src, dst)
            else:
                continue
            if key in seen:
                continue
            seen.add(key)
            pairs.append(key)
    return pairs[:6]


def methods_for_path(
    path: str,
    *,
    bcg: Optional[Dict[str, Any]] = None,
    ccrs: Optional[Iterable[Dict[str, Any]]] = None,
    har_entry: Optional[Dict[str, Any]] = None,
) -> Set[str]:
    found: Set[str] = set()
    np = norm_path(path)
    har_m = ((har_entry or {}).get('request') or {}).get('method')
    if har_m:
        found.add(_norm_method(har_m))
    for n in (bcg or {}).get('nodes') or []:
        if norm_path(n.get('path') or '') == np and n.get('method'):
            found.add(_norm_method(n.get('method')))
    for RCR in ccrs or []:
        ep = (RCR.get('endpoint') or {}).get('path') or ''
        if norm_path(ep) != np:
            continue
        mv = (RCR.get('method') or {}).get('value') if isinstance(RCR.get('method'), dict) else RCR.get('method')
        if mv:
            found.add(_norm_method(mv))
    return found


def ccrs_for_path(path: str, ccrs: Optional[Iterable[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    np = norm_path(path)
    out = []
    for RCR in ccrs or []:
        ep = (RCR.get('endpoint') or {}).get('path') or ''
        if norm_path(ep) == np:
            out.append(RCR)
    return out


def _concrete(value: Any) -> Optional[str]:
    if value in (None, '', [], {}):
        return None
    if isinstance(value, dict):
        return None
    return str(value)


def _baseline_values(step: Dict[str, Any], har_entry: Optional[Dict[str, Any]]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for key, value in (step.get('inputs') or {}).items():
        text = _concrete(value)
        if text is not None:
            out[str(key)] = text
    for key, value in _har_query_keys(har_entry).items():
        out.setdefault(str(key), str(value))
    return out


def _drift_source_alts(
    step: Dict[str, Any],
    har_entry: Optional[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """First structure-preserving candidate for the source credential only."""
    baseline = _baseline_values(step, har_entry)
    alts: List[Dict[str, Any]] = []
    for field in step.get('drift_fields') or []:
        original = None
        for key, value in baseline.items():
            if str(key).lower() == str(field).lower():
                original = value
                break
        if not original:
            continue
        refined, strategy = refine_source_from_feedback(str(field), original, distance=1)
        if not refined:
            continue
        alts.append({
            'id': f'alt:drift_source:{field}:d1',
            'kind': 'drift_source',
            'field': str(field),
            'original': original,
            'value': refined,
            'distance': 1,
            'strategy': strategy,
            'source': 'baseline_pattern',
        })
        break
    return alts


def _rebuild_fresh_alt(
    step: Dict[str, Any],
    har_entry: Optional[Dict[str, Any]],
    *,
    has_crypto: bool,
) -> Optional[Dict[str, Any]]:
    baseline = _baseline_values(step, har_entry)
    values: Dict[str, str] = {}
    drop: List[str] = []
    now_s = str(int(time.time()))
    now_ms = str(int(time.time() * 1000))
    for key, value in baseline.items():
        low = key.lower()
        if low in _SIGN_FIELDS and has_crypto:
            drop.append(key)
            continue
        if low not in _FRESH_FIELDS:
            continue
        if str(value).isdigit() and len(str(value)) >= 13:
            values[key] = now_ms
        elif low in {'timestamp', 'ts', 'time', 'requesttime', '_t'}:
            values[key] = now_s if not str(value).isdigit() else (
                now_ms if len(str(value)) >= 13 else now_s
            )
        elif str(value).isdigit():
            refined, _ = refine_source_from_feedback(key, value, distance=1)
            if refined:
                values[key] = refined
    if not values and not drop:
        return None
    return {
        'id': 'alt:rebuild_fresh',
        'kind': 'rebuild_fresh',
        'values': values,
        'drop_fields': drop,
        'source': 'freshness',
    }


def _binding_names(ccrs: Optional[Iterable[Dict[str, Any]]]) -> List[str]:
    names: List[str] = []
    for RCR in ccrs or []:
        for item in RCR.get('binding_credentials') or []:
            names.append(str(item))
        roles = RCR.get('field_roles') or {}
        if isinstance(roles, dict):
            for name, role in roles.items():
                if str(role).lower() in {'binding', 'identity', 'subject'}:
                    names.append(str(name))
    return list(dict.fromkeys(names))


def _response_text(classification: Dict[str, Any]) -> str:
    text = str(classification.get('body_preview') or '')
    if '\\u' in text or '\\x' in text:
        try:
            text = text.encode('utf-8').decode('unicode_escape')
        except Exception:
            pass
    return text


def response_guided_alt(
    step: Dict[str, Any],
    resolved: Dict[str, Any],
    classification: Optional[Dict[str, Any]],
    previous: Optional[Dict[str, Any]],
    *,
    ccrs: Optional[Iterable[Dict[str, Any]]] = None,
    session_values: Optional[Dict[str, Any]] = None,
    realized_fields: Optional[Iterable[str]] = None,
) -> Optional[Dict[str, Any]]:
    """Next node alternative from the response, still using the existing mutator."""
    classification = classification or {}
    body = _response_text(classification)
    category = str(classification.get('category') or '')
    realized = {str(name).lower() for name in (realized_fields or [])}
    owned = [str(f) for f in (step.get('drift_fields') or [])]

    identity = category in {'forbidden', 'auth_required', 'user_not_exist'} or bool(_IDENTITY_HINT.search(body))
    if identity:
        session = session_values or {}
        values: Dict[str, Any] = {}
        for name in _binding_names(ccrs):
            if owned and name.lower() not in {f.lower() for f in owned} and name.lower() not in {
                str(k).lower() for k in resolved
            }:
                continue
            for key, value in session.items():
                if str(key).lower() == name.lower() and value not in (None, ''):
                    values[name] = value
                    break
        if values:
            return {
                'id': 'alt:restore_binding:' + ','.join(values),
                'kind': 'restore_binding',
                'values': values,
                'source': 'ccr_binding',
            }

    if _FRESH_HINT.search(body):
        fresh = _rebuild_fresh_alt(step, None, has_crypto=False)
        if fresh and previous and previous.get('kind') == 'drift_source' and previous.get('field'):
            fresh['values'][str(previous['field'])] = previous.get('value')
            fresh['id'] = f"alt:rebuild_fresh:{previous['field']}:d{previous.get('distance')}"
        if fresh:
            return fresh

    # Downstream nodes keep the source perturbation already realized.
    if not owned or all(name.lower() in realized for name in owned):
        return None
    field = next((name for name in owned if name.lower() not in realized), '')
    original = None
    if previous and previous.get('kind') == 'drift_source' and str(previous.get('field') or '').lower() == field.lower():
        original = previous.get('original')
    if not original:
        for key, value in resolved.items():
            if str(key).lower() == field.lower() and _concrete(value):
                original = str(value)
                break
    if not original:
        for key, value in (step.get('inputs') or {}).items():
            if str(key).lower() == field.lower() and _concrete(value):
                original = str(value)
                break
    if not original:
        return None
    distance = int((previous or {}).get('distance') or 0) + 1
    if distance > _MAX_DRIFT_DISTANCE:
        return None
    refined, strategy = refine_source_from_feedback(
        field, original, category=category, body=body, distance=distance,
    )
    if not refined:
        return None
    return {
        'id': f'alt:drift_source:{field}:d{distance}',
        'kind': 'drift_source',
        'field': field,
        'original': str(original),
        'value': refined,
        'distance': distance,
        'strategy': strategy,
        'source': 'response',
    }


def synthesize_node_alts(
    step: Dict[str, Any],
    *,
    har_entry: Optional[Dict[str, Any]] = None,
    ccrs: Optional[Iterable[Dict[str, Any]]] = None,
    has_crypto: bool = False,
    declared_alts: Optional[List[Dict[str, Any]]] = None,
    session_values: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Finite M_i for this request slot. Original attempt is *not* included."""
    alts: List[Dict[str, Any]] = []
    seen: Set[str] = set()

    def add(alt: Dict[str, Any]) -> None:
        aid = alt.get('id') or ''
        if not aid or aid in seen:
            return
        seen.add(aid)
        alts.append(alt)

    for raw in declared_alts or []:
        if not isinstance(raw, dict):
            continue
        kind = raw.get('kind') or ''
        if kind in EXECUTABLE_KINDS and (raw.get('method') or raw.get('transform') or raw.get('rename') or 'crypto' in raw or raw.get('placement')):
            alt = dict(raw)
            alt.setdefault('id', f"alt:declared:{kind}:{len(seen)}")
            add(alt)
        elif isinstance(raw.get('transform'), dict) and raw['transform']:
            alt = {'id': f"alt:transform:{len(seen)}", 'kind': 'transform', 'transform': raw['transform']}
            add(alt)

    drift = list(step.get('drift_fields') or [])
    for alt in _drift_source_alts(step, har_entry):
        add(alt)
    if drift:
        add({'id': 'alt:fill_missing_ids', 'kind': 'fill_missing_ids', 'source': 'drift_fields'})
    fresh = _rebuild_fresh_alt(step, har_entry, has_crypto=has_crypto)
    if fresh:
        add(fresh)
    if session_values:
        add({
            'id': 'alt:fill_session',
            'kind': 'fill_session',
            'values': dict(session_values),
            'source': 'session_har',
        })
    if has_crypto:
        add({
            'id': 'alt:encrypted_query',
            'kind': 'placement',
            'placement': 'encrypted_query',
            'source': 'wrapper_query',
        })

    # method/path 级变更归 Workflow Feedback，避免与 Node 物化重叠导致消融打平
    method = _norm_method(step.get('method'))
    path = step.get('path') or ''

    if has_crypto:
        add({'id': 'alt:transport:plaintext', 'kind': 'transport', 'crypto': False})

    har_vals = _har_query_keys(har_entry)
    current_keys = list((step.get('inputs') or {}).keys()) or list(har_vals.keys())
    current_keys = list(dict.fromkeys(current_keys + drift))
    candidates = list(har_vals.keys()) + _ccr_fields(ccrs)
    for src, dst in _alias_pairs(current_keys, candidates)[:1]:
        add({
            'id': f'alt:alias:{src}->{dst}',
            'kind': 'field_alias',
            'rename': {src: dst},
            'source': 'har_or_ccr',
        })

    add({'id': 'alt:drop_nulls', 'kind': 'drop_nulls'})
    if har_vals:
        add({
            'id': 'alt:fill_har',
            'kind': 'fill_har',
            'values': {k: v for k, v in har_vals.items() if v not in (None, '')},
            'source': 'har',
        })
    add({
        'id': 'alt:placement:body' if method == 'GET' else 'alt:placement:query',
        'kind': 'placement',
        'placement': 'body' if method == 'GET' else 'query',
    })

    return alts[:MAX_NODE_ALTS]


def apply_node_alt(
    step: Dict[str, Any],
    resolved: Dict[str, Any],
    alt: Optional[Dict[str, Any]],
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    step_out = dict(step)
    resolved_out = dict(resolved or {})
    if not alt:
        return step_out, resolved_out
    kind = alt.get('kind')
    if kind == 'method_switch' and alt.get('method'):
        step_out['method'] = _norm_method(alt['method'])
    elif kind == 'transport':
        step_out['_force_crypto'] = bool(alt.get('crypto'))
    elif kind == 'placement' and alt.get('placement'):
        step_out['_placement'] = alt['placement']
        if alt['placement'] == 'body' and _norm_method(step_out.get('method')) == 'GET':
            step_out['method'] = 'POST'
        if alt['placement'] in ('query', 'encrypted_query'):
            for k, v in list(resolved_out.items()):
                if v in (None, ''):
                    continue
                kl = str(k).lower()
                canon = _CANON_PARAM.get(kl)
                if canon:
                    resolved_out.setdefault(canon, v)
                if kl == 'bindid':
                    resolved_out.setdefault('bindId', v)
    elif kind == 'drop_nulls':
        resolved_out = {k: v for k, v in resolved_out.items() if v not in (None, '')}
    elif kind == 'fill_har':
        for k, v in (alt.get('values') or {}).items():
            if resolved_out.get(k) in (None, ''):
                resolved_out[k] = v
    elif kind == 'fill_session':
        drift_l = {str(f).lower() for f in (step_out.get('drift_fields') or [])}
        for k, v in (alt.get('values') or {}).items():
            if v in (None, ''):
                continue
            kl = str(k).lower()
            if kl in _FILL_SKIP:
                continue
            if drift_l and kl not in drift_l:
                continue
            hit = next((rk for rk in resolved_out if str(rk).lower() == kl), None)
            want = _CANON_PARAM.get(kl) or next(
                (f for f in (step_out.get('drift_fields') or []) if str(f).lower() == kl),
                k,
            )
            if hit is None:
                resolved_out[want] = v
            elif resolved_out.get(hit) in (None, ''):
                resolved_out[hit] = v
    elif kind == 'fill_missing_ids':
        fields = [
            f for f in (step_out.get('drift_fields') or [])
            if str(f).lower() not in _FILL_SKIP
        ]
        if any(str(f).lower() == 'titleid' for f in fields):
            fields = [f for f in fields if str(f).lower() != 'title']
        rank = ('userid', 'bindid', 'unionid', 'titleid', 'openid', 'title')
        fields.sort(key=lambda f: next((i for i, n in enumerate(rank) if str(f).lower() == n), 40))
        for field in fields[:2]:
            canon = _CANON_PARAM.get(str(field).lower(), field)
            hit = next((rk for rk in resolved_out if str(rk).lower() == str(canon).lower()), None)
            if hit is None or resolved_out.get(hit) in (None, ''):
                resolved_out[canon] = '1'
    elif kind == 'drift_source':
        field = str(alt.get('field') or '')
        value = alt.get('value')
        owned = {str(f).lower() for f in (step_out.get('drift_fields') or [])}
        if field and value not in (None, '') and (not owned or field.lower() in owned):
            hit = next((rk for rk in resolved_out if str(rk).lower() == field.lower()), None)
            resolved_out[hit or field] = value
    elif kind == 'rebuild_fresh':
        for field, value in (alt.get('values') or {}).items():
            hit = next((rk for rk in resolved_out if str(rk).lower() == str(field).lower()), None)
            if hit is None:
                resolved_out[field] = value
            else:
                resolved_out[hit] = value
        for field in alt.get('drop_fields') or []:
            for rk in list(resolved_out):
                if str(rk).lower() == str(field).lower():
                    resolved_out.pop(rk, None)
    elif kind == 'restore_binding':
        for field, value in (alt.get('values') or {}).items():
            if value in (None, ''):
                continue
            hit = next((rk for rk in resolved_out if str(rk).lower() == str(field).lower()), None)
            resolved_out[hit or field] = value
    elif kind == 'field_alias':
        for src, dst in (alt.get('rename') or {}).items():
            if src in resolved_out and dst not in resolved_out:
                resolved_out[dst] = resolved_out[src]
    elif kind == 'transform':
        for field, rule in (alt.get('transform') or {}).items():
            if field not in resolved_out or not isinstance(rule, dict):
                continue
            if rule.get('type') == 'constant':
                resolved_out[field] = rule.get('value')
            elif rule.get('type') == 'format' and isinstance(resolved_out[field], str):
                resolved_out[field] = rule.get('template', '').format(value=resolved_out[field])
            elif rule.get('type') == 'rename' and rule.get('to'):
                resolved_out[rule['to']] = resolved_out[field]
    return step_out, resolved_out


def _step_from_spec(
    *,
    node_id: str,
    path: str,
    method: str,
    failed_step: Dict[str, Any],
    source: str,
) -> Dict[str, Any]:
    return {
        'step': failed_step.get('step'),
        'node_id': node_id,
        'operation_id': node_id,
        'method': _norm_method(method),
        'path': path,
        'node_type': failed_step.get('node_type'),
        'requires_auth': failed_step.get('requires_auth', True),
        'auth_bypass': failed_step.get('auth_bypass', False),
        'crbd_driftable': failed_step.get('crbd_driftable', False),
        'drift_fields': list(failed_step.get('drift_fields') or []),
        'identity_anchor': failed_step.get('identity_anchor'),
        'inputs': dict(failed_step.get('inputs') or {}),
        'outputs': dict(failed_step.get('outputs') or {}),
        'metadata': {
            'source': source,
            'workflow_alt_of': failed_step.get('node_id'),
        },
    }


def synthesize_workflow_alts(
    failed_step: Dict[str, Any],
    chain: Dict[str, Any],
    *,
    bcg: Optional[Dict[str, Any]] = None,
    ccrs: Optional[Iterable[Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    """Other evidence-supported r_j: promote exit, path repair, producer prefix, method variants."""
    alts: List[Dict[str, Any]] = []
    seen: Set[Any] = set()
    failed_id = failed_step.get('node_id')
    path = failed_step.get('path') or ''
    np = norm_path(path)
    failed_method = _norm_method(failed_step.get('method'))
    nodes = chain.get('nodes') or {}
    if not isinstance(nodes, dict):
        nodes = {}

    def add(alt: Dict[str, Any]) -> None:
        aid = alt.get('id') or ''
        step = alt.get('step') or alt.get('prefix_step') or {}
        kind = alt.get('kind')
        sig = (
            kind,
            norm_path(step.get('path') or ''),
            _norm_method(step.get('method')),
            bool(alt.get('prefix_step')),
        )
        if not aid or aid in seen or sig in seen:
            return
        seen.add(aid)
        seen.add(sig)
        alts.append(alt)

    # 1) Promote chain exit when entry hop fails (handoff 错配 / 伪依赖)
    exit_id = chain.get('exit_node') or chain.get('drift_target') or chain.get('target')
    if exit_id and exit_id != failed_id and exit_id in nodes:
        enode = nodes[exit_id]
        epath = enode.get('path') or ''
        if epath and norm_path(epath) != np:
            add({
                'id': f'wf:promote-exit:{exit_id}',
                'kind': 'promote_exit',
                'reason': 'promote_chain_exit',
                'step': _step_from_spec(
                    node_id=str(exit_id),
                    path=epath,
                    method=enode.get('method') or failed_method,
                    failed_step=failed_step,
                    source='promote_exit',
                ),
            })

    # 2) Host/gateway path-prefix repair (红城 BCG 短路径缺 /hcapi[/wx])
    if path and not path.startswith('http'):
        bare = path if path.startswith('/') else f'/{path}'
        for prefix in ('/hcapi/wx', '/hcapi'):
            if bare.startswith(prefix + '/') or bare == prefix:
                continue
            if re.search(r'mySecondHandHouse|commercialRealEstate|myRental|member/|/auth/face', bare, re.I):
                prefixed = prefix + bare
                add({
                    'id': f'wf:path-prefix:{prefix}',
                    'kind': 'path_prefix',
                    'reason': 'gateway_path_prefix',
                    'step': _step_from_spec(
                        node_id=str(failed_id or 'wf'),
                        path=prefixed,
                        method=failed_method,
                        failed_step=failed_step,
                        source='path_prefix',
                    ),
                })
        # 补全模板 {id}/{houseId}
        if '{' not in bare and re.search(r'putOffSale|putOnSale|taskDown|taskUp|detail$', bare, re.I):
            for field in ('id', 'houseId'):
                templated = bare.rstrip('/') + '/{' + field + '}'
                add({
                    'id': f'wf:path-template:{{{field}}}',
                    'kind': 'path_template',
                    'reason': 'append_path_template',
                    'step': _step_from_spec(
                        node_id=str(failed_id or 'wf'),
                        path=templated,
                        method=failed_method,
                        failed_step=failed_step,
                        source='path_template',
                    ),
                })

    # 3) Insert producer prefix (不同 path；不替换 target)
    consumed = {str(k).lower() for k in (failed_step.get('inputs') or {}).keys()}
    consumed |= {str(k).lower() for k in (failed_step.get('drift_fields') or [])}
    consumed -= {
        'token', 'authorization', 'appidentity', 'appversion', 'appplatform',
        'channel', 'type', '',
    }
    if consumed:
        for nid, node in nodes.items():
            if nid == failed_id:
                continue
            npath = node.get('path') or ''
            if not npath or norm_path(npath) == np:
                continue
            produces = {str(x).lower() for x in (node.get('produces') or [])}
            produces |= {str(x).lower() for x in (node.get('drift_fields') or [])}
            if not (produces & consumed):
                continue
            add({
                'id': f'wf:insert-producer:{nid}',
                'kind': 'insert_producer_prefix',
                'reason': 'insert_producer_prefix',
                'prefix_step': _step_from_spec(
                    node_id=nid,
                    path=npath,
                    method=node.get('method') or 'GET',
                    failed_step=failed_step,
                    source='insert_producer_prefix',
                ),
                # keep failed target as step for metadata; executor uses prefix_step
                'step': dict(failed_step),
            })
        # BCG producers for missing BindId / orderCode etc.
        for n in (bcg or {}).get('nodes') or []:
            npath = n.get('path') or ''
            if not npath or norm_path(npath) == np:
                continue
            cred = str(n.get('credential') or '').lower()
            if cred not in consumed:
                continue
            # 按缺字段收紧 producer，避免 BindId 误绑到 orderList
            if cred in {'bindid', 'bind_id'} and not re.search(r'BindInfo|bindInfo|Account/Bind', npath, re.I):
                continue
            if cred in {'ordercode', 'order_code'} and not re.search(
                r'queryOrderList|OrderList|orderList|findByOrder', npath, re.I
            ):
                continue
            if cred not in {'bindid', 'bind_id', 'ordercode', 'order_code', 'unionid', 'titleid'} and not re.search(
                r'BindInfo|bindInfo|queryOrderList|OrderList|orderList|addressList',
                npath,
                re.I,
            ):
                continue
            nid = str(n.get('node_id') or npath)
            add({
                'id': f'wf:insert-bcg-producer:{nid}',
                'kind': 'insert_producer_prefix',
                'reason': 'bcg_insert_producer',
                'prefix_step': _step_from_spec(
                    node_id=nid,
                    path=npath,
                    method=n.get('method') or 'GET',
                    failed_step=failed_step,
                    source='bcg_insert_producer',
                ),
                'step': dict(failed_step),
            })

    # 4) Same-path method variants (chain / RCR / BCG)
    for nid, node in nodes.items():
        if nid == failed_id:
            continue
        npath = node.get('path') or ''
        nmethod = _norm_method(node.get('method'))
        if norm_path(npath) == np and nmethod != failed_method:
            add({
                'id': f'wf:chain-node:{nid}',
                'kind': 'same_path_variant',
                'reason': 'chain_node_method_variant',
                'step': _step_from_spec(
                    node_id=nid, path=npath, method=nmethod,
                    failed_step=failed_step, source='chain_node',
                ),
            })

    for RCR in ccrs_for_path(path, ccrs):
        mv = (RCR.get('method') or {}).get('value') if isinstance(RCR.get('method'), dict) else None
        if not mv or _norm_method(mv) == failed_method:
            continue
        oid = RCR.get('operation_id') or f'RCR:{_norm_method(mv)}'
        add({
            'id': f'wf:RCR:{oid}:{_norm_method(mv)}',
            'kind': 'same_path_variant',
            'reason': 'ccr_method_variant',
            'step': _step_from_spec(
                node_id=f'RCR:{oid}', path=path, method=mv,
                failed_step=failed_step, source='ccr_method_variant',
            ),
        })

    for n in (bcg or {}).get('nodes') or []:
        if norm_path(n.get('path') or '') != np:
            continue
        m = n.get('method')
        if not m or _norm_method(m) == failed_method:
            continue
        nid = n.get('node_id') or n.get('operation_id')
        add({
            'id': f'wf:bcg:{nid}',
            'kind': 'same_path_variant',
            'reason': 'bcg_method_variant',
            'step': _step_from_spec(
                node_id=str(nid), path=n.get('path') or path, method=m,
                failed_step=failed_step, source='bcg_method_variant',
            ),
        })

    # 5) Sibling path (放宽：同 leaf 即可，不强制 credential 交集)
    identityish = {
        'token', 'authorization', 'appidentity', 'appversion', 'appplatform',
        'channel', 'type', 'teacherschoolid', 'schoolversion', '__resource_ctx__',
    }
    leaf = path.rstrip('/').rsplit('/', 1)[-1].lower() if path else ''
    leaf = re.sub(r'\{[^}]+\}', '', leaf)
    if leaf and (bcg or {}).get('nodes'):
        for n in (bcg or {}).get('nodes') or []:
            npath = n.get('path') or ''
            if norm_path(npath) == np or not npath:
                continue
            nleaf = npath.rstrip('/').rsplit('/', 1)[-1].lower()
            nleaf = re.sub(r'\{[^}]+\}', '', nleaf)
            if nleaf != leaf:
                continue
            cred = str(n.get('credential') or '').lower()
            if cred in identityish:
                continue
            add({
                'id': f'wf:sibling:{npath}:{_norm_method(n.get("method"))}',
                'kind': 'sibling_path',
                'reason': 'bcg_same_leaf',
                'step': _step_from_spec(
                    node_id=str(n.get('node_id') or npath),
                    path=npath,
                    method=n.get('method') or failed_method,
                    failed_step=failed_step,
                    source='bcg_sibling_path',
                ),
            })

    # 6) method_flip 最后（噪声大；写路径跳过）
    is_write = bool(re.search(
        r'unbind|un-bind|delete|putoff|puton|save|modify|remove|update|edit|create|add|taskup|taskdown',
        path or '',
        re.I,
    ))
    if failed_method in ('GET', 'POST') and not is_write:
        flipped = 'POST' if failed_method == 'GET' else 'GET'
        if not (failed_method == 'GET' and flipped == 'POST' and re.search(r'/detail', path, re.I)):
            add({
                'id': f'wf:method-flip:{flipped}',
                'kind': 'same_path_variant',
                'reason': 'method_flip',
                'step': _step_from_spec(
                    node_id=str(failed_id or 'wf'), path=path, method=flipped,
                    failed_step=failed_step, source='method_flip',
                ),
            })
    if re.search(r'/detail', path, re.I) and failed_method != 'GET':
        add({
            'id': 'wf:method-force-GET',
            'kind': 'same_path_variant',
            'reason': 'detail_prefer_get',
            'step': _step_from_spec(
                node_id=str(failed_id or 'wf'), path=path, method='GET',
                failed_step=failed_step, source='detail_prefer_get',
            ),
        })

    return alts[:MAX_WORKFLOW_ALTS]


def attach_step_feedback_metadata(
    step: Dict[str, Any],
    node: Optional[Dict[str, Any]] = None,
    *,
    har_entry: Optional[Dict[str, Any]] = None,
    ccrs: Optional[Iterable[Dict[str, Any]]] = None,
    has_crypto: bool = False,
    session_values: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    meta = dict(step.get('metadata') or {})
    if node:
        nmeta = node.get('metadata') or {}
        if isinstance(nmeta, dict):
            for k, v in nmeta.items():
                meta.setdefault(k, v)
        declared = node.get('materialization_alternatives') or meta.get('materialization_alternatives') or []
    else:
        declared = meta.get('materialization_alternatives') or []
    if har_entry is None:
        har_entry = meta.get('har_entry')
    alts = synthesize_node_alts(
        step,
        har_entry=har_entry,
        ccrs=ccrs,
        has_crypto=has_crypto,
        declared_alts=declared if isinstance(declared, list) else [],
        session_values=session_values,
    )
    meta['materialization_alternatives'] = alts
    step = dict(step)
    step['metadata'] = meta
    return step
