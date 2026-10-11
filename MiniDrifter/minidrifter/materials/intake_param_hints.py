# -*- coding: utf-8 -*-
"""Build API param hints from baseline_intake_report decrypted captures (generic)."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from minidrifter.materials.baseline_importer import parse_raw_http
from minidrifter.materials.baseline_intake import split_multi_raw_http

FIELD_ALIASES: Dict[str, List[str]] = {
    'timestamp': ['Timestamp', 'TIMESTAMP', 'timeStamp', 'TimeSpan', 'timespan'],
    'userid': ['UserId', 'userId'],
    'token': ['Token'],
}

# Query keys that belong in HTTP headers for typical mini-program transports, not encrypted query.
HEADER_PARAM_KEYS = frozenset({
    'token', 'authorization', 'appidentity', 'appversion', 'appplatform',
    'remark', 'host', 'content-type',
})


def normalize_api_path(path: str) -> str:
    p = (path or '').split('?', 1)[0].strip()
    if not p.startswith('/'):
        p = f'/{p}'
    return p.rstrip('/').lower() or '/'


def _parse_query_pairs(query_str: str) -> List[Tuple[str, str]]:
    if not query_str:
        return []
    pairs: List[Tuple[str, str]] = []
    for part in query_str.split('&'):
        if not part:
            continue
        if '=' in part:
            k, v = part.split('=', 1)
        else:
            k, v = part, ''
        if k:
            pairs.append((k, v))
    return pairs


def load_intake_report(pack_dir: Optional[Path]) -> Optional[Dict[str, Any]]:
    if not pack_dir:
        return None
    path = Path(pack_dir) / 'baseline_intake_report.json'
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding='utf-8'))


def _trim_request_chunk(chunk: str) -> str:
    resp = re.search(r'\nHTTP/\d', chunk)
    if resp:
        return chunk[:resp.start()]
    return chunk


def _find_capture_request(
    pack_dir: Path,
    cap_path: str,
    cap_method: str,
) -> Optional[Dict[str, Any]]:
    """Match capture file by normalized path + method (not capture_index filename)."""
    mat_dir = pack_dir / 'user_materials'
    if not mat_dir.is_dir():
        return None

    want_path = normalize_api_path(cap_path)
    want_method = (cap_method or 'GET').upper()
    path_fallback: Optional[Dict[str, Any]] = None

    files = sorted(mat_dir.glob('*.txt')) + sorted(mat_dir.glob('*.http'))
    for fp in files:
        text = fp.read_text(encoding='utf-8', errors='replace')
        for chunk in split_multi_raw_http(text):
            try:
                req = parse_raw_http(_trim_request_chunk(chunk))
            except ValueError:
                continue
            req_path = normalize_api_path(req.get('path') or '')
            req_method = (req.get('method') or 'GET').upper()
            if req_path != want_path:
                continue
            if path_fallback is None:
                path_fallback = req
            if req_method == want_method:
                return req
    return path_fallback


def _request_to_hint_entry(req: Dict[str, Any], cap: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    body_form = req.get('body_form') or {}
    query = req.get('query') or {}
    if body_form:
        pairs = [(str(k), str(v) if v is not None else '') for k, v in body_form.items()]
        transport = 'form_body'
        query_plain = '&'.join(f'{k}={v}' for k, v in pairs)
        body_params = dict(body_form)
    elif query:
        pairs = [(str(k), str(v) if v is not None else '') for k, v in query.items()]
        transport = 'query'
        query_plain = '&'.join(f'{k}={v}' for k, v in pairs)
        body_params = {}
    else:
        return None

    if not pairs:
        return None

    method = (req.get('method') or cap.get('method') or 'GET').upper()
    return {
        'query_plain': query_plain,
        'param_pairs': pairs,
        'body_params': body_params,
        'capture_index': cap.get('capture_index'),
        'method': method,
        'transport': transport,
        'authorization_verified': False,
        'sign_verified': False,
        'capture_locked': True,
        'source': 'plaintext_capture_file',
    }


def hint_lookup(
    hints: Dict[str, Dict[str, Any]],
    path: str,
    method: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    path_n = normalize_api_path(path)
    if method:
        hit = hints.get(f'{path_n}|{(method or "GET").upper()}')
        if hit:
            return hit
    return hints.get(path_n)


def _hint_from_plaintext_capture(
    cap: Dict[str, Any],
    *,
    pack_dir: Optional[Path] = None,
) -> Optional[Dict[str, Any]]:
    assessment = cap.get('transport_assessment') or {}
    if assessment.get('transport_mode') != 'plaintext_only' and not assessment.get('plaintext_usable'):
        return None
    if not pack_dir:
        return None

    req = _find_capture_request(
        Path(pack_dir),
        cap.get('path') or '',
        cap.get('method') or 'GET',
    )
    if not req:
        return None

    return _request_to_hint_entry(req, cap)


def _merge_hint_entry(index: Dict[str, Dict[str, Any]], path: str, entry: Dict[str, Any]) -> None:
    method = (entry.get('method') or 'GET').upper()
    method_key = f'{path}|{method}'
    prev = index.get(method_key) or index.get(path)
    if not prev:
        index[method_key] = entry
        if method_key not in index or index.get(path) is None:
            index[path] = entry
    elif entry.get('sign_verified') and not prev.get('sign_verified'):
        index[method_key] = entry
        index[path] = entry
    elif entry.get('authorization_verified') and not prev.get('authorization_verified'):
        index[method_key] = entry
        index[path] = entry
    elif entry.get('source') == 'plaintext_capture_file' and not prev.get('param_pairs'):
        index[method_key] = entry
        index[path] = entry
    elif method_key not in index:
        index[method_key] = entry


def index_capture_query_hints(
    intake_report: Optional[Dict[str, Any]],
    *,
    pack_dir: Optional[Path] = None,
) -> Dict[str, Dict[str, Any]]:
    """Map normalized path -> best decrypted or plaintext query hint from intake captures."""
    if not intake_report:
        return {}

    index: Dict[str, Dict[str, Any]] = {}
    for cap in intake_report.get('captures') or []:
        path = normalize_api_path(cap.get('path') or '')
        if not path:
            continue

        proc = cap.get('crypto_processing') or {}
        decrypted = proc.get('decrypted') or {}
        query = decrypted.get('query')
        body_form = decrypted.get('body_form')
        input_mode = proc.get('input_mode') or ''

        entry = None
        if query or body_form or input_mode in {
            'ciphertext_query_decrypted', 'ciphertext_form_body_decrypted',
        }:
            body_params: Dict[str, Any] = {}
            if body_form:
                try:
                    obj = json.loads(str(body_form))
                    if isinstance(obj, dict):
                        pairs = [(str(k), str(v) if v is not None else '') for k, v in obj.items()]
                        body_params = dict(obj)
                    else:
                        pairs = []
                        body_params = {}
                except json.JSONDecodeError:
                    pairs = []
                    body_params = {}
                query_plain = str(body_form)
                transport = 'form_body'
            else:
                pairs = _parse_query_pairs(str(query))
                query_plain = str(query)
                transport = 'query'

            if pairs:
                entry = {
                    'query_plain': query_plain,
                    'param_pairs': pairs,
                    'body_params': body_params if transport == 'form_body' else {},
                    'capture_index': cap.get('capture_index'),
                    'method': (cap.get('method') or 'GET').upper(),
                    'transport': transport,
                    'authorization_verified': bool((proc.get('authorization_check') or {}).get('verified')),
                    'sign_verified': bool(proc.get('sign_check')),
                    'capture_locked': True,
                }

        if not entry:
            entry = _hint_from_plaintext_capture(cap, pack_dir=pack_dir)

        if entry:
            _merge_hint_entry(index, path, entry)
    return index


def _baseline_ref(field_name: str) -> str:
    canon = {'userId': 'UserId', 'userid': 'UserId', 'openId': 'OpenId'}.get(field_name, field_name)
    return f'$baseline.{canon}'


def _resolve_pool_field(name: str, resolved_pool: Dict[str, Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if name in resolved_pool:
        return resolved_pool[name]
    low = name.lower()
    for k, v in resolved_pool.items():
        if k.lower() == low:
            return v
    for aliases in FIELD_ALIASES.values():
        if name in aliases or low in [a.lower() for a in aliases]:
            for alias in aliases:
                hit = resolved_pool.get(alias) or next(
                    (resolved_pool[k] for k in resolved_pool if k.lower() == alias.lower()), None
                )
                if hit:
                    return hit
    return None


def _baseline_ref_for_key(key: str, value: str, resolved_pool: Dict[str, Dict[str, Any]]) -> str:
    candidates = [key, key[0].upper() + key[1:] if key else key]
    for aliases in FIELD_ALIASES.values():
        if key in aliases or key.lower() in [a.lower() for a in aliases]:
            candidates.extend(aliases)
            break

    seen = set()
    for name in candidates:
        if name in seen:
            continue
        seen.add(name)
        hit = _resolve_pool_field(name, resolved_pool)
        if not hit:
            continue
        pool_val = str(hit.get('value') or '')
        if pool_val and (pool_val == value or not value):
            return _baseline_ref(name)
    if key.lower() == 'userid':
        hit = _resolve_pool_field('UserId', resolved_pool)
        if hit:
            return '$baseline.UserId'
    return value


def params_from_intake_hint(
    hint: Dict[str, Any],
    resolved_pool: Dict[str, Dict[str, Any]],
    *,
    exclude_header_params: bool = True,
) -> Dict[str, str]:
    """Turn decrypted capture query into materialized param map (ordered)."""
    out: Dict[str, str] = {}
    for key, value in hint.get('param_pairs') or []:
        if exclude_header_params and key.lower() in HEADER_PARAM_KEYS:
            continue
        if value == '':
            out[key] = ''
        else:
            ref = _baseline_ref_for_key(key, value, resolved_pool)
            out[key] = ref if ref.startswith('$baseline.') else value
    return out


def merge_plain_params(
    skeleton_params: Dict[str, str],
    intake_params: Optional[Dict[str, str]],
    *,
    prefer_intake: bool = True,
) -> Dict[str, str]:
    if prefer_intake and intake_params:
        return dict(intake_params)
    if not intake_params:
        return dict(skeleton_params)
    merged = dict(skeleton_params)
    merged.update(intake_params)
    return merged


def resolve_intake_capture_card_ids(
    intake_report: Optional[Dict[str, Any]],
    cards_by_id: Dict[str, Dict[str, Any]],
) -> List[str]:
    """Map baseline intake captures → api card_ids for guaranteed materialize/probe."""
    if not intake_report:
        return []

    index: Dict[tuple, str] = {}
    for cid, card in cards_by_id.items():
        ep = (card.get('static') or {}).get('endpoint') or {}
        path = normalize_api_path(ep.get('path') or '')
        if not path:
            continue
        replay = card.get('replay') or {}
        method = (
            (replay.get('transport') or {}).get('method')
            or (card.get('static') or {}).get('method')
            or 'GET'
        ).upper()
        index[(path, method)] = cid
        index.setdefault((path, 'POST'), cid)
        index.setdefault((path, 'GET'), cid)

    out: List[str] = []
    for cap in intake_report.get('captures') or []:
        path = normalize_api_path(cap.get('path') or '')
        method = (cap.get('method') or 'GET').upper()
        hit = index.get((path, method)) or index.get((path, 'POST')) or index.get((path, 'GET'))
        if hit and hit not in out:
            out.append(hit)
    return out
