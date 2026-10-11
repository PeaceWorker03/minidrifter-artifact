# -*- coding: utf-8 -*-
"""HAR sequence ingestion — full entries, static-asset filter, API-only path."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

# Generic API path hints (profile-driven extensions go in packs; core uses shape rules).
API_PATH_HINTS = re.compile(
    r'/(api|wechat|mini|member|order|pay|address|coupon|wallet|user|account|'
    r'invoice|device|cart|ticket|booking|profile|login|auth|action)/',
    re.I,
)

STATIC_SUFFIXES = frozenset({
    '.js', '.css', '.map', '.png', '.jpg', '.jpeg', '.gif', '.webp', '.svg',
    '.ico', '.woff', '.woff2', '.ttf', '.eot', '.mp4', '.mp3',
})

STATIC_PATH_HINTS = re.compile(
    r'/(static|assets|cdn|analytics|track|beacon|favicon|log\.gif|'
    r'__webpack|chunk-|hot-update)',
    re.I,
)


def looks_like_har(text: str) -> bool:
    t = (text or '').lstrip()
    if not t.startswith('{'):
        return False
    try:
        doc = json.loads(t)
    except json.JSONDecodeError:
        return False
    return isinstance(doc.get('log'), dict) and isinstance(doc['log'].get('entries'), list)


def looks_like_burp_xml(text: str) -> bool:
    t = (text or '').lstrip()
    return t.startswith('<?xml') and '<!ELEMENT items' in t[:1000] and '<!ELEMENT item' in t[:1000]


def parse_burp_xml(text: str) -> Dict[str, Any]:
    """Parse Burp Suite XML export to HAR-like dict."""
    import xml.etree.ElementTree as ET
    from urllib.parse import urlparse, parse_qs
    import base64

    root = ET.fromstring(text)
    entries = []
    for item in root.findall('item'):
        url_el = item.find('url')
        method_el = item.find('method')
        status_el = item.find('status')
        req_el = item.find('request')
        resp_el = item.find('response')
        if url_el is None:
            continue
        url = url_el.text or ''
        method = (method_el.text if method_el is not None else 'GET').upper()
        status = int(status_el.text) if status_el is not None and status_el.text else 0

        # Request headers/body
        headers = {}
        body_text = ''
        if req_el is not None and req_el.text:
            raw = req_el.text
            if req_el.get('base64') == 'true':
                try:
                    raw = base64.b64decode(raw).decode('utf-8', errors='replace')
                except Exception:
                    pass
            lines = raw.split('\r\n')
            for line in lines[1:]:
                if ': ' in line:
                    k, v = line.split(': ', 1)
                    headers[k] = v
                elif line.strip() == '':
                    break
            # body after empty line
            if '\r\n\r\n' in raw:
                body_text = raw.split('\r\n\r\n', 1)[-1]

        # Response body
        resp_text = ''
        if resp_el is not None and resp_el.text:
            raw_resp = resp_el.text
            if resp_el.get('base64') == 'true':
                try:
                    raw_resp = base64.b64decode(raw_resp).decode('utf-8', errors='replace')
                except Exception:
                    pass
            if '\r\n\r\n' in raw_resp:
                resp_text = raw_resp.split('\r\n\r\n', 1)[-1]

        parsed = urlparse(url)
        query = {k: v[0] if len(v) == 1 else v for k, v in parse_qs(parsed.query).items()}

        # Parse body
        body_json = None
        body_form = {}
        if body_text:
            try:
                body_json = json.loads(body_text)
            except json.JSONDecodeError:
                if '=' in body_text:
                    body_form = dict(parse_qs(body_text))

        # Parse response
        resp_json = None
        if resp_text:
            try:
                resp_json = json.loads(resp_text)
            except json.JSONDecodeError:
                pass

        entries.append({
            'request': {
                'method': method,
                'url': url,
                'path': parsed.path,
                'query': query,
                'headers': headers,
                'body_json': body_json,
                'body_form': body_form,
            },
            'response_status': status,
            'response_body': resp_json,
            'response_text': resp_text[:5000],
        })

    return {'log': {'entries': entries}}


def _is_static_asset_url(url: str) -> bool:
    if not url:
        return True
    parsed = urlparse(url)
    path = (parsed.path or '').lower()
    if any(path.endswith(s) for s in STATIC_SUFFIXES):
        return True
    if STATIC_PATH_HINTS.search(path):
        return True
    # Host root with no API path segment is usually not a business API.
    if path in ('', '/') and not parsed.query:
        return True
    return False


def _is_api_like_url(url: str) -> bool:
    if not url or _is_static_asset_url(url):
        return False
    parsed = urlparse(url)
    path = parsed.path or '/'
    if API_PATH_HINTS.search(path):
        return True
    # Path with depth >= 2 and not purely static extension.
    segments = [s for s in path.split('/') if s]
    if len(segments) >= 2:
        return True
    if parsed.query and any(
        k.lower() in {'q', 'sign', 'token', 'cid', 'uid', 'userid', 'memberid'}
        for k in parsed.query.split('&')
        if '=' in k or k
    ):
        return True
    return False


def _har_headers(header_list: List[Dict[str, Any]]) -> Dict[str, str]:
    # Handle both list-of-dicts (HAR) and plain dict (Burp XML parsed)
    if isinstance(header_list, dict):
        return {str(k): str(v) for k, v in header_list.items()}
    return {
        h['name']: h['value']
        for h in (header_list or [])
        if h.get('name')
    }


def _har_body_json(post_data: Optional[Dict[str, Any]]) -> Tuple[Optional[Any], Dict[str, str]]:
    if not post_data:
        return None, {}
    text = post_data.get('text') or ''
    body_form: Dict[str, str] = {}
    mime = (post_data.get('mimeType') or '').lower()
    if text:
        if 'json' in mime or text.lstrip().startswith(('{', '[')):
            try:
                return json.loads(text), body_form
            except json.JSONDecodeError:
                pass
        if 'form' in mime or '=' in text:
            from minidrifter.materials.baseline_importer import parse_urlencoded_form
            body_form = parse_urlencoded_form(text)
    return None, body_form


def _har_response_json(resp: Dict[str, Any]) -> Optional[Any]:
    content = resp.get('content') or {}
    text = content.get('text') or ''
    if not text:
        return None
    encoding = (content.get('encoding') or '').lower()
    if encoding == 'base64':
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def har_entry_to_request(entry: Dict[str, Any]) -> Dict[str, Any]:
    """Convert one HAR entry to baseline_importer-compatible request dict."""
    req = entry.get('request') or {}
    url = req.get('url') or ''
    parsed = urlparse(url)
    from urllib.parse import parse_qs, unquote
    raw_query = unquote(parsed.query or '')
    query = {
        k: v[0] if len(v) == 1 else v
        for k, v in parse_qs(parsed.query).items()
    }
    # 若 parse_qs 为空但 URL 有加密 blob，则保留原始 query 供后续解密
    query_blob = ''
    if not query and raw_query:
        if len(raw_query) > 20 and ('=' not in raw_query or raw_query.startswith('8aS')):
            query_blob = raw_query
    body_json, body_form = _har_body_json(req.get('postData'))
    # HAR 中 postData.text 有时被原始捕获为带引号的字符串，去除首尾引号
    body_raw = (req.get('postData') or {}).get('text') or None
    if body_raw and isinstance(body_raw, str):
        body_raw = body_raw.strip()
        if len(body_raw) >= 2 and body_raw[0] == body_raw[-1] and body_raw[0] in ('"', "'"):
            body_raw = body_raw[1:-1]
    return {
        'method': (req.get('method') or 'GET').upper(),
        'url': url,
        'path': parsed.path or '/',
        'query': query,
        'query_blob': query_blob,
        'headers': _har_headers(req.get('headers')),
        'body_raw': body_raw,
        'body_json': body_json,
        'body_form': body_form,
        'started_at': entry.get('startedDateTime'),
    }


def filter_har_entries(
    entries: List[Dict[str, Any]],
    *,
    api_only: bool = True,
) -> List[Dict[str, Any]]:
    """Sort by time, drop static assets, keep API-like requests."""
    sorted_entries = sorted(
        entries,
        key=lambda e: e.get('startedDateTime') or '',
    )
    if not api_only:
        return sorted_entries
    kept: List[Dict[str, Any]] = []
    for entry in sorted_entries:
        url = (entry.get('request') or {}).get('url') or ''
        if _is_api_like_url(url):
            kept.append(entry)
    return kept


def parse_har_sequence(
    har: Dict[str, Any],
    *,
    api_only: bool = True,
) -> List[Dict[str, Any]]:
    """Parse HAR log → list of {request, response_body, started_at, har_index}."""
    entries = har.get('log', {}).get('entries') or []
    filtered = filter_har_entries(entries, api_only=api_only)
    out: List[Dict[str, Any]] = []
    for i, entry in enumerate(filtered):
        req = har_entry_to_request(entry)
        resp = entry.get('response') or {}
        out.append({
            'har_index': i + 1,
            'started_at': entry.get('startedDateTime'),
            'request': req,
            'response_body': _har_response_json(resp),
            'response_status': resp.get('status'),
        })
    return out


def har_text_to_capture_inputs(text: str, *, api_only: bool = True) -> List[Dict[str, Any]]:
    har = json.loads(text)
    return parse_har_sequence(har, api_only=api_only)


def har_file_to_capture_inputs(path: Path, *, api_only: bool = True) -> List[Dict[str, Any]]:
    har = json.loads(Path(path).read_text(encoding='utf-8', errors='replace'))
    return parse_har_sequence(har, api_only=api_only)


def har_entry_to_raw_http_chunk(entry: Dict[str, Any]) -> str:
    """Best-effort Raw HTTP reconstruction for material file export."""
    req = har_entry_to_request(entry)
    lines = [f"{req['method']} {req['url']} HTTP/1.1"]
    for k, v in (req.get('headers') or {}).items():
        lines.append(f'{k}: {v}')
    lines.append('')
    body = req.get('body_raw') or ''
    if not body and req.get('body_json') is not None:
        body = json.dumps(req['body_json'], ensure_ascii=False)
    elif not body and req.get('body_form'):
        from urllib.parse import urlencode
        body = urlencode(req['body_form'])
    if body:
        lines.append(body)
    resp = entry.get('response') or {}
    status = resp.get('status') or 200
    lines.append('')
    lines.append(f'HTTP/1.1 {status}')
    for h in resp.get('headers') or []:
        if h.get('name'):
            lines.append(f"{h['name']}: {h.get('value', '')}")
    lines.append('')
    content = ((resp.get('content') or {}).get('text')) or ''
    if content:
        lines.append(content)
    return '\n'.join(lines)
