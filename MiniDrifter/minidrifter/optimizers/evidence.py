# -*- coding: utf-8 -*-
from __future__ import annotations
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from minidrifter.core.utils import line_no, read_text
from minidrifter.optimizers.url_utils import clean_raw_url, split_url

BUNDLE_BASENAMES = frozenset({
    'app.js', 'common.js', 'vendors.js', 'taro.js', 'runtime.js',
    'app-service.js', 'page-frame.js', 'appservice.js',
})
CALLEE_METHOD_RE = re.compile(r'\.(get|post|put|delete|patch|head)\s*\(', re.I)
EXPLICIT_METHOD_RE = re.compile(r'\bmethod\s*:\s*["\'](GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)["\']', re.I)
API_LITERAL_RE = re.compile(r'\bapi\s*:\s*["\']([^"\']+)["\']', re.I)
OBJECT_KEY_RE = re.compile(r'\b([A-Za-z_$][\w$]{1,48})\s*:')
COMMON_PARAM_NAMES = frozenset({
    'userId', 'UserId', 'orderId', 'OrderId', 'memberId', 'MemberId',
    'phoneNo', 'PhoneNo', 'openId', 'OpenId', 'unionId', 'UnionId',
    'token', 'Token', 'deviceId', 'carId', 'invoiceId', 'targetUserId',
    'encryptMemberId', 'orderNo', 'userNo', 'id', 'code',
})


def _path_needle(raw_url: str | None) -> str:
    u = clean_raw_url(raw_url or '')
    if not u:
        return ''
    if u.startswith('http'):
        _, path, _ = split_url(u)
        return path or u
    return u.split('?')[0]


def is_bundle_source(source: Dict[str, Any] | None) -> bool:
    if not source:
        return False
    file = str(source.get('file') or '')
    base = Path(file.replace('\\', '/')).name.lower()
    line = int(source.get('line') or 0)
    if base in BUNDLE_BASENAMES and line <= 3:
        return True
    if 'chunk_' in base or 'sub-vendors' in base:
        return True
    return False


def resolve_source_file(project_root: Path, source_file: str) -> Optional[Path]:
    if not source_file:
        return None
    rel = source_file.replace('\\', '/')
    candidates = [
        project_root / rel,
        project_root / Path(rel).name,
    ]
    parts = rel.split('/')
    if len(parts) > 1:
        candidates.append(project_root / parts[-1])
        candidates.append(project_root / '/'.join(parts[-2:]))
    for cand in candidates:
        try:
            if cand.is_file():
                return cand.resolve()
        except Exception:
            continue
    return None


def offset_local_snippet(
    project_root: Path,
    source: Dict[str, Any] | None,
    raw_url: str | None,
    radius: int = 320,
) -> Tuple[str, Dict[str, Any]]:
    meta: Dict[str, Any] = {'strategy': 'original_source', 'resolved_file': None, 'offset': None}
    if not source or not project_root.is_dir():
        return str(source.get('snippet') or ''), meta
    needle = _path_needle(raw_url)
    snippet = str(source.get('snippet') or '')
    file = str(source.get('file') or '')
    resolved = resolve_source_file(project_root, file)
    if not resolved or not needle:
        return snippet, meta
    text = read_text(resolved)
    idx = text.find(needle)
    if idx < 0:
        short = needle.rsplit('/', 1)[-1]
        if len(short) >= 8:
            idx = text.find(short)
    if idx < 0:
        return snippet, meta
    start = max(0, idx - radius)
    end = min(len(text), idx + len(needle) + radius)
    focused = re.sub(r'\s+', ' ', text[start:end]).strip()
    meta = {
        'strategy': 'offset_local',
        'resolved_file': str(resolved),
        'offset': idx,
        'line': line_no(text, idx),
        'needle': needle,
    }
    return focused, meta


def enrich_source_evidence(
    project_root: Path | None,
    raw_url: str | None,
    source: Dict[str, Any] | None,
    url_expr: str | None = None,
) -> Dict[str, Any]:
    source = dict(source or {})
    texts = [str(source.get('snippet') or ''), str(url_expr or '')]
    focused = ''
    focus_meta: Dict[str, Any] = {}
    if project_root and project_root.is_dir() and (is_bundle_source(source) or len(texts[0]) > 400):
        focused, focus_meta = offset_local_snippet(project_root, source, raw_url)
    if not focused:
        focused = texts[0] if len(texts[0]) <= 900 else texts[0][:900]
        focus_meta = {'strategy': 'snippet_trim'}
    recovered = recover_params_from_slice(focused, raw_url)
    if focus_meta.get('strategy') == 'offset_local':
        source = {
            **source,
            'file': focus_meta.get('resolved_file') or source.get('file'),
            'line': focus_meta.get('line') or source.get('line'),
            'snippet': focused[:500],
            'evidence_strategy': 'offset_local',
        }
    else:
        source = {**source, 'evidence_strategy': source.get('evidence_strategy') or 'snippet'}
    return {
        'source': source,
        'focused_text': focused,
        'focus_meta': focus_meta,
        'recovered_params': recovered,
    }


def recover_params_from_slice(text: str, raw_url: str | None) -> List[str]:
    if not text:
        return []
    needle = _path_needle(raw_url)
    idx = text.find(needle) if needle else -1
    if idx < 0 and needle:
        short = needle.rsplit('/', 1)[-1]
        idx = text.find(short) if short else -1
    window = text
    if idx >= 0:
        window = text[max(0, idx - 120): min(len(text), idx + len(needle or '') + 420)]
    keys: List[str] = []
    for m in API_LITERAL_RE.finditer(window):
        if needle and needle not in m.group(1) and m.group(1) not in needle:
            continue
        after = window[m.end(): m.end() + 260]
        for km in OBJECT_KEY_RE.finditer(after):
            k = km.group(1)
            if k in {'api', 'data', 'method', 'url', 'header', 'success', 'fail', 'type', 'function', 'return', 'case'}:
                continue
            if k in COMMON_PARAM_NAMES or k.endswith('Id') or k.endswith('ID'):
                keys.append(k)
        break
    for name in COMMON_PARAM_NAMES:
        if re.search(rf'\b{re.escape(name)}\b', window):
            keys.append(name)
    return list(dict.fromkeys(keys))


def infer_method_from_slice(text: str, raw_url: str | None) -> Optional[Dict[str, Any]]:
    if not text:
        return None
    needle = _path_needle(raw_url)
    idx = text.find(needle) if needle else 0
    if idx < 0 and needle:
        short = needle.rsplit('/', 1)[-1]
        idx = text.find(short) if short else 0
    start = max(0, idx - 180)
    end = min(len(text), idx + len(needle or '') + 220)
    window = text[start:end]
    mm = EXPLICIT_METHOD_RE.search(window)
    if mm:
        return {
            'method': mm.group(1).upper(),
            'method_source': 'focused_explicit_method',
            'method_confidence': 0.95,
        }
    cm = CALLEE_METHOD_RE.search(window)
    if cm:
        return {
            'method': cm.group(1).upper(),
            'method_source': 'focused_callee_name',
            'method_confidence': 0.9,
        }
    return None


def infer_method_from_path(path: str | None) -> Optional[Dict[str, Any]]:
    if not path:
        return None
    low = path.lower()
    if low.startswith('/action/') or '/action/' in low:
        return {'method': 'POST', 'method_source': 'path_convention_action', 'method_confidence': 0.62}
    if low.startswith('/resource/') or '/resource/' in low:
        return {'method': 'GET', 'method_source': 'path_convention_resource', 'method_confidence': 0.62}
    # Generic REST-ish leaf verbs (language-agnostic path conventions).
    leaf = low.rstrip('/').rsplit('/', 1)[-1]
    if re.search(r'(create|add|save|submit|update|edit|delete|remove|pay|login|register|send|bind|upload|verify|analysis)$', leaf):
        return {'method': 'POST', 'method_source': 'path_convention_verb', 'method_confidence': 0.55}
    if re.search(r'(list|detail|info|get|query|search|find|check)$', leaf):
        return {'method': 'GET', 'method_source': 'path_convention_verb', 'method_confidence': 0.5}
    # Multi-segment verbs commonly used as final path component.
    if re.search(r'/(upload|verify|analysis|login|pay)(/|$)', low):
        return {'method': 'POST', 'method_source': 'path_convention_segment', 'method_confidence': 0.52}
    return None


def infer_wrapper_default_method(wrappers: List[Dict[str, Any]] | None) -> Optional[Dict[str, Any]]:
    """Extract default HTTP method declared inside request wrappers (generic)."""
    if not wrappers:
        return None
    counts: Dict[str, int] = {}
    for w in wrappers:
        # Prefer structured fields produced by contract enrichment / wrapper analyzer.
        for m in w.get('default_methods') or []:
            method = str(m.get('method') or '').upper()
            if method:
                counts[method] = counts.get(method, 0) + 3
        text = ' '.join([
            str(w.get('snippet') or ''),
            str((w.get('evidence') or {}).get('snippet') or ''),
            str(w.get('source', {}).get('snippet') or '') if isinstance(w.get('source'), dict) else '',
            str(w.get('body') or '')[:2000],
        ])
        for m in EXPLICIT_METHOD_RE.finditer(text):
            method = m.group(1).upper()
            counts[method] = counts.get(method, 0) + 1
        for m in re.finditer(r"method\s*\|\|\s*['\"](GET|POST|PUT|DELETE)['\"]", text, re.I):
            method = m.group(1).upper()
            counts[method] = counts.get(method, 0) + 2
        for m in re.finditer(r"method\s*=\s*method\s*\|\|\s*['\"](GET|POST)['\"]", text, re.I):
            method = m.group(1).upper()
            counts[method] = counts.get(method, 0) + 2
        for name in w.get('exported_or_defined_methods') or []:
            nl = str(name).lower()
            if nl in {'get', 'post'}:
                counts[nl.upper()] = counts.get(nl.upper(), 0) + 2
    if not counts:
        return None
    # Prefer GET/POST over rarer verbs when tied.
    best = sorted(
        counts.items(),
        key=lambda x: (-x[1], 0 if x[0] in {'GET', 'POST'} else 1, x[0]),
    )[0][0]
    return {
        'method': best,
        'method_source': 'wrapper_default_method',
        'method_confidence': 0.58,
    }
