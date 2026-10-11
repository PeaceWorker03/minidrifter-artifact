# -*- coding: utf-8 -*-
"""Contract enrichment — raise F_i / RCR recovery using wrappers + callsite evidence.

General heuristics only (no app-specific hosts/paths).
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from minidrifter.analyzers.credential import classify_credential
from minidrifter.core.utils import read_text
from minidrifter.optimizers.evidence import (
    enrich_source_evidence,
    infer_method_from_path,
    infer_method_from_slice,
)
from minidrifter.optimizers.url_utils import split_url

_STORAGE_KEY_RE = re.compile(
    r'(?:get|set|remove)Storage(?:Sync)?\s*\(\s*[\'"]([^\'"]+)[\'"]',
    re.I,
)
_GLOBAL_TOKEN_RE = re.compile(
    r'globalData\.([A-Za-z_$][\w$]*(?:Token|Jwt|Session|Auth|UserInfo|User))',
    re.I,
)
_HEADER_ASSIGN_RE = re.compile(
    r'[\'"]?(Token|Authorization|AppIdentity|Appidentity|TimeSpan|sign|signature)[\'"]?\s*:',
    re.I,
)
_METHOD_LIT_RE = re.compile(r'\bmethod\s*:\s*[\'"](GET|POST|PUT|DELETE|PATCH)[\'"]', re.I)
_METHOD_DEFAULT_RE = re.compile(
    r'method\s*(?:=|\|\|)\s*(?:method\s*\|\|\s*)?[\'"](GET|POST|PUT|DELETE)[\'"]',
    re.I,
)
_AUTH_STORAGE_RE = re.compile(
    r'(token|jwt|session|auth|user|login|credential)',
    re.I,
)
_OBJECT_KEY_DEEP_RE = re.compile(r'\b([A-Za-z_$][\w$]{1,48})\s*:')
_QUERY_KEY_RE = re.compile(r'[?&]([A-Za-z_][\w]{1,40})=', re.I)
_CONCAT_KEY_RE = re.compile(r'[\'"]([A-Za-z_][\w]{1,40})[\'"]\s*\+\s*[\'"]=', re.I)


def enrich_wrappers(wrappers: List[Dict[str, Any]], project_root: Optional[Path]) -> List[Dict[str, Any]]:
    """Attach default_methods / injected_headers / identity_storage_keys from wrapper files."""
    out: List[Dict[str, Any]] = []
    for w in wrappers or []:
        w2 = dict(w)
        text = ''
        rel = w.get('file') or ''
        if project_root and rel:
            fp = Path(project_root) / rel
            if fp.is_file():
                text = read_text(fp)
        if not text:
            text = str((w.get('evidence') or {}).get('snippet') or '')

        methods: List[Dict[str, Any]] = []
        for m in _METHOD_LIT_RE.finditer(text):
            methods.append({'method': m.group(1).upper(), 'confidence': 0.85, 'source': 'wrapper_literal'})
        for m in _METHOD_DEFAULT_RE.finditer(text):
            methods.append({'method': m.group(1).upper(), 'confidence': 0.7, 'source': 'wrapper_default'})
        for name in w.get('exported_or_defined_methods') or []:
            nl = str(name).lower()
            # Only promote unambiguous HTTP verb exports (avoid JS .delete noise).
            if nl in {'get', 'post'}:
                methods.append({
                    'method': nl.upper(),
                    'confidence': 0.9,
                    'source': 'wrapper_exported_method',
                    'export_name': nl,
                })
            elif nl in {'put', 'patch'} and _METHOD_LIT_RE.search(text):
                methods.append({
                    'method': nl.upper(),
                    'confidence': 0.75,
                    'source': 'wrapper_exported_method',
                    'export_name': nl,
                })

        headers = sorted(set(
            list(w.get('header_hints') or [])
            + [m.group(1) for m in _HEADER_ASSIGN_RE.finditer(text)]
        ))
        storage_keys = sorted({m.group(1) for m in _STORAGE_KEY_RE.finditer(text)})
        identity_keys = [k for k in storage_keys if _AUTH_STORAGE_RE.search(k)]
        globals_ = sorted({m.group(1) for m in _GLOBAL_TOKEN_RE.finditer(text)})

        w2['default_methods'] = methods
        w2['injected_headers'] = headers
        w2['identity_storage_keys'] = identity_keys
        w2['identity_global_fields'] = globals_
        w2['full_text_chars'] = len(text)
        # Keep a larger evidence snippet for downstream provenance.
        if text and len(str((w2.get('evidence') or {}).get('snippet') or '')) < 400:
            ev = dict(w2.get('evidence') or {})
            ev['snippet'] = re.sub(r'\s+', ' ', text[:2500]).strip()
            w2['evidence'] = ev
        out.append(w2)
    return out


def scan_project_identity_roots(project_root: Optional[Path]) -> Dict[str, Any]:
    """Project-wide identity roots from storage / globalData (generic patterns)."""
    if not project_root or not Path(project_root).is_dir():
        return {'storage_keys': [], 'global_fields': [], 'header_names': []}
    storage: Counter = Counter()
    globals_c: Counter = Counter()
    headers: Counter = Counter()
    root = Path(project_root)
    # Prefer likely roots; fall back to capped scan.
    candidates = list(root.rglob('*.js'))
    # Cap for performance on huge apps.
    if len(candidates) > 400:
        preferred = [
            p for p in candidates
            if any(k in p.name.lower() for k in ('http', 'request', 'api', 'auth', 'app', 'user', 'login'))
        ]
        candidates = (preferred + [p for p in candidates if p not in preferred])[:400]
    for js in candidates:
        text = read_text(js)
        if not text:
            continue
        for m in _STORAGE_KEY_RE.finditer(text):
            key = m.group(1)
            if _AUTH_STORAGE_RE.search(key) or len(key) <= 24:
                storage[key] += 1
        for m in _GLOBAL_TOKEN_RE.finditer(text):
            globals_c[m.group(1)] += 1
        for m in _HEADER_ASSIGN_RE.finditer(text):
            headers[m.group(1)] += 1
    return {
        'storage_keys': [k for k, _ in storage.most_common(40) if _AUTH_STORAGE_RE.search(k)],
        'global_fields': [k for k, _ in globals_c.most_common(30)],
        'header_names': [k for k, _ in headers.most_common(20)],
    }


def _path_of(op: Dict[str, Any]) -> str:
    return str((op.get('endpoint') or {}).get('path') or '')


def _normalize_path(p: str) -> str:
    p = (p or '').split('?')[0]
    if not p.startswith('/'):
        p = '/' + p
    return p.rstrip('/') or '/'


def build_callsite_index(api_calls: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    by_path: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    by_key: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for c in api_calls or []:
        url = c.get('resolved_url') or c.get('url_expr') or ''
        _, path, _ = split_url(url)
        if path:
            by_path[_normalize_path(path)].append(c)
        uk = c.get('url_key')
        if uk:
            by_key[str(uk)].append(c)
    return {'by_path': by_path, 'by_key': by_key}


def _recover_keys_from_text(text: str) -> List[str]:
    keys: List[str] = []
    for m in _QUERY_KEY_RE.finditer(text or ''):
        keys.append(m.group(1))
    for m in _CONCAT_KEY_RE.finditer(text or ''):
        keys.append(m.group(1))
    # object keys near data/params/body
    for block_m in re.finditer(r'\b(data|params|query|body|formData)\s*:\s*\{', text or '', re.I):
        start = block_m.end() - 1
        depth = 0
        end = start
        for i, ch in enumerate(text[start:start + 800], start=start):
            if ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break
        block = text[start:end]
        for km in _OBJECT_KEY_DEEP_RE.finditer(block):
            k = km.group(1)
            if k.lower() not in {'function', 'success', 'fail', 'complete', 'header', 'headers'}:
                keys.append(k)
    # generic *Id / Token names
    for m in re.finditer(r'\b([A-Za-z][\w]{0,30}(?:Id|ID|No|Token|Phone))\b', text or ''):
        keys.append(m.group(1))
    return list(dict.fromkeys(keys))


def enrich_operations_for_contract(
    operations: List[Dict[str, Any]],
    *,
    api_calls: List[Dict[str, Any]],
    wrappers: List[Dict[str, Any]],
    project_root: Optional[Path],
    identity_roots: Optional[Dict[str, Any]] = None,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Upgrade business ops for contract recovery quality."""
    wrappers = enrich_wrappers(wrappers, project_root)
    identity_roots = identity_roots or scan_project_identity_roots(project_root)
    idx = build_callsite_index(api_calls)

    injected_headers = sorted({
        h for w in wrappers for h in (w.get('injected_headers') or [])
    } | set(identity_roots.get('header_names') or []))
    # Prefer auth-like headers.
    auth_headers = [h for h in injected_headers if re.search(r'(token|authorization|appidentity|sign)', h, re.I)]
    if not auth_headers and injected_headers:
        auth_headers = injected_headers[:3]

    wrapper_method_by_export: Dict[str, str] = {}
    wrapper_default_method = None
    method_votes: Counter = Counter()
    for w in wrappers:
        for m in w.get('default_methods') or []:
            if m.get('export_name'):
                wrapper_method_by_export[str(m['export_name']).lower()] = m['method']
            if m.get('method') in {'GET', 'POST'}:
                method_votes[m['method']] += int(10 * float(m.get('confidence') or 0.5))
            elif m.get('method'):
                method_votes[m['method']] += 1
    if method_votes:
        wrapper_default_method = sorted(
            method_votes.items(),
            key=lambda x: (-x[1], 0 if x[0] in {'GET', 'POST'} else 1, x[0]),
        )[0][0]
        if wrapper_default_method not in {'GET', 'POST'} and (
            method_votes.get('GET') or method_votes.get('POST')
        ):
            wrapper_default_method = 'POST' if method_votes.get('POST', 0) >= method_votes.get('GET', 0) else 'GET'

    stats = Counter()
    out: List[Dict[str, Any]] = []

    for op in operations:
        op = dict(op)
        path = _normalize_path(_path_of(op))
        params = set(op.get('param_schema') or [])
        headers = set(op.get('header_schema') or [])

        # 1) Inherit method/params from matching callsites.
        related: List[Dict[str, Any]] = []
        related.extend(idx['by_path'].get(path) or [])
        for uk in op.get('url_key_candidates') or []:
            related.extend(idx['by_key'].get(str(uk)) or [])
        for c in related[:40]:
            m = (c.get('method') or '').upper()
            callee = str(c.get('callee') or '').lower()
            if m and m != 'UNKNOWN' and (
                op.get('method') == 'UNKNOWN'
                or float(op.get('method_confidence') or 0) < 0.9
            ):
                conf = 0.92 if any(callee.endswith('.' + x) or callee == x for x in ('get', 'post', 'put', 'delete')) else 0.8
                if conf >= float(op.get('method_confidence') or 0):
                    op['method'] = m
                    op['method_source'] = 'callsite_alignment'
                    op['method_confidence'] = conf
                    stats['method_from_callsite'] += 1
            for k in c.get('data_keys') or []:
                params.add(k)
            for k in c.get('header_keys') or []:
                headers.add(k)
            # Callee-based method from wrapper exports: http.get / request.post
            for export, method in wrapper_method_by_export.items():
                if callee.endswith('.' + export) or callee == export or f'/{export}' in callee:
                    if float(op.get('method_confidence') or 0) < 0.9:
                        op['method'] = method
                        op['method_source'] = 'wrapper_export_callee'
                        op['method_confidence'] = 0.88
                        stats['method_from_wrapper_export'] += 1

        # 2) Slice recovery on supporting sources (+ registry enrichment).
        if project_root:
            sources = list(op.get('supporting_sources') or [])
            for src in sources[:12]:
                ev = enrich_source_evidence(project_root, path, src, None)
                focused = ev.get('focused_text') or ''
                for k in ev.get('recovered_params') or []:
                    params.add(k)
                for k in _recover_keys_from_text(focused):
                    params.add(k)
                slice_method = infer_method_from_slice(focused, path)
                if slice_method and slice_method.get('method_confidence', 0) > float(op.get('method_confidence') or 0):
                    op['method'] = slice_method['method']
                    op['method_source'] = slice_method['method_source']
                    op['method_confidence'] = slice_method['method_confidence']
                    stats['method_from_slice'] += 1
                # Attach richer source meta for request_facts.
                if isinstance(src, dict) and focused and len(str(src.get('snippet') or '')) < 200:
                    src = dict(src)
                    src['snippet'] = focused[:800]
                    src['evidence_strategy'] = ev.get('focus_meta', {}).get('strategy') or src.get('evidence_strategy')

        # 3) Wrapper default method / path convention fallback.
        if op.get('method') == 'UNKNOWN' or float(op.get('method_confidence') or 0) < 0.5:
            conv = infer_method_from_path(path)
            if conv:
                op['method'] = conv['method']
                op['method_source'] = conv['method_source']
                op['method_confidence'] = conv['method_confidence']
                stats['method_from_path'] += 1
            elif wrapper_default_method:
                op['method'] = wrapper_default_method
                op['method_source'] = 'wrapper_default_method'
                op['method_confidence'] = 0.58
                stats['method_from_wrapper_default'] += 1
            elif re.search(r'/(auth|upload|verify|pay|submit|login)', path, re.I):
                op['method'] = 'POST'
                op['method_source'] = 'path_convention_sensitive_verb'
                op['method_confidence'] = 0.52
                stats['method_from_sensitive_path'] += 1
            else:
                # Last resort for business ops: most mini-program business wrappers default POST.
                op['method'] = 'POST'
                op['method_source'] = 'business_default_post_weak'
                op['method_confidence'] = 0.4
                stats['method_business_default_post'] += 1

        # 4) Inject identity/auth headers from wrappers (contract-critical).
        for h in auth_headers:
            headers.add(h)
        if auth_headers:
            stats['ops_with_injected_headers'] += 1
            op['wrapper_injected_headers'] = auth_headers
            op['identity_roots'] = {
                'storage_keys': identity_roots.get('storage_keys') or [],
                'global_fields': identity_roots.get('global_fields') or [],
            }

        # 5) Transform hints from wrappers.
        crypto_files = [w.get('file') for w in wrappers if w.get('crypto_hints')]
        if crypto_files or any(w.get('crypto_hints') for w in wrappers):
            op['transform_hints'] = {
                'binding': 'wrapper_default_chain',
                'wrapper_files': [w.get('file') for w in wrappers if w.get('file')][:8],
                'crypto_hints': sorted({
                    h for w in wrappers for h in (w.get('crypto_hints') or [])
                })[:20],
                'header_hints': auth_headers,
            }
            stats['ops_with_transform_hints'] += 1

        op['param_schema'] = sorted(params)
        op['header_schema'] = sorted(headers)
        cred = Counter()
        for k in list(params) + list(headers):
            cred[classify_credential(k)] += 1
        op['credential_roles'] = dict(cred)
        out.append(op)

    report = {
        'enriched_ops': len(out),
        'stats': dict(stats),
        'auth_headers': auth_headers,
        'identity_roots': identity_roots,
        'wrapper_count': len(wrappers),
    }
    return out, report
