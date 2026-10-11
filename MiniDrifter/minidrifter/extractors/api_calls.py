# -*- coding: utf-8 -*-
from __future__ import annotations
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from minidrifter.core.patterns import HTTP_METHODS, PLATFORM_APIS
from minidrifter.core.utils import extract_object_keys, find_matching_paren, line_no, normalize_rel, read_text, short_snippet, split_args, stable_id
from minidrifter.extractors.js_ast import scan_platform_calls


class APICallSiteExtractor:
    """Recover concrete and dynamic API call sites from JS files.

    It is designed for decompiled code. It uses URL-registry keys, wrapper aliases, and stable wx.request anchors.
    """

    def __init__(self, root: Path, url_registry: Dict[str, Any], aliases: Dict[str, Any], wrappers: List[Dict[str, Any]], platform: str = 'wechat'):
        self.root = root
        self.url_entries = url_registry.get('entries', {})
        self.aliases = aliases.get('files', {})
        self.wrappers = wrappers
        self.platform = platform
        self.wrapper_files = {w['file'] for w in wrappers}
        self.wrapper_alias_by_file: Dict[str, List[str]] = {}

    def _aliases_for_file(self, rel: str) -> Dict[str, str]:
        return self.aliases.get(rel, {}).get('aliases', {})

    def _resolve_url_expr(self, expr: str, rel: str) -> Tuple[Optional[str], Optional[str], str]:
        expr_clean = expr.strip()
        # direct string URL
        m = re.search(r'["\'](https?://[^"\']+|/[^"\']+)["\']', expr_clean)
        if m:
            val = m.group(1)
            if val.startswith('/pages') or val.startswith('../') or val.startswith('./'):
                return None, None, expr_clean
            # try reverse key lookup
            for k, e in self.url_entries.items():
                if e.get('resolved_url') == val:
                    return k, val, expr_clean
            return None, val, expr_clean
        # property reference like a.UserBalance, getApp().url.UserBalance, or k.url.WeChatOpenId + a.des.
        # In concatenated encrypted URLs, the final property may be `des`; choose the first property that is a known URL key.
        props = re.findall(r'\.([A-Za-z_$][\w$]*)\b', expr_clean)
        bracket_props = re.findall(r'\[["\']([A-Za-z_$][\w$]*)["\']\]', expr_clean)
        for prop in props + bracket_props:
            if prop in self.url_entries:
                return prop, self.url_entries[prop].get('resolved_url'), expr_clean
        prop = (props + bracket_props)[-1] if (props or bracket_props) else None
        # If expression itself is a key
        if expr_clean in self.url_entries:
            return expr_clean, self.url_entries[expr_clean].get('resolved_url'), expr_clean
        return prop, None, expr_clean

    def _is_wrapper_callee(self, callee: str, rel: str) -> bool:
        callee_lower = callee.lower()
        if any(callee_lower.endswith('.' + m) or callee_lower == m for m in HTTP_METHODS):
            return True
        if 'request' in callee_lower or 'http' in callee_lower or 'fetch' in callee_lower:
            return True
        aliases = self._aliases_for_file(rel)
        base = callee.split('.')[0]
        if base in aliases and 'require:' in aliases[base]:
            target = aliases[base]
            if any(wf in target for wf in self.wrapper_files):
                return True
        return False

    def _method_from_callee(self, callee: str, args: List[str]) -> str:
        low = callee.lower()
        for m in HTTP_METHODS:
            if low.endswith('.' + m) or low == m:
                return m.upper()
        # options object may have method
        if args:
            mm = re.search(r'\bmethod\s*:\s*["\']([A-Za-z]+)["\']', args[0], re.I)
            if mm:
                return mm.group(1).upper()
        return 'UNKNOWN'

    def _extract_call_args(self, text: str, start: int) -> Tuple[str, List[str], int]:
        # start points at callee beginning; find first '(' after it and match.
        open_idx = text.find('(', start)
        if open_idx < 0:
            return '', [], start
        close_idx = find_matching_paren(text, open_idx)
        if close_idx < 0:
            return '', [], open_idx
        return text[open_idx+1:close_idx], split_args(text[open_idx+1:close_idx]), close_idx

    def _extract_callee_before(self, text: str, open_idx: int) -> Tuple[str, int]:
        left = text[:open_idx]
        m = re.search(r'([A-Za-z_$][\w$]*(?:\.(?:default\.)?[A-Za-z_$][\w$]*)*)\s*$', left)
        if not m:
            return '', open_idx
        return m.group(1), m.start(1)

    def _parse_options_object(self, arg: str, rel: str) -> Tuple[Optional[str], Optional[str], str, List[str], List[str]]:
        um = re.search(r'\b(?:url|api)\s*:\s*([^,}\n]+)', arg)
        mm = re.search(r'\b(?:method|type)\s*:\s*["\']([A-Za-z]+)["\']', arg, re.I)
        dm = re.search(r'\b(?:data|body|params|query)\s*:\s*({[^}]*}|[A-Za-z_$][\w$.]*)', arg, re.S)
        hm = re.search(r'\bheader\s*:\s*({[^}]*}|[A-Za-z_$][\w$.]*)', arg, re.S)
        url_key = resolved = None
        url_expr = ''
        if um:
            url_key, resolved, url_expr = self._resolve_url_expr(um.group(1), rel)
        data_keys = extract_object_keys(dm.group(1)) if dm else []
        header_keys = extract_object_keys(hm.group(1)) if hm else []
        return url_key, resolved, url_expr, data_keys, header_keys

    def _build_call(self, *, rel: str, text: str, idx: int, callee: str, args: List[str], call_type: str) -> Optional[Dict[str, Any]]:
        method = self._method_from_callee(callee, args)
        url_key = resolved_url = url_expr = None
        param_exprs = []
        data_keys: List[str] = []
        header_keys: List[str] = []
        desc = None
        if call_type == 'platform_request' and args:
            url_key, resolved_url, url_expr, data_keys, header_keys = self._parse_options_object(args[0], rel)
        else:
            if args:
                url_key, resolved_url, url_expr = self._resolve_url_expr(args[0], rel)
            # common wrapper conventions: get(url, params, desc), post(url, query, body, desc)
            for a in args[1:3]:
                param_exprs.append(a)
                data_keys.extend(extract_object_keys(a))
            for a in args[1:]:
                st = a.strip()
                if (st.startswith('"') and st.endswith('"')) or (st.startswith("'") and st.endswith("'")):
                    val = st[1:-1]
                    if len(val) >= 2 and not val.startswith('http'):
                        desc = val
                        break
        # dynamic/unknown calls still matter if callee is wrapper.
        dynamic = resolved_url is None
        if not resolved_url and not self._is_wrapper_callee(callee, rel) and call_type != 'platform_request':
            return None
        return {
            'api_call_id': stable_id('call', rel, str(idx), callee, url_expr or ''),
            'call_type': call_type,
            'callee': callee,
            'method': method,
            'url_key': url_key,
            'resolved_url': resolved_url,
            'url_expr': url_expr,
            'dynamic_url': dynamic,
            'args': args,
            'param_exprs': param_exprs,
            'data_keys': sorted(set(data_keys)),
            'header_keys': sorted(set(header_keys)),
            'description_arg': desc,
            'source': {'file': rel, 'line': line_no(text, idx), 'snippet': short_snippet(text, idx)},
        }

    def run(self) -> Dict[str, Any]:
        calls: List[Dict[str, Any]] = []
        dynamic: List[Dict[str, Any]] = []
        req_apis = set(PLATFORM_APIS.get(self.platform, PLATFORM_APIS['wechat'])['request'])
        req_apis.update({'wx.uploadFile', 'wx.downloadFile'})
        ast_doc = scan_platform_calls(self.root) or {}
        ast_calls = ast_doc.get('calls') or {}
        for js in self.root.rglob('*.js'):
            rel = normalize_rel(js, self.root)
            text = read_text(js)
            # 1) platform request anchors: Acorn AST when the file parsed, regex otherwise
            ast_hits = [h for h in (ast_calls.get(rel) or []) if h.get('callee') in req_apis]
            if ast_hits:
                for hit in ast_hits:
                    arg_text = text[int(hit['argStart']):int(hit['argEnd'])]
                    args = split_args(arg_text)
                    c = self._build_call(
                        rel=rel, text=text, idx=int(hit['start']),
                        callee=hit['callee'], args=args, call_type='platform_request',
                    )
                    if c:
                        c['parser'] = 'acorn'
                        calls.append(c)
            else:
                for api in req_apis:
                    for m in re.finditer(re.escape(api) + r'\s*\(', text):
                        arg_text, args, close = self._extract_call_args(text, m.start())
                        c = self._build_call(rel=rel, text=text, idx=m.start(), callee=api, args=args, call_type='platform_request')
                        if c:
                            c['parser'] = 'regex'
                            calls.append(c)
            # 2) generic call expressions to wrappers or URL-key first arg.
            for m in re.finditer(r'([A-Za-z_$][\w$]*(?:\.(?:default\.)?[A-Za-z_$][\w$]*)*)\s*\(', text):
                callee = m.group(1)
                if callee in ['if', 'for', 'while', 'switch', 'function', 'return', 'App', 'Page', 'Component', 'Behavior'] or callee.startswith(('wx.', 'console.')):
                    continue
                arg_text, args, close = self._extract_call_args(text, m.start())
                if not args:
                    continue
                url_key, resolved_url, url_expr = self._resolve_url_expr(args[0], rel)
                if resolved_url or self._is_wrapper_callee(callee, rel):
                    # Avoid treating large framework constructors such as App({...url: ...}) as request calls.
                    if (not self._is_wrapper_callee(callee, rel)) and callee in {'App','Page','Component','Behavior','Object','JSON.parse'}:
                        continue
                    c = self._build_call(rel=rel, text=text, idx=m.start(), callee=callee, args=args, call_type='wrapped_or_service_call')
                    if c:
                        if c['dynamic_url']:
                            dynamic.append(c)
                        else:
                            calls.append(c)
        # de-dup
        seen, out = set(), []
        for c in calls:
            key = (c['source']['file'], c['source']['line'], c.get('resolved_url'), c.get('callee'))
            if key not in seen:
                seen.add(key); out.append(c)
        seen_dyn, dyn_out = set(), []
        for c in dynamic:
            key = (c['source']['file'], c['source']['line'], c.get('callee'), c.get('url_expr'))
            if key not in seen_dyn:
                seen_dyn.add(key); dyn_out.append(c)
        return {'api_call_sites': out, 'dynamic_api_candidates': dyn_out}
