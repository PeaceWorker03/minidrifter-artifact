# -*- coding: utf-8 -*-
from __future__ import annotations
import re
from pathlib import Path
from typing import Any, Dict, List, Optional
from minidrifter.core.patterns import SENSITIVE_DOMAIN_KEYS
from minidrifter.core.utils import line_no, normalize_rel, read_text, short_snippet, stable_id, tokenise_identifier


class URLRegistryExtractor:
    """Recover global or local API URL registries from app.js/config/api files."""
    DEFINE_PROPERTY_RE = re.compile(r'\b(?:[A-Za-z_$][\w$]*|Object\.defineProperty)\s*\(\s*([A-Za-z_$][\w$]*)\s*,\s*["\']([A-Za-z_$][\w$]*)["\']\s*,\s*([^\)]+?)\s*\)')
    OBJECT_PAIR_RE = re.compile(r'([A-Za-z_$][\w$]*)\s*:\s*((?:[A-Za-z_$][\w$]*\s*\+\s*)?["\'][^"\']+(?:["\'])|["\']https?://[^"\']+["\'])')
    ASSIGN_PAIR_RE = re.compile(r'([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\.([A-Za-z_$][\w$]*)\s*=\s*((?:[A-Za-z_$][\w$]*\s*\+\s*)?["\'][^"\']+(?:["\'])|["\']https?://[^"\']+["\'])')

    def __init__(self, root: Path):
        self.root = root

    def _resolve_expr(self, expr: str, constants: Dict[str, str]) -> Optional[str]:
        expr = expr.strip().rstrip(',')
        parts = [p.strip() for p in expr.split('+')]
        out = ''
        for p in parts:
            if not p:
                continue
            if (p.startswith('"') and p.endswith('"')) or (p.startswith("'") and p.endswith("'")):
                out += p[1:-1]
            elif p in constants:
                out += constants[p]
            else:
                return None
        if out.startswith('http') or '/' in out or '?' in out:
            return out
        return None

    def run(self) -> Dict[str, Any]:
        entries: Dict[str, Dict[str, Any]] = {}
        constants_global: Dict[str, str] = {}
        js_files = list(self.root.rglob('*.js'))
        # global scan for host/base constants, because app.js often defines A = "https://...".
        host_re = re.compile(r'\b([A-Za-z_$][\w$]*)\s*=\s*[\"\'](https?://[^\"\']+/?)[\"\']')
        for js in js_files:
            text = read_text(js)
            for m in host_re.finditer(text):
                constants_global[m.group(1)] = m.group(2)
        for js in js_files:
            rel = normalize_rel(js, self.root)
            text = read_text(js)
            constants = dict(constants_global)
            for m in host_re.finditer(text):
                constants[m.group(1)] = m.group(2)
            candidates = []
            # Common decompiled patterns: key: A + "path" and o(e, "key", A + "path")
            for m in re.finditer(r'([A-Za-z_$][\w$]*)\s*:\s*([A-Za-z_$][\w$]*)\s*\+\s*[\"\']([^\"\']+)[\"\']', text):
                candidates.append((m.group(1), f'{m.group(2)} + \"{m.group(3)}\"', m.start()))
            for m in re.finditer(r'\bo\(e,\s*[\"\']([^\"\']+)[\"\']\s*,\s*([A-Za-z_$][\w$]*)\s*\+\s*[\"\']([^\"\']+)[\"\']\s*\)', text):
                candidates.append((m.group(1), f'{m.group(2)} + \"{m.group(3)}\"', m.start()))
            for m in re.finditer(r'([A-Za-z_$][\w$]*)\s*:\s*[\"\'](https?://[^\"\']+|[^\"\n]*[/][^\"\n]*)[\"\']', text):
                candidates.append((m.group(1), f'\"{m.group(2)}\"', m.start()))
            for m in re.finditer(r'\bo\(e,\s*[\"\']([^\"\']+)[\"\']\s*,\s*[\"\']([^\"\']+)[\"\']\s*\)', text):
                candidates.append((m.group(1), f'\"{m.group(2)}\"', m.start()))
            for m in self.OBJECT_PAIR_RE.finditer(text):
                candidates.append((m.group(1), m.group(2), m.start()))
            for m in self.DEFINE_PROPERTY_RE.finditer(text):
                candidates.append((m.group(2), m.group(3), m.start()))
            for m in self.ASSIGN_PAIR_RE.finditer(text):
                candidates.append((m.group(2), m.group(3), m.start()))
            for key, expr, idx in candidates:
                val = self._resolve_expr(expr, constants)
                if not val:
                    continue
                # Filter weakly: keep backend URLs/API paths, not frontend page routes.
                if val.startswith('/pages') or val.startswith('../') or val.startswith('./'):
                    continue
                from minidrifter.optimizers.url_utils import (
                    classify_url_type,
                    is_frontend_route_path,
                    is_probable_url,
                )
                if not is_probable_url(val) or is_frontend_route_path(val):
                    continue
                cls = classify_url_type(val, key, rel)
                if cls.get('url_type') in {
                    'static_asset',
                    'telemetry_or_errorlog',
                    'frontend_route',
                    'third_party_or_telemetry',
                }:
                    continue
                # Keep absolute hosts and any multi-segment / business-classified relative path.
                if not val.startswith('http') and not cls.get('is_business_api') and val.count('/') < 2:
                    continue
                eid = stable_id('url', key, val, rel)
                tokens = tokenise_identifier(key + ' ' + val)
                entries[key] = {
                    'url_id': eid,
                    'url_key': key,
                    'resolved_url': val,
                    'raw_expr': expr.strip(),
                    'key_tokens': tokenise_identifier(key),
                    'path_tokens': tokenise_identifier(val),
                    'business_hints': sorted(set(t for t in tokens if SENSITIVE_DOMAIN_KEYS.search(t))),
                    'source': {'file': rel, 'line': line_no(text, idx), 'snippet': short_snippet(text, idx)},
                    'use_count': 0,
                    'reachability': 'registered_only',
                }
        return {'entries': entries, 'host_constants': constants_global, 'count': len(entries)}
