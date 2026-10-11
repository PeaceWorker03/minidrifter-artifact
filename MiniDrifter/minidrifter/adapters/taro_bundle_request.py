# -*- coding: utf-8
"""Request adapter for Taro bundle-inline API recovery ({api: \"/path\"} pattern)."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from minidrifter.adapters.base import RequestAdapter

_API_PATH_RE = re.compile(r'api\s*:\s*["\']([^"\']+)["\']', re.I)
_METHOD_RE = re.compile(r'method\s*:\s*["\'](GET|POST|PUT|DELETE)["\']', re.I)


class TaroBundleRequestAdapter(RequestAdapter):
    """Recover operations from embedded api: literals and /action|/resource path conventions."""

    def __init__(self, profile: Dict[str, Any] | None = None) -> None:
        self._profile = profile or {}
        self._prefix_hosts: Dict[str, str] = dict(self._profile.get('path_prefix_hosts') or {})
        self._method_rules = self._profile.get('method_inference') or {}

    def detect_wrapper(self, project_root: Path, output_dir: Path) -> Optional[Dict[str, Any]]:
        wrappers_path = Path(output_dir) / 'request_wrappers.json'
        if not wrappers_path.exists():
            return None
        wrappers: List[Dict[str, Any]] = json.loads(wrappers_path.read_text(encoding='utf-8'))
        if not isinstance(wrappers, list):
            return None

        scored: List[tuple[float, Dict[str, Any]]] = []
        for w in wrappers:
            score = 0.0
            headers = {h.lower() for h in (w.get('header_hints') or [])}
            crypto = {h.lower() for h in (w.get('crypto_hints') or [])}
            wf = (w.get('file') or '').replace('\\', '/').lower()
            if w.get('calls_platform_request'):
                score += 10.0
            if 'token' in headers:
                score += 6.0
            if 'sign' in headers:
                score += 6.0
            if crypto & {'aes', 'encrypt', 'sign', 'md5'}:
                score += 8.0
            if 'common.js' in wf:
                score += 12.0
            elif wf.endswith('app.js'):
                score += 4.0
            if score > 0:
                scored.append((score, w))
        if not scored:
            return wrappers[0] if wrappers else None
        scored.sort(key=lambda x: x[0], reverse=True)
        best = scored[0][1]
        return {
            'wrapper_id': best.get('wrapper_id'),
            'file': best.get('file'),
            'adapter': 'taro_bundle_request',
            'header_hints': best.get('header_hints') or [],
            'crypto_hints': best.get('crypto_hints') or [],
            'score': round(scored[0][0], 2),
        }

    def recover_operation(self, callsite: Dict[str, Any]) -> Dict[str, Any]:
        path = callsite.get('path') or callsite.get('api_path') or ''
        snippet = (callsite.get('snippet') or callsite.get('evidence') or '')
        if isinstance(snippet, dict):
            snippet = snippet.get('snippet') or ''

        if not path:
            m = _API_PATH_RE.search(str(snippet))
            if m:
                path = m.group(1)
        if not path:
            url = callsite.get('resolved_url') or callsite.get('url') or ''
            if url.startswith('/'):
                path = url.split('?', 1)[0]

        method = callsite.get('method')
        method_source = callsite.get('method_source') or 'adapter'
        if path.startswith('/action/') or path.startswith('/resource/'):
            method, method_source = self._infer_method_from_path(path)
        elif not method or method == 'UNKNOWN':
            explicit = _METHOD_RE.search(str(snippet))
            if explicit:
                method = explicit.group(1).upper()
                method_source = 'explicit_snippet'
            else:
                method, method_source = self._infer_method_from_path(path)

        host = callsite.get('host') or ''
        if not host and path:
            host = self._resolve_host(path)

        return {
            'path': path,
            'method': method or 'UNKNOWN',
            'method_source': method_source,
            'host': host,
            'normalized_url': f'{host}{path}' if host and path else path,
            'param_style': 'taro_api_literal',
            'adapter': 'taro_bundle_request',
            'confidence': 0.55 if method and method != 'UNKNOWN' else 0.35,
        }

    def _infer_method_from_path(self, path: str) -> tuple[str, str]:
        path = path or ''
        action_rule = self._method_rules.get('action_prefix') or {}
        resource_rule = self._method_rules.get('resource_prefix') or {}
        if path.startswith(action_rule.get('prefix') or '/action/'):
            return action_rule.get('method') or 'POST', 'path_convention_action'
        if path.startswith(resource_rule.get('prefix') or '/resource/'):
            return resource_rule.get('method') or 'GET', 'path_convention_resource'
        if '/action/' in path:
            return 'POST', 'path_convention_action'
        if '/resource/' in path:
            return 'GET', 'path_convention_resource'
        return 'UNKNOWN', 'unresolved'

    def _resolve_host(self, path: str) -> str:
        if not path:
            return ''
        business = path.startswith('/action/') or path.startswith('/resource/') or '/carrctapi' in path
        if not business:
            return ''
        for prefix, host in sorted(self._prefix_hosts.items(), key=lambda x: -len(x[0])):
            if path.startswith(prefix):
                return host.rstrip('/')
        hints = self._profile.get('host_hints') or []
        return hints[0] if hints else ''
