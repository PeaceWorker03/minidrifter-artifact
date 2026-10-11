# -*- coding: utf-8
"""Request adapter for registry-rich decompiled mini-programs (ehai-style)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from minidrifter.adapters.base import RequestAdapter


class WeChatHttpWrapperAdapter(RequestAdapter):
    """Recover operations from resolved_url + explicit wrapper hints."""

    def __init__(self, profile: Dict[str, Any] | None = None) -> None:
        self._profile = profile or {}

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
            if 'appidentity' in headers or 'authorization' in headers:
                score += 10.0
            if crypto & {'aes', 'md5', 'encrypt'}:
                score += 8.0
            if 'utils/http' in wf or 'apigetwayhttp' in wf:
                score += 12.0
            if score > 0:
                scored.append((score, w))
        if not scored:
            return wrappers[0] if wrappers else None
        scored.sort(key=lambda x: x[0], reverse=True)
        best = scored[0][1]
        return {
            'wrapper_id': best.get('wrapper_id'),
            'file': best.get('file'),
            'adapter': 'wechat_http_wrapper',
            'header_hints': best.get('header_hints') or [],
            'crypto_hints': best.get('crypto_hints') or [],
            'score': round(scored[0][0], 2),
        }

    def recover_operation(self, callsite: Dict[str, Any]) -> Dict[str, Any]:
        url = callsite.get('resolved_url') or callsite.get('url') or ''
        path = callsite.get('path') or ''
        if not path and url:
            if '://' in url:
                path = '/' + url.split('://', 1)[1].split('/', 1)[-1].split('?', 1)[0]
                if not path.startswith('/'):
                    path = '/' + path
            elif url.startswith('/'):
                path = url.split('?', 1)[0]

        method = callsite.get('method') or 'UNKNOWN'
        method_source = callsite.get('method_source') or 'registry_resolved'
        return {
            'path': path,
            'method': method,
            'method_source': method_source,
            'normalized_url': url or path,
            'param_style': 'registry_rich',
            'adapter': 'wechat_http_wrapper',
            'confidence': 0.7 if method != 'UNKNOWN' else 0.4,
        }
