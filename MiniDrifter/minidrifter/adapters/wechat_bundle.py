# -*- coding: utf-8
"""WeChat Taro/webpack bundle-inline project adapter (app_service_bundle shape)."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List

from minidrifter.adapters.base import ProjectAdapter
from minidrifter.core.profile import ProjectProfileDetector
from minidrifter.workspace.decompile_gate import classify_project_state

_BUNDLE_ENTRY_FILES = ('common.js', 'vendors.js', 'taro.js', 'runtime.js', 'app.js')
_API_LITERAL_RE = re.compile(r'api\s*:\s*["\']([^"\']+)["\']', re.I)
_PAGE_ROUTE_RE = re.compile(r'["\']([^"\']+/pages/[^"\']+)["\']')


class WeChatBundleProjectAdapter(ProjectAdapter):
    """Detect Taro/webpack bundle-inline mini-programs (no pages/ dir, app-service.js)."""

    def detect(self, project_root: Path) -> Dict[str, Any]:
        root = Path(project_root)
        profile = ProjectProfileDetector(root).run()
        gate = classify_project_state(root)
        framework = self._detect_framework(root)
        return {
            'adapter': 'wechat_bundle',
            'profile': profile,
            'framework': framework,
            'surface_shape': 'bundle_inline',
            'ready': gate.get('state') == 'READY_DECOMPILED' or profile.get('has_app_service_js'),
            'audit_state': gate.get('state'),
            'message': gate.get('message'),
        }

    def extract_pages(self, project_root: Path) -> List[Dict[str, Any]]:
        root = Path(project_root)
        pages: List[Dict[str, Any]] = []
        seen: set[str] = set()

        app_config = root / 'app-config.json'
        if app_config.exists():
            doc = json.loads(app_config.read_text(encoding='utf-8'))
            for p in doc.get('pages') or []:
                if p not in seen:
                    seen.add(p)
                    pages.append({'route': p, 'source': 'app-config.json'})

        for js_path in root.rglob('*.js'):
            if js_path.stat().st_size > 2_000_000:
                continue
            rel = str(js_path.relative_to(root)).replace('\\', '/')
            if '/pages/' not in rel and 'app-service' not in rel:
                continue
            try:
                text = js_path.read_text(encoding='utf-8', errors='ignore')[:500_000]
            except OSError:
                continue
            for m in _PAGE_ROUTE_RE.finditer(text):
                route = m.group(1).lstrip('/')
                if route not in seen and len(route) < 120:
                    seen.add(route)
                    pages.append({'route': route, 'source': rel})
            if len(pages) >= 400:
                break
        return pages[:400]

    def extract_api_callsites(self, project_root: Path) -> List[Dict[str, Any]]:
        root = Path(project_root)
        sites: List[Dict[str, Any]] = []
        for js_path in root.rglob('*app-service.js'):
            if js_path.stat().st_size > 3_000_000:
                continue
            rel = str(js_path.relative_to(root)).replace('\\', '/')
            try:
                text = js_path.read_text(encoding='utf-8', errors='ignore')
            except OSError:
                continue
            for m in _API_LITERAL_RE.finditer(text):
                path = m.group(1)
                if not path.startswith('/'):
                    continue
                sites.append({
                    'path': path,
                    'source_file': rel,
                    'surface': 'embedded_literal',
                    'adapter': 'wechat_bundle',
                })
            if len(sites) >= 500:
                break
        return sites

    @staticmethod
    def _detect_framework(root: Path) -> str:
        for name in _BUNDLE_ENTRY_FILES:
            p = root / name
            if not p.exists():
                continue
            head = p.read_text(encoding='utf-8', errors='ignore')[:8000].lower()
            if 'taro' in head or 'webpackjsonp' in head:
                return 'taro'
            if 'uni-app' in head or 'uniapp' in head:
                return 'uni-app'
        return 'webpack_bundle'
