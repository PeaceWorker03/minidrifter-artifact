# -*- coding: utf-8 -*-
from __future__ import annotations
from pathlib import Path
from typing import Any, Dict, List
from minidrifter.core.utils import normalize_rel, try_json


class PageSurfaceExtractor:
    def __init__(self, root: Path):
        self.root = root

    def _page_files(self, page_id: str) -> Dict[str, str | None]:
        base = self.root / page_id
        out = {}
        for ext in ['.js', '.wxml', '.json', '.wxss']:
            p = base.with_suffix(ext)
            out[ext[1:]] = normalize_rel(p, self.root) if p.exists() else None
        return out

    def run(self) -> Dict[str, Any]:
        app_json = try_json(self.root / 'app.json') or {}
        app_config = try_json(self.root / 'app-config.json') or {}
        pages = []
        seen = set()
        tab_pages = set()
        for item in (app_json.get('tabBar') or {}).get('list', []) if isinstance(app_json.get('tabBar'), dict) else []:
            if isinstance(item, dict) and item.get('pagePath'):
                tab_pages.add(item['pagePath'].replace('\\', '/').removesuffix('.html'))
        def add_page(page_id: str, subpackage=None, declared_from='app.json'):
            page_id = page_id.replace('\\', '/').removesuffix('.html')
            if page_id in seen:
                return
            seen.add(page_id)
            pages.append({
                'page_id': page_id,
                'subpackage': subpackage,
                'declared_from': declared_from,
                'is_tab_page': page_id in tab_pages,
                'files': self._page_files(page_id),
            })
        for p in app_json.get('pages') or []:
            add_page(p, None, 'app.json')
        for sp in app_json.get('subPackages') or app_json.get('subpackages') or []:
            root = sp.get('root', '').strip('/').replace('\\', '/')
            for p in sp.get('pages') or []:
                add_page(f'{root}/{p}'.strip('/'), root, 'app.json:subPackages')
        # app-config sometimes carries page routes in pages or entryPagePath
        cfg_pages = app_config.get('pages') or []
        if isinstance(cfg_pages, dict):
            cfg_pages = list(cfg_pages.keys())
        for p in cfg_pages:
            if isinstance(p, str):
                add_page(p, None, 'app-config.json')
        # fallback: all wxml/js pairs under pages/components
        for wxml in self.root.rglob('*.wxml'):
            rel = normalize_rel(wxml.with_suffix(''), self.root)
            if rel not in seen and (wxml.with_suffix('.js')).exists():
                add_page(rel, None, 'filesystem_pair')
        components = []
        for js in self.root.rglob('*.js'):
            if '/components/' in ('/' + normalize_rel(js, self.root)) or normalize_rel(js, self.root).startswith('components/'):
                components.append({
                    'component_id': normalize_rel(js.with_suffix(''), self.root),
                    'files': self._page_files(normalize_rel(js.with_suffix(''), self.root)),
                })
        return {
            'pages': pages,
            'components': components,
            'permissions': app_json.get('permission') or app_config.get('permission') or {},
            'required_private_infos': app_json.get('requiredPrivateInfos') or app_config.get('requiredPrivateInfos') or [],
            'window': app_json.get('window') or app_config.get('window') or {},
        }
