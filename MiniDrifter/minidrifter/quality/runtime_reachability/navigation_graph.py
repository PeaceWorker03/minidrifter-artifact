# -*- coding: utf-8 -*-
"""Real navigation graph from navigateTo / switchTab / Taro router calls."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

_NAV_PATTERNS = [
    re.compile(
        r'(?:wx\.)?(?:navigateTo|redirectTo|reLaunch|switchTab|T8)\s*\(\s*\{[^}]*url\s*:\s*["\']([^"\']+)["\']',
        re.I,
    ),
    re.compile(
        r'(?:Taro\.)?navigateTo\s*\(\s*\{[^}]*url\s*:\s*["\']([^"\']+)["\']',
        re.I,
    ),
]
_PAGE_ID_RE = re.compile(r'^((?:pages|package|third-platform)/[\w./-]+?)(?:/index)?$')

BUNDLE_CHUNK_MARKERS = ('/sub-common/', '/sub-vendors/', '/vendors.js', '/common.js')


def _load_json(path: Path) -> Any:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding='utf-8'))


def project_root_from_pack(pack_dir: Path) -> Optional[Path]:
    prof = _load_json(pack_dir / 'project_profile.json') or {}
    root = prof.get('project_root')
    if root and Path(root).is_dir():
        return Path(root)
    parent = pack_dir.parent
    if (parent / 'app.json').exists():
        return parent
    return None


def is_user_facing_page(page_id: Optional[str]) -> bool:
    if not page_id:
        return False
    low = page_id.replace('\\', '/').lower()
    if any(m in low for m in BUNDLE_CHUNK_MARKERS):
        return False
    return bool(_PAGE_ID_RE.match(page_id.replace('\\', '/')))


def page_id_from_source_file(fpath: str) -> Optional[str]:
    fpath = (fpath or '').replace('\\', '/')
    if '/pages/' not in fpath and not fpath.startswith('pages/'):
        if '/package/' not in fpath and not fpath.startswith('package/'):
            return None
    base = fpath.rsplit('.', 1)[0]
    m = re.search(r'((?:pages|package|third-platform)/[\w./-]+)', base)
    return m.group(1).rstrip('/') if m else None


def normalize_page_url(url: str) -> Optional[str]:
    url = (url or '').split('?', 1)[0].strip()
    if url.startswith('/'):
        url = url[1:]
    m = _PAGE_ID_RE.match(url)
    if not m:
        return None
    page = m.group(1)
    if not page.endswith('/index') and page.count('/') >= 1:
        if not any(page.endswith(x) for x in ('.js', '.wxml')):
            pass
    return page.rstrip('/')


def page_role(page_id: Optional[str]) -> str:
    if not page_id:
        return 'unknown'
    low = page_id.replace('\\', '/').lower()
    if '/sub-common/' in low or '/sub-vendors/' in low:
        return 'bundle_chunk'
    if low.endswith('common.js') or '/vendors/' in low:
        return 'bundle_chunk'
    if is_user_facing_page(page_id):
        return 'user_page'
    return 'unknown'


def build_navigation_graph(project_root: Path) -> Dict[str, Any]:
    """Build inbound/outbound edges between user-facing pages."""
    root = Path(project_root)
    inbound: Dict[str, List[Dict[str, Any]]] = {}
    outbound: Dict[str, List[Dict[str, Any]]] = {}
    tab_pages: List[Dict[str, Any]] = []
    entry_page = 'pages/index/index'

    app = _load_json(root / 'app.json') or {}
    entry_page = app.get('entryPagePath') or entry_page
    for item in (app.get('tabBar') or {}).get('list') or []:
        tab_pages.append({
            'text': item.get('text'),
            'pagePath': (item.get('pagePath') or '').replace('.html', ''),
        })

    if not root.is_dir():
        return {
            'entry_page': entry_page,
            'tab_pages': tab_pages,
            'inbound': inbound,
            'outbound': outbound,
            'edge_count': 0,
        }

    for js in root.rglob('*.js'):
        rel = str(js.relative_to(root)).replace('\\', '/')
        from_page = page_id_from_source_file(rel)
        if not from_page:
            continue
        try:
            text = js.read_text(encoding='utf-8', errors='replace')
        except OSError:
            continue
        for pat in _NAV_PATTERNS:
            for m in pat.finditer(text):
                to_page = normalize_page_url(m.group(1))
                if not to_page or not is_user_facing_page(to_page):
                    continue
                nav_kind = 'switchTab' if 'switchTab' in m.group(0) else 'navigateTo'
                edge = {
                    'from_page': from_page,
                    'to_page': to_page,
                    'evidence': f'{nav_kind}_call',
                    'source_file': rel,
                    'confidence': 0.94 if nav_kind == 'switchTab' else 0.90,
                }
                inbound.setdefault(to_page, []).append(edge)
                outbound.setdefault(from_page, []).append(edge)

    return {
        'entry_page': entry_page,
        'tab_pages': tab_pages,
        'inbound': inbound,
        'outbound': outbound,
        'edge_count': sum(len(v) for v in inbound.values()),
    }


def navigation_steps_to_page(
    nav_graph: Dict[str, Any],
    target_page: str,
) -> List[Dict[str, Any]]:
    """BFS from entry_page to target; return step edges."""
    entry = nav_graph.get('entry_page') or 'pages/index/index'
    inbound = nav_graph.get('inbound') or {}
    if target_page == entry:
        return [{'step': 1, 'action': f'打开小程序首页（{entry}）', 'evidence': 'entry_page'}]

    # direct inbound from entry or tab
    for edge in inbound.get(target_page) or []:
        if edge.get('from_page') == entry or any(
            edge.get('from_page') == t.get('pagePath') for t in nav_graph.get('tab_pages') or []
        ):
            return [
                {'step': 1, 'action': f'从 `{edge["from_page"]}` 跳转', 'evidence': edge.get('evidence'), 'edge': edge},
                {'step': 2, 'action': f'进入 `{target_page}`', 'evidence': 'navigate_target'},
            ]

    for edge in inbound.get(target_page) or []:
        return [
            {'step': 1, 'action': f'从 `{edge.get("from_page")}` 进入（{edge.get("source_file", "")}）', 'evidence': edge.get('evidence'), 'edge': edge},
            {'step': 2, 'action': f'到达 `{target_page}`', 'evidence': 'navigate_target'},
        ]
    return []
