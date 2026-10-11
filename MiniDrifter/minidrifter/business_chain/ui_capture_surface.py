# -*- coding: utf-8 -*-
"""Dual-track capture surface — UI-grounded capture vs full chain test targets (generic)."""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from minidrifter.materials.intake_param_hints import normalize_api_path

# Evidence tiers for capture instructions (not chain ranking).
_CAPTURE_EVIDENCE_RANK = {
    'api_call_site_direct': 0.95,
    'registry_callsite_source': 0.90,
    'chunk_require_backtrace': 0.82,
    'chunk_id_backtrace': 0.78,
    'demand_graph_callsite': 0.72,
    'navigate_to_graph': 0.80,
    'tab_bar_entry': 0.75,
    'path_page_hint': 0.35,
    'page_surface_token': 0.40,
    'semantic_path_rule': 0.38,
    'none': 0.0,
}

_BUNDLE_PAGE_MARKERS = ('/sub-common/', '/sub-vendors/', 'webpack', 'common.js')
_NAV_URL_RE = re.compile(
    r'(?:navigateTo|redirectTo|reLaunch|switchTab)\s*\(\s*\{[^}]*url\s*:\s*["\']([^"\']+)["\']',
    re.I,
)
_API_LITERAL_RE = re.compile(r'api\s*:\s*["\']([^"\']+)["\']', re.I)
_ENTRY_PAGE_RE = re.compile(r'^((?:pages|package|third-platform)/[\w./-]+?)(?:/index)?$')

# Runtime supersession: static chain entry → APIs users actually trigger in UI.
_RUNTIME_PROXY_RULES: List[Tuple[re.Pattern[str], re.Pattern[str], str]] = [
    (re.compile(r'deptlist/v1', re.I), re.compile(r'dept/listandmap/v[13]', re.I), 'listAndMap supersedes deptList'),
    (re.compile(r'citylist/v1', re.I), re.compile(r'citylist/v1|new-city-list', re.I), 'cityList entry'),
]


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


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
    if any(m in low for m in _BUNDLE_PAGE_MARKERS):
        return False
    if not _ENTRY_PAGE_RE.match(page_id.replace('\\', '/')):
        return False
    return True


def _normalize_page_from_url(url: str) -> Optional[str]:
    url = (url or '').split('?', 1)[0].strip()
    if url.startswith('/'):
        url = url[1:]
    m = _ENTRY_PAGE_RE.match(url)
    if not m:
        return None
    page = m.group(1)
    if not page.endswith('/index') and '/index' not in page.rsplit('/', 1)[-1]:
        if not page.endswith('.js'):
            page = f'{page}/index' if '/' in page else page
    return page.rstrip('/')


def build_navigation_graph(project_root: Path) -> Dict[str, List[Dict[str, Any]]]:
    """Scan source for navigateTo/reLaunch targets → inbound edges per page."""
    graph: Dict[str, List[Dict[str, Any]]] = {}
    root = Path(project_root)
    if not root.is_dir():
        return graph
    for js in root.rglob('*.js'):
        rel = str(js.relative_to(root)).replace('\\', '/')
        from_page = page_id_from_source_file(rel)
        if not from_page:
            continue
        try:
            text = js.read_text(encoding='utf-8', errors='replace')
        except OSError:
            continue
        for m in _NAV_URL_RE.finditer(text):
            target = _normalize_page_from_url(m.group(1))
            if not target or not is_user_facing_page(target):
                continue
            graph.setdefault(target, []).append({
                'from_page': from_page,
                'source_file': rel,
                'nav_kind': 'switchTab' if 'switchTab' in m.group(0) else 'navigateTo',
            })
    return graph


def page_id_from_source_file(fpath: str) -> Optional[str]:
    fpath = (fpath or '').replace('\\', '/')
    if '/pages/' not in fpath and not fpath.startswith('pages/'):
        if '/package/' not in fpath and not fpath.startswith('package/'):
            return None
    base = fpath.rsplit('.', 1)[0]
    m = re.search(r'((?:pages|package|third-platform)/[\w./-]+)', base)
    return m.group(1).rstrip('/') if m else None


def _callsites_for_api(pack_dir: Path, api_path: str) -> List[Dict[str, Any]]:
    norm = normalize_api_path(api_path)
    tail = norm.rsplit('/', 1)[-1] if norm else ''
    calls = _load_json(pack_dir / 'api_call_sites.json') or []
    if isinstance(calls, dict):
        calls = calls.get('api_call_sites') or calls.get('calls') or []
    out: List[Dict[str, Any]] = []
    for call in calls:
        url = normalize_api_path((call.get('resolved_url') or call.get('url') or '').split('?', 1)[0])
        if not url:
            continue
        if url == norm or norm in url or url.endswith(norm):
            out.append({
                'resolved_url': url or call.get('resolved_url'),
                'source_file': (call.get('source') or {}).get('file', '').replace('\\', '/'),
                'line': (call.get('source') or {}).get('line'),
            })
            continue
        if tail and len(tail) > 4 and tail in url.lower() and url.count('/') >= norm.count('/'):
            out.append({
                'resolved_url': url,
                'source_file': (call.get('source') or {}).get('file', '').replace('\\', '/'),
                'line': (call.get('source') or {}).get('line'),
            })
    return out


def _pages_for_api_callsites(pack_dir: Path, api_path: str) -> List[Tuple[str, str, float]]:
    """Return (page_id, evidence_type, confidence) from callsites + chunk backtrace."""
    from minidrifter.quality.semantics.callsite_backtrace import (
        collect_callsite_page_candidates,
        project_root_from_pack as p3_root,
    )
    from minidrifter.quality.semantics.path_tokens import infer_path_semantic

    pack_dir = Path(pack_dir)
    semantic = infer_path_semantic(api_path)
    norm = normalize_api_path(api_path)
    calls = _load_json(pack_dir / 'api_call_sites.json') or []
    if isinstance(calls, dict):
        calls = calls.get('api_call_sites') or calls.get('calls') or []
    root = p3_root(pack_dir)
    seen: Set[str] = set()
    pages: List[Tuple[str, str, float]] = []

    for call in calls:
        url = normalize_api_path((call.get('resolved_url') or call.get('url') or '').split('?', 1)[0])
        if url != norm and norm.rsplit('/', 1)[-1] not in url.lower():
            continue
        for conf, pg, ev, _meta in collect_callsite_page_candidates(
            call, pack_dir=pack_dir, norm_api=norm, semantic=semantic, project_root=root,
        ):
            if not is_user_facing_page(pg) or pg in seen:
                continue
            seen.add(pg)
            pages.append((pg, ev, conf))
    pages.sort(key=lambda x: x[2], reverse=True)
    return pages


def _apis_invoked_from_page_source(project_root: Path, page_id: str) -> Set[str]:
    """Best-effort: API path literals reachable from a page's JS (incl. sub-common requires)."""
    apis: Set[str] = set()
    js_path = project_root / f'{page_id}.js'
    if not js_path.exists():
        for alt in (project_root / page_id).glob('*.js'):
            js_path = alt
            break
    if not js_path.exists():
        return apis
    try:
        text = js_path.read_text(encoding='utf-8', errors='replace')
    except OSError:
        return apis
    for m in _API_LITERAL_RE.finditer(text):
        apis.add(normalize_api_path(m.group(1)))
    for hm in re.finditer(r'sub-common/([a-f0-9]{8,})\.js', text, re.I):
        sub = project_root / 'package' / 'preload-common' / 'sub-common' / f'{hm.group(1)}.js'
        if not sub.exists():
            for found in project_root.rglob(f'**/sub-common/{hm.group(1)}.js'):
                sub = found
                break
        if sub.exists():
            try:
                st = sub.read_text(encoding='utf-8', errors='replace')
                for m in _API_LITERAL_RE.finditer(st):
                    apis.add(normalize_api_path(m.group(1)))
            except OSError:
                pass
    return apis


def _find_runtime_proxies(
    pack_dir: Path,
    chain_entry_path: str,
    *,
    project_root: Optional[Path],
) -> List[Dict[str, Any]]:
    """When chain entry is static-only, find UI-callable APIs that harvest same objects."""
    from minidrifter.quality.semantics.callsite_backtrace import (
        collect_callsite_page_candidates,
        project_root_from_pack as p3_root,
    )
    from minidrifter.quality.semantics.path_tokens import infer_path_semantic

    norm = normalize_api_path(chain_entry_path)
    proxies: List[Dict[str, Any]] = []
    pack_dir = Path(pack_dir)
    root = project_root or p3_root(pack_dir)
    nav_graph = build_navigation_graph(root) if root else {}
    semantic = infer_path_semantic(chain_entry_path)

    # 1) Rule-based supersession (deptList → listAndMap, etc.)
    for entry_pat, proxy_pat, reason in _RUNTIME_PROXY_RULES:
        if not entry_pat.search(norm):
            continue
        calls = _load_json(pack_dir / 'api_call_sites.json') or []
        if isinstance(calls, dict):
            calls = calls.get('api_call_sites') or calls.get('calls') or []
        for call in calls:
            url = normalize_api_path((call.get('resolved_url') or call.get('url') or '').split('?', 1)[0])
            if not url or not proxy_pat.search(url):
                continue
            for conf, pg, ev, _meta in collect_callsite_page_candidates(
                call, pack_dir=pack_dir, norm_api=url, semantic=semantic, project_root=root,
            ):
                if not is_user_facing_page(pg):
                    continue
                proxies.append({
                    'proxy_path': url,
                    'ui_page': pg,
                    'reason': reason,
                    'inbound_nav': nav_graph.get(pg, [])[:3],
                    'confidence': conf,
                    'evidence': ev,
                })
        if proxies:
            break

    if proxies:
        proxies.sort(key=lambda x: (
            -x.get('confidence', 0),
            -len(x.get('inbound_nav') or []),
            0 if 'index/index' in str((x.get('inbound_nav') or [{}])[0].get('from_page', '')) else 1,
        ))
        return proxies[:4]

    if not root:
        return proxies

    entry_pages = {p for p in nav_graph if is_user_facing_page(p)}

    # 2) Page JS literal scan + token overlap
    for entry_pat, proxy_pat, reason in _RUNTIME_PROXY_RULES:
        if not entry_pat.search(norm):
            continue
        for page in sorted(entry_pages):
            apis = _apis_invoked_from_page_source(root, page)
            for api in sorted(apis):
                if proxy_pat.search(api):
                    proxies.append({
                        'proxy_path': api,
                        'ui_page': page,
                        'reason': reason,
                        'inbound_nav': nav_graph.get(page, [])[:3],
                    })

    if proxies:
        return proxies[:4]

    tail_tokens = [t for t in re.split(r'[/._-]+', norm.lower()) if len(t) > 3]
    for page in sorted(entry_pages)[:40]:
        for api in _apis_invoked_from_page_source(root, page):
            if api == norm:
                continue
            score = sum(1 for t in tail_tokens if t in api.lower())
            if score >= 2:
                proxies.append({
                    'proxy_path': api,
                    'ui_page': page,
                    'reason': f'path_token_overlap:{score}',
                    'inbound_nav': nav_graph.get(page, [])[:3],
                })
    proxies.sort(key=lambda x: (0 if 'supersedes' in x.get('reason', '') else 1))
    return proxies[:4]


def _navigation_steps_verified(
    pack_dir: Path,
    page_id: str,
    nav_graph: Dict[str, List[Dict[str, Any]]],
) -> List[str]:
    """Rule-only navigation from app entry / tab bar / navigate graph — no LLM."""
    root = project_root_from_pack(pack_dir)
    steps: List[str] = []
    if not root or not page_id:
        return steps

    app = _load_json(root / 'app.json') or {}
    entry = app.get('entryPagePath') or 'pages/index/index'
    steps.append(f'打开微信，进入小程序首页（{entry}）')

    for item in (app.get('tabBar') or {}).get('list') or []:
        tab_page = (item.get('pagePath') or '').replace('.html', '')
        if tab_page and (page_id == tab_page or page_id.startswith(tab_page.rsplit('/', 1)[0])):
            label = item.get('text') or 'Tab'
            steps.append(f'点击底部 Tab「{label}」（{tab_page}）')
            if page_id != tab_page and page_id != f'{tab_page}/index':
                steps.append(f'在 Tab 页内继续进入目标页（{page_id}）')
            return steps

    inbound = nav_graph.get(page_id) or []
    if inbound:
        edge = inbound[0]
        from_p = edge.get('from_page') or entry
        if from_p.startswith('pages/index') or 'index/index' in from_p:
            steps.append('在首页订车/业务模块中找到对应入口（见静态导航证据）')
        else:
            steps.append(f'从 `{from_p}` 跳转进入（静态 navigateTo 证据：{edge.get("source_file", "")}）')
        steps.append(f'进入目标页 `{page_id}`')
        return steps

    meta = {}
    surface = _load_json(pack_dir / 'page_surface.json') or {}
    for pg in surface.get('pages') or []:
        if pg.get('page_id') == page_id:
            meta = pg
            break
    if meta.get('subpackage'):
        steps.append(f'该页位于分包 `{meta["subpackage"]}`，需从首页相关入口进入（无直接 Tab）')
    steps.append(f'导航至页面 `{page_id}`（静态分析未找到可靠 navigateTo 路径，请结合真机 UI 确认）')
    return steps


def assess_capture_surface(
    pack_dir: Path,
    req: Dict[str, Any],
    chain: Dict[str, Any],
    entry_ctx: Dict[str, Any],
) -> Dict[str, Any]:
    """Classify one material request: UI capture vs chain-only test target."""
    pack_dir = Path(pack_dir)
    entry_path = normalize_api_path(
        (req.get('example_paths') or [chain.get('entry_path') or ''])[0]
    )
    page_id = (
        req.get('entry_page')
        or entry_ctx.get('entry_page')
        or chain.get('entry_page')
    )
    page_evidence = (
        req.get('entry_page_evidence')
        or entry_ctx.get('entry_page_evidence')
        or chain.get('entry_page_evidence')
        or 'none'
    )
    if not is_user_facing_page(page_id):
        page_id = None

    confidence = float(
        entry_ctx.get('entry_page_confidence')
        or _CAPTURE_EVIDENCE_RANK.get(page_evidence, 0.3)
    )

    root = project_root_from_pack(pack_dir)
    nav_graph = build_navigation_graph(root) if root else {}

    ui_pages = _pages_for_api_callsites(pack_dir, entry_path)
    if ui_pages:
        page_id = page_id or ui_pages[0][0]
        page_evidence = ui_pages[0][1]
        confidence = max(confidence, ui_pages[0][2])

    callsites = _callsites_for_api(pack_dir, entry_path)
    direct_ui_callsite = any(
        normalize_api_path(c.get('resolved_url') or '') == entry_path
        and is_user_facing_page(page_id_from_source_file(c.get('source_file') or ''))
        for c in callsites
    )

    proxies = _find_runtime_proxies(pack_dir, entry_path, project_root=root)

    if direct_ui_callsite and page_id and is_user_facing_page(page_id):
        kind = 'ui_direct'
        capture_paths = [entry_path]
        capture_page = page_id
        capture_evidence = page_evidence
    elif proxies:
        kind = 'ui_proxy'
        best = proxies[0]
        capture_paths = [best['proxy_path'], entry_path]
        capture_page = best['ui_page']
        capture_evidence = 'runtime_proxy'
        confidence = max(confidence, 0.72)
    elif not direct_ui_callsite and not callsites:
        if proxies:
            kind = 'ui_proxy'
            best = proxies[0]
            capture_paths = [best['proxy_path'], entry_path]
            capture_page = best['ui_page']
            capture_evidence = 'runtime_proxy'
            confidence = max(confidence, 0.72)
        else:
            kind = 'bundle_opaque'
            capture_paths = [entry_path]
            capture_page = None
            capture_evidence = 'no_callsite'
            confidence = min(confidence, 0.25)
    elif not direct_ui_callsite and (page_evidence in {'path_page_hint', 'page_surface_token', 'semantic_path_rule'} or not page_id):
        kind = 'static_only'
        capture_paths = [entry_path]
        capture_page = proxies[0]['ui_page'] if proxies else None
        capture_evidence = page_evidence
        confidence = min(confidence, 0.45)
    elif direct_ui_callsite:
        kind = 'ui_direct'
        capture_paths = [entry_path]
        capture_page = page_id
        capture_evidence = page_evidence
    else:
        kind = 'static_only'
        capture_paths = [entry_path]
        capture_page = page_id if is_user_facing_page(page_id) else None
        capture_evidence = page_evidence

    nav_steps = (
        _navigation_steps_verified(pack_dir, capture_page, nav_graph)
        if capture_page else []
    )
    nav_verified = bool(nav_steps) and '请结合真机' not in nav_steps[-1]

    llm_eligible = (
        kind in {'ui_direct', 'ui_proxy'}
        and confidence < 0.85
        and (not nav_verified or not capture_page)
    )

    return {
        'schema_version': '1.0.0',
        'request_id': req.get('request_id'),
        'chain_entry_path': entry_path,
        'chain_entry_api': req.get('entry_api') or chain.get('entry_api'),
        'test_role': 'chain_entry',
        'capture_role': kind,
        'capture_paths': list(dict.fromkeys(capture_paths)),
        'capture_accept_paths': list(dict.fromkeys(
            [entry_path] + [p['proxy_path'] for p in proxies] + capture_paths
        )),
        'ui_page': capture_page,
        'page_evidence': capture_evidence,
        'confidence': round(min(confidence, 0.99), 2),
        'navigation_steps': nav_steps,
        'navigation_verified': nav_verified,
        'runtime_proxies': proxies,
        'ui_pages_from_callsite': [{'page': p, 'evidence': e, 'confidence': c} for p, e, c in ui_pages[:5]],
        'llm_eligible': llm_eligible,
        'user_capture_required': kind in {'ui_direct', 'ui_proxy'},
        'chain_test_included': True,
        'instruction_mode': (
            'ui_grounded' if kind in {'ui_direct', 'ui_proxy'}
            else 'api_only_manual'
        ),
    }


def build_capture_surface_plan(
    pack_dir: Path,
    *,
    material_plan: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build dual-track plan: user capture tasks + full chain test targets."""
    pack_dir = Path(pack_dir)
    from minidrifter.business_chain.chain_hop_enrichment import resolve_entry_context

    plan = material_plan or _load_json(pack_dir / 'chain_material_request_plan.json') or {}
    chains = {
        c['chain_id']: c for c in (_load_json(pack_dir / 'business_chains.json') or {}).get('chains') or []
        if c.get('chain_id')
    }
    surfaces: List[Dict[str, Any]] = []
    for req in plan.get('requests') or []:
        cid = req.get('chain_id') or ''
        chain = chains.get(cid) or {}
        entry_path = (req.get('example_paths') or [chain.get('entry_path') or ''])[0]
        entry_ctx = resolve_entry_context(pack_dir, entry_path, api_id=req.get('entry_api'))
        surf = assess_capture_surface(pack_dir, req, chain, entry_ctx)
        surfaces.append(surf)

    ui_capture = [s for s in surfaces if s.get('user_capture_required')]
    static_only = [s for s in surfaces if s.get('capture_role') == 'static_only']
    return {
        'schema_version': '1.0.0',
        'generated_at': _utc_now(),
        'policy': (
            'Dual-track: user_capture = UI-grounded materials only; '
            'chain_test_targets = all chain entry APIs (incl. static-only) remain verification objects.'
        ),
        'surface_count': len(surfaces),
        'ui_capture_count': len(ui_capture),
        'static_only_count': len(static_only),
        'surfaces': surfaces,
        'ui_capture_request_ids': [s['request_id'] for s in ui_capture],
        'chain_test_entry_paths': list(dict.fromkeys(
            s['chain_entry_path'] for s in surfaces if s.get('chain_test_included')
        )),
    }


def write_capture_surface_plan(pack_dir: Path, plan: Optional[Dict[str, Any]] = None) -> Path:
    doc = build_capture_surface_plan(pack_dir, material_plan=plan)
    out = Path(pack_dir) / 'capture_surface_plan.json'
    from minidrifter.core.utils import write_json
    write_json(out, doc)
    return out
