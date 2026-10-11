# -*- coding: utf-8 -*-
"""Generic UI capture operation guide — link chain material requests to mini-program actions."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from minidrifter.business_chain.chain_templates import chain_type_label
from minidrifter.materials.intake_param_hints import normalize_api_path

_CHAIN_TYPE_UI: Dict[str, str] = {
    'LIST_DETAIL': '进入列表页并等待列表数据加载完成（页面出现条目后通常会触发 list 接口）',
    'PROFILE_OBJECT': '进入个人中心或资料页，触发加载用户/会员信息的请求',
    'OBJECT_CAPABILITY': '在已有业务对象的前提下，进入使用能力/凭证的功能页',
    'CAPABILITY_CONSUME': '打开需要能力凭证的消费页面（勿完成支付/下单）',
    'BIND_UNBIND': '进入绑定/解绑相关页面并触发对应操作',
    'GENERAL': '按下方页面与操作说明，触发入口业务请求',
}


def _load_json(path: Path) -> Any:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding='utf-8'))


def _camel_to_words(name: str) -> str:
    parts = re.sub(r'([a-z])([A-Z])', r'\1 \2', name).replace('_', ' ').split()
    return ' '.join(parts) if parts else name


def _resolve_project_root(pack_dir: Path) -> Optional[Path]:
    prof = _load_json(pack_dir / 'project_profile.json') or {}
    root = prof.get('project_root')
    if root and Path(root).is_dir():
        return Path(root)
    parent = pack_dir.parent
    if (parent / 'app.json').exists():
        return parent
    return None


def _page_nav_title(pack_dir: Path, page_id: Optional[str]) -> Optional[str]:
    if not page_id:
        return None
    root = _resolve_project_root(pack_dir)
    if not root:
        return None
    json_path = root / f'{page_id}.json'
    if not json_path.exists():
        return None
    doc = _load_json(json_path) or {}
    title = (doc.get('navigationBarTitleText') or '').strip()
    return title or None


def _page_surface_meta(pack_dir: Path, page_id: Optional[str]) -> Dict[str, Any]:
    if not page_id:
        return {}
    surface = _load_json(pack_dir / 'page_surface.json') or {}
    for pg in surface.get('pages') or []:
        if pg.get('page_id') == page_id:
            return pg
    return {}


def _human_page_name(
    pack_dir: Path,
    page_id: Optional[str],
    *,
    page_label: Optional[str] = None,
) -> str:
    title = _page_nav_title(pack_dir, page_id)
    if title:
        return title
    if page_id:
        leaf = page_id.rsplit('/', 1)[-1]
        from_id = _camel_to_words(leaf)
        api_derived = bool(
            page_label and re.search(r'\.(jhtml|html|json)|相关页面|跳转页$', page_label)
        )
        if page_label and not api_derived:
            return page_label
        if from_id and from_id.lower() != leaf.lower():
            return from_id
        if leaf not in {'index', 'list'}:
            return from_id or leaf
    if page_label and page_label not in {'unknown', '对应业务页面'}:
        return page_label
    if not page_id:
        return '对应业务页面'
    leaf = page_id.rsplit('/', 1)[-1]
    if leaf in {'index', 'list'}:
        folder = page_id.rsplit('/', 2)[-2] if '/' in page_id else ''
        return f'{folder or "首页"}页' if folder else '首页'
    return _camel_to_words(leaf)


def _event_to_ui_action(event: Optional[str]) -> Optional[str]:
    if not event:
        return None
    ev = event.strip()
    for prefix in ('bindtap:', 'bind:tap:', 'tap:', 'catchtap:', 'catch:tap:'):
        if ev.lower().startswith(prefix):
            handler = ev[len(prefix):]
            return f'点击页面上的相关按钮/区域（事件 `{handler}`）'
    if ev.startswith('bind'):
        return f'在页面上执行交互操作（事件 `{ev}`）'
    return f'在页面上执行：`{ev}`'


def _api_filter_hint(entry_path: str) -> str:
    norm = normalize_api_path(entry_path)
    if 'listandmap' in norm.lower():
        tail = 'listAndMap'
        return (
            f'在抓包工具中筛选 Host 为业务域名、Path 含 `{tail}`（v1/v3 均可）'
            f' 或完整路径 `{norm}` 的请求'
        )
    tail = norm.rsplit('/', 1)[-1] if norm else entry_path
    return f'在抓包工具中筛选 Host 为业务域名、Path 含 `{tail}` 或完整路径 `{norm}` 的请求'


def _chain_type_hint(chain_type: Optional[str]) -> str:
    return _CHAIN_TYPE_UI.get(chain_type or '', _CHAIN_TYPE_UI['GENERAL'])


def _navigation_hint(pack_dir: Path, page_id: Optional[str]) -> List[str]:
    if not page_id:
        return ['从首页或业务入口进入目标页面（可使用分享链接、扫码、搜索店铺名等方式）']
    meta = _page_surface_meta(pack_dir, page_id)
    hints: List[str] = []
    if meta.get('is_tab_page'):
        hints.append('该页面为 Tab 页：打开小程序后点击底部对应 Tab 进入')
    sub = meta.get('subpackage')
    if sub:
        hints.append(f'该页面位于分包 `{sub}`：通常从首页/商城入口跳转进入（非 Tab 直开）')
    if page_id.startswith('pages/index/'):
        hints.append('该页面在主包：可从首页 `pages/index/index` 相关入口跳转')
    elif page_id.startswith('pages/shop/'):
        hints.append('该页面在店铺分包：从首页进入某店铺/分类/商品相关入口后到达')
    elif page_id.startswith('pages/user/'):
        hints.append('该页面在用户分包：从「我的」/个人中心类入口进入')
    if not hints:
        hints.append(f'导航到页面 `{page_id}`（通过首页业务入口、分享或扫码）')
    return hints


def build_ui_capture_guide(
    req: Dict[str, Any],
    chain: Dict[str, Any],
    entry_ctx: Dict[str, Any],
    pack_dir: Path,
    *,
    surface: Optional[Dict[str, Any]] = None,
    capture_anchor: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Structured UI operation guide for one chain material request."""
    pack_dir = Path(pack_dir)
    if capture_anchor:
        entry_path = (req.get('example_paths') or [chain.get('entry_path') or ''])[0]
        chain_entry_path = entry_path
        capture_path = capture_anchor.get('api') or entry_path
        capture_role = 'ui_proxy' if (capture_anchor.get('static_producer') or {}).get('api') != capture_path else 'ui_direct'
        page_id = capture_anchor.get('page') or entry_ctx.get('entry_page')
        nav_verified = [
            s.get('action') if isinstance(s, dict) else str(s)
            for s in (capture_anchor.get('navigation_steps') or [])
        ]
        from minidrifter.quality.runtime_reachability.llm_ui_guard import llm_eligible_for_steps
        surface = {
            'capture_role': capture_role,
            'ui_page': page_id,
            'navigation_steps': nav_verified,
            'navigation_verified': bool(nav_verified),
            'capture_accept_paths': [capture_path],
            'weak_evidence': bool(capture_anchor.get('weak_evidence')),
            'instruction_mode': capture_anchor.get('instruction_mode'),
            'llm_eligible': llm_eligible_for_steps({
                'usable_for_capture': capture_anchor.get('usable_for_capture', True),
                'evidence': capture_anchor.get('evidence'),
                'confidence': capture_anchor.get('confidence', 0.9),
                'ui_reachability': capture_anchor.get('ui_reachability'),
            }),
            'runtime_proxies': [{
                'proxy_path': capture_path,
                'ui_page': page_id,
                'reason': 'material_source_alias',
            }] if capture_role == 'ui_proxy' else [],
        }
    elif surface is None:
        from minidrifter.business_chain.ui_capture_surface import assess_capture_surface
        surface = assess_capture_surface(pack_dir, req, chain, entry_ctx)

    entry_path = (req.get('example_paths') or [chain.get('entry_path') or ''])[0]
    chain_entry_path = surface.get('chain_entry_path') or entry_path
    capture_path = (
        (surface.get('capture_paths') or surface.get('capture_accept_paths') or [entry_path])[0]
    )
    capture_role = surface.get('capture_role') or 'static_only'
    page_id = surface.get('ui_page') or (
        req.get('entry_page') or entry_ctx.get('entry_page') or chain.get('entry_page')
    )
    page_name = _human_page_name(
        pack_dir, page_id,
        page_label=req.get('page_label') or entry_ctx.get('page_label'),
    )
    event_action = _event_to_ui_action(
        req.get('entry_event') or entry_ctx.get('entry_event') or chain.get('entry_event')
    )
    chain_type = chain.get('chain_type') or (req.get('recommended_api_roles') or ['GENERAL'])[0]
    api_tail = capture_path.rsplit('/', 1)[-1] if capture_path else ''
    filter_tail = 'listAndMap' if 'listandmap' in capture_path.lower() else api_tail
    expected = req.get('expected_response_fields') or entry_ctx.get('expected_response_fields') or []
    priority = '必做' if req.get('minimum') else '推荐'
    one_line_task: Optional[str] = None

    ui_steps: List[str] = [
        f'确认抓包工具（Charles / Fiddler / mitmproxy）已配置手机代理，SSL 证书已信任',
        f'打开微信，进入目标小程序（本项目：{pack_dir.parent.name}）',
        '使用测试账号完成登录（若未登录，先走登录/授权流程）',
    ]

    if capture_role == 'static_only':
        ui_steps.append(
            '⚠️ **静态链入口**：该 API 在静态业务链中存在，但**未找到可靠 UI 调用证据**。'
            '请由熟悉业务的同学在真机上确认触发路径，或改用下方「运行时替代 API」抓包。'
        )
        ui_steps.append(f'链测试目标 API：`{chain_entry_path}`（验证阶段仍会测，不因 UI 不可达而跳过）')
        if surface.get('runtime_proxies'):
            proxy = surface['runtime_proxies'][0]
            ui_steps.append(
                f'推荐替代抓包：`{proxy.get("proxy_path")}`（页面 `{proxy.get("ui_page")}`，原因：{proxy.get("reason")}）'
            )
    elif capture_role == 'ui_proxy':
        proxy = (surface.get('runtime_proxies') or [{}])[0]
        ui_steps.append(
            f'链入口 API 为 `{chain_entry_path}`；真机 UI 实际触发 **`{capture_path}`**（{proxy.get("reason", "runtime proxy")}）'
        )
        one_line_task = (
            f'在真机上触发 `{capture_path}` 并抓取含 '
            + '、'.join(f'`{f}`' for f in expected[:4] or ['deptId'])
            + f' 的响应（不要抓 `{chain_entry_path}`）'
        )

    if surface.get('weak_evidence'):
        ui_steps.append(
            '⚠️ 弱证据兜底：页面路径来自材料计划推断，请以真机 UI 与抓包 Path 为准'
        )

    nav_verified = surface.get('navigation_steps') or []
    if nav_verified:
        ui_steps.extend([f'[导航] {s}' for s in nav_verified])
    else:
        ui_steps.extend(_navigation_hint(pack_dir, page_id))
    ui_steps.append(f'进入页面：**{page_name}**（`{page_id or "见静态推断"}`）')
    ui_steps.append(_chain_type_hint(chain_type))
    if event_action:
        ui_steps.append(event_action)
    else:
        ui_steps.append(f'在页面内执行「{entry_ctx.get("action_label") or "浏览/加载"}」操作，等待网络请求发出')
    ui_steps.append('保持页面停留 2–3 秒，确保 list/详情 请求已完成（响应已返回）')
    ui_steps.append(_api_filter_hint(capture_path))
    ui_steps.append(
        f'在抓包记录中找到 **{filter_tail or capture_path}** 请求，导出完整 **Request + Response**（含 headers）'
    )
    if expected:
        ui_steps.append(
            '确认 Response body 中出现字段：'
            + '、'.join(f'`{f}`' for f in expected[:6])
        )
    ui_steps.append(
        f'将导出文件保存为 `.http` 或 `.txt`，放入 `baseline/user_materials/` 目录'
    )

    return {
        'request_id': req.get('request_id'),
        'priority': priority,
        'page_id': page_id,
        'page_name': page_name,
        'entry_path': chain_entry_path,
        'capture_path': capture_path,
        'capture_role': capture_role,
        'one_line_task': one_line_task,
        'capture_surface': surface,
        'navigation_steps': nav_verified or None,
        'navigation_verified': bool(surface.get('navigation_verified')),
        'chain_type': chain_type,
        'chain_type_label': chain_type_label(chain_type),
        'ui_steps': ui_steps,
        'capture_filter': {
            'path_contains': filter_tail,
            'full_path': normalize_api_path(capture_path),
            'chain_entry_path': normalize_api_path(chain_entry_path),
            'accept_paths': surface.get('capture_accept_paths') or [capture_path],
        },
        'save_as': f"{req.get('request_id', 'capture')}_{filter_tail or 'entry'}.http",
        'llm_eligible': bool(surface.get('llm_eligible')),
        'instruction_mode': surface.get('instruction_mode'),
        'weak_evidence': bool(surface.get('weak_evidence')),
    }


def render_global_capture_preamble(
    pack_dir: Path,
    *,
    llm_login_steps: Optional[List[str]] = None,
) -> List[str]:
    """Phase 0 — login baseline (always required before chain entry captures)."""
    pack_dir = Path(pack_dir)
    has_baseline = (pack_dir / 'baseline_runtime_context.json').exists()
    lines = [
        '## 0. 登录态基线抓包（所有链入口的前置步骤）',
        '',
        '在采集下方链入口材料之前，请先完成本步骤。',
        '',
    ]
    if llm_login_steps:
        lines.append('**小程序内操作（LLM 细化）：**')
        lines.append('')
        for i, step in enumerate(llm_login_steps, 1):
            lines.append(f'{i}. {step}')
        lines.append('')
    else:
        lines.extend([
            '**小程序内操作：**',
            '1. 打开抓包工具并配置好手机代理',
            '2. 打开微信小程序并完成登录（微信授权 + 手机号/会员登录如有）',
            '3. 登录后随便浏览一个页面（如首页、个人中心），确保出现带 Token/cid 的业务请求',
            '4. 在抓包中任选一条 **已登录且返回 200** 的业务请求，导出完整 Request + Response',
            '5. 保存到 `baseline/user_materials/login_baseline.http`',
            '',
        ])
    lines.extend([
        '**抓包确认：** Response 或 Headers 中应能看到 session 相关字段（如 token、cid、uid 等）。',
        '',
    ])
    if has_baseline:
        lines.append('> ✅ 检测到 `baseline_runtime_context.json` 已存在，可跳过本步直接补链入口抓包。')
        lines.append('')
    else:
        lines.append('> ⏳ 当前尚未导入 baseline，请先完成本步再采集链入口材料。')
        lines.append('')
    lines.extend([
        '**导入命令：**',
        '```',
        f'python -m minidrifter.cli run-closed-loop -i "{pack_dir}" --skip-analyze '
        '-f baseline/user_materials/login_baseline.http',
        '```',
        '',
        '---',
        '',
    ])
    return lines


def render_ui_guide_markdown(guide: Dict[str, Any]) -> List[str]:
    """Render one request's UI guide as markdown lines."""
    lines: List[str] = []
    surface = guide.get('capture_surface') or {}
    role = guide.get('capture_role') or surface.get('capture_role')
    if role == 'static_only':
        lines.append('> ⚠️ **静态链入口**：无可靠 UI 证据；材料用于链测试，抓包步骤需人工确认或使用替代 API')
        lines.append('')
    elif role == 'ui_proxy':
        lines.append('> 🔀 **运行时替代**：链入口与真机请求路径不同，请按 `capture_path` 筛选抓包')
        lines.append('')
    if guide.get('llm_enriched'):
        lines.append('> 🤖 LLM 仅补充了证据缺口部分（页面名/导航），未改写 API 与抓包筛选')
        lines.append('')
    nav = guide.get('navigation_steps') or []
    if nav:
        lines.extend([
            '**从首页到目标页（点击路径）：**',
            '',
        ])
        for i, step in enumerate(nav, 1):
            lines.append(f'{i}. {step}')
        lines.append('')
    lines.extend([
        '**小程序内操作步骤：**',
        '',
    ])
    for i, step in enumerate(guide.get('ui_steps') or [], 1):
        lines.append(f'{i}. {step}')
    lines.extend([
        '',
        f'**建议文件名：** `{guide.get("save_as", "capture.http")}`',
        '',
        f'**抓包筛选：** Path 含 `{guide.get("capture_filter", {}).get("path_contains", "")}`',
        '',
    ])
    return lines
