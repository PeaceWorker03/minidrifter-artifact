# -*- coding: utf-8 -*-
"""Human-operable baseline capture requirements — project-specific from static pack."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from minidrifter.business_chain.chain_run_context import load_json
from minidrifter.core.utils import write_json
from minidrifter.materials.intake_param_hints import normalize_api_path
from minidrifter.orchestration.console.workspace_layout import (
    ensure_baseline_for_pack,
    rel_display,
)
from minidrifter.verification.subject_override_fields import infer_subject_fields_from_path

SCHEMA_VERSION = '1.1.0'

# Fallback only when static pack has zero recoverable APIs.
GENERIC_CHECKLIST_FALLBACK = [
    {
        'id': 'login',
        'title': '登录小程序',
        'purpose': '获取 Token / session / Authorization',
        'pages': '登录页、授权页',
        'paths_hint': 'login, openid, token, session',
        'example_apis': [],
        'hosts': [],
        'fields': ['Token', 'Authorization'],
        'source': 'generic_fallback',
    },
]

PLANE_UI_NAV: Dict[str, Tuple[str, str]] = {
    'credential_session': ('登录并建立会话', '登录页、微信授权、首次打开小程序'),
    'user_profile_personal_info': ('打开「我的 / 个人信息 / 实名」', '我的、个人中心、实名认证、账户资料'),
    'account_state_wallet': ('打开钱包 / 余额 / 积分 / 会员卡', '钱包、余额、积分、会员卡、财富页'),
    'contact_address_invoice': ('打开地址 / 发票 / 联系方式', '地址管理、发票抬头、联系信息'),
    'business_object': ('打开订单 / 账单 / 业务对象列表', '订单列表、账单记录、缴费记录、详情页'),
    'realname_verification': ('完成实名 / 身份核验流程', '实名认证、身份证、人脸识别'),
    'action_operation': ('触发核心业务操作（读接口优先）', '首页、搜索、缴费、办理、查询'),
    'environment_public': ('浏览公开/活动/配置页（可选）', '首页 banner、活动页、帮助页'),
}

PLANE_PURPOSE: Dict[str, str] = {
    'credential_session': '获取 Token、session、Authorization 及登录态字段',
    'user_profile_personal_info': '获取 userId / customerId 及个人信息读接口',
    'account_state_wallet': '获取余额、积分、会员卡、优惠券相关读接口',
    'contact_address_invoice': '获取 addressId、发票抬头及地址读接口',
    'business_object': '获取 orderId / billId 及订单、账单详情读接口',
    'realname_verification': '获取实名状态、证件相关读接口',
    'action_operation': '覆盖静态恢复的业务写/查接口（优先成功 200 响应）',
    'environment_public': '覆盖公开配置、活动类读接口（辅助 runtime 索引）',
}

PLANE_PAGE_KEYWORDS: Dict[str, Tuple[str, ...]] = {
    'credential_session': ('login', 'auth', 'oauth', 'signin', 'router'),
    'user_profile_personal_info': ('my', 'profile', 'user', 'member', 'who', 'personal'),
    'account_state_wallet': ('wallet', 'wealth', 'balance', 'card', 'coupon', 'point'),
    'contact_address_invoice': ('address', 'invoice', 'contact'),
    'business_object': ('order', 'bill', 'payment', 'pay', 'loan', 'record'),
    'realname_verification': ('realname', 'identity', 'credit', 'verify', 'takephoto'),
    'action_operation': ('index', 'search', 'cashier', 'tabbar', 'home'),
    'environment_public': ('campaign', 'activity', 'info', 'public'),
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _project_name(pack_dir: Path, layout) -> str:
    dash = load_json(pack_dir / 'project_dashboard.json') or {}
    name = dash.get('project_name')
    if name and name != 'OUTPUT':
        return str(name)
    if layout.workspace and pack_dir.parent == layout.workspace:
        return pack_dir.parent.name
    return pack_dir.parent.name if pack_dir.name == 'OUTPUT' else pack_dir.name


def _project_hosts(pack_dir: Path, *, limit: int = 4) -> List[str]:
    hosts: List[str] = []
    seen: set[str] = set()

    def _add(h: str) -> None:
        h = (h or '').strip().rstrip('/')
        if not h or h in seen:
            return
        if not h.startswith('http'):
            h = f'https://{h}'
        seen.add(h)
        hosts.append(h)

    hr = load_json(pack_dir / 'host_resolution.json') or {}
    for row in (hr.get('host_pools') or {}).get('business_explicit') or []:
        _add(row.get('host') or '')
    adapter = load_json(pack_dir / 'adapter_profile.json') or {}
    for h in adapter.get('host_hints') or []:
        _add(str(h))
    return hosts[:limit]


def _page_routes_for_plane(pack_dir: Path, plane: str, *, limit: int = 4) -> List[str]:
    surface = load_json(pack_dir / 'page_surface.json') or {}
    keywords = PLANE_PAGE_KEYWORDS.get(plane) or ()
    routes: List[str] = []
    for page in surface.get('pages') or []:
        pid = str(page.get('page_id') or page.get('route') or '')
        low = pid.lower()
        if any(k in low for k in keywords):
            routes.append(pid)
    return routes[:limit]


def _stage1_targets(pack_dir: Path) -> List[Dict[str, Any]]:
    plan = load_json(pack_dir / 'acquisition_plan.json') or {}
    rows = list(plan.get('stage_1_target_apis') or [])
    rows.sort(key=lambda r: -float(r.get('stage1_score') or r.get('replay_safe_rank') or 0))
    return rows


def _api_entries(pack_dir: Path) -> List[Dict[str, Any]]:
    idx = load_json(pack_dir / 'api_plane_index.json') or {}
    return list(idx.get('entries') or [])


def _material_required_paths(pack_dir: Path) -> List[str]:
    mr = load_json(pack_dir / 'material_requirements.json') or {}
    paths: List[str] = []
    for bucket in ('required', 'recommended'):
        for item in mr.get(bucket) or []:
            paths.extend(item.get('example_paths') or [])
    return list(dict.fromkeys(paths))


def _format_api_row(path: str, method: str = '', host: str = '') -> str:
    m = (method or 'GET').upper()
    if m == 'UNKNOWN':
        m = 'GET/POST'
    row = f'`{m} {path}`'
    if host:
        row += f' @ `{host}`'
    return row


def _group_entries_by_plane(entries: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for ent in entries:
        plane = ent.get('primary_plane') or 'action_operation'
        grouped.setdefault(plane, []).append(ent)
    for plane, rows in grouped.items():
        rows.sort(key=lambda r: -float(r.get('sensitivity_score') or 0))
    return grouped


def _paths_from_entries(entries: List[Dict[str, Any]], *, limit: int = 6) -> List[str]:
    out: List[str] = []
    for ent in entries:
        p = ent.get('path') or ''
        if p and p not in out:
            out.append(p)
    return out[:limit]


def _fields_from_entries(entries: List[Dict[str, Any]]) -> List[str]:
    fields: List[str] = []
    for ent in entries:
        for bag in (ent.get('subject_fields'), ent.get('sensitive_fields')):
            for f in bag or []:
                if f and f not in fields:
                    fields.append(str(f))
    return fields[:8]


def _build_auth_step(
    pack_dir: Path,
    *,
    hosts: List[str],
    stage1: List[Dict[str, Any]],
    entries: List[Dict[str, Any]],
) -> Dict[str, Any]:
    token_apis: List[Dict[str, Any]] = []
    for ent in entries:
        sens = {str(x).lower() for x in (ent.get('sensitive_fields') or [])}
        if 'token' in sens or 'authorization' in sens:
            token_apis.append(ent)
    for row in stage1:
        if row.get('stage1_user_fields'):
            token_apis.append({
                'path': row.get('path'),
                'method': row.get('method'),
                'sensitive_fields': row.get('stage1_user_fields'),
            })

    paths = _paths_from_entries(token_apis, limit=5)
    paths.extend(_material_required_paths(pack_dir))
    paths = list(dict.fromkeys(p for p in paths if p))[:6]

    mr = load_json(pack_dir / 'material_requirements.json') or {}
    req = (mr.get('required') or [{}])[0] if mr.get('required') else {}
    purpose = req.get('purpose') or PLANE_PURPOSE['credential_session']

    acq = load_json(pack_dir / 'acquisition_plan.json') or {}
    field_names: List[str] = []
    for mat in acq.get('stage_1_user_materials') or []:
        field_names.extend(mat.get('covers_fields') or [])
    field_names = list(dict.fromkeys(field_names))[:8]

    pages = '、'.join(_page_routes_for_plane(pack_dir, 'credential_session') or ['登录页、授权页'])
    return {
        'id': 'auth',
        'title': '登录并建立会话（必做）',
        'purpose': purpose,
        'pages': pages,
        'paths_hint': ', '.join(normalize_api_path(p) for p in paths[:4]) or 'login, token, MiniPro',
        'example_apis': [
            {'path': p, 'method': next((e.get('method') for e in entries if e.get('path') == p), 'POST')}
            for p in paths[:5]
        ],
        'hosts': hosts[:2],
        'fields': field_names or ['Token', 'Authorization'],
        'source': 'static_material_plan',
        'priority': 'required',
    }


def _build_plane_step(
    plane: str,
    entries: List[Dict[str, Any]],
    *,
    pack_dir: Path,
    hosts: List[str],
) -> Dict[str, Any]:
    title, default_pages = PLANE_UI_NAV.get(plane, (f'触发 {plane} 相关页面', '相关业务页面'))
    page_routes = _page_routes_for_plane(pack_dir, plane)
    pages = '、'.join(page_routes) if page_routes else default_pages
    paths = _paths_from_entries(entries)
    fields = _fields_from_entries(entries)
    if not fields:
        for p in paths:
            fields.extend(infer_subject_fields_from_path(p))
        fields = list(dict.fromkeys(fields))[:6]

    return {
        'id': plane,
        'title': title,
        'purpose': PLANE_PURPOSE.get(plane, f'覆盖 {plane} 平面静态恢复的 API'),
        'pages': pages,
        'paths_hint': ', '.join(normalize_api_path(p) for p in paths[:5]),
        'example_apis': [{'path': e.get('path'), 'method': e.get('method')} for e in entries[:6]],
        'hosts': hosts[:2],
        'fields': fields,
        'source': 'api_plane_index',
        'priority': 'high' if float(entries[0].get('sensitivity_score') or 0) >= 0.75 else 'normal',
    }


def build_project_operator_checklist(pack_dir: Path) -> List[Dict[str, Any]]:
    """Build capture steps from static pack — not a fixed generic checklist."""
    pack_dir = Path(pack_dir)
    entries = _api_entries(pack_dir)
    if not entries:
        return list(GENERIC_CHECKLIST_FALLBACK)

    hosts = _project_hosts(pack_dir)
    stage1 = _stage1_targets(pack_dir)
    grouped = _group_entries_by_plane(entries)

    checklist: List[Dict[str, Any]] = []
    checklist.append(_build_auth_step(pack_dir, hosts=hosts, stage1=stage1, entries=entries))

    plane_order = sorted(
        grouped.keys(),
        key=lambda pl: (
            0 if pl == 'action_operation' else 1,
            -max(float(e.get('sensitivity_score') or 0) for e in grouped[pl]),
        ),
    )
    for plane in plane_order:
        rows = grouped[plane]
        if plane == 'environment_public' and all(
            float(r.get('sensitivity_score') or 0) < 0.4 for r in rows
        ):
            # Keep one lightweight public step if it contains stage-1 targets.
            stage_paths = {normalize_api_path(r.get('path') or '') for r in stage1}
            if not any(normalize_api_path(r.get('path') or '') in stage_paths for r in rows):
                continue
        checklist.append(_build_plane_step(plane, rows, pack_dir=pack_dir, hosts=hosts))

    # Deduplicate near-duplicate steps by overlapping primary paths.
    seen_paths: set[str] = set()
    deduped: List[Dict[str, Any]] = []
    for step in checklist:
        paths = {normalize_api_path(a.get('path') or '') for a in (step.get('example_apis') or []) if a.get('path')}
        if paths and paths.issubset(seen_paths) and step.get('id') != 'auth':
            continue
        seen_paths |= paths
        deduped.append(step)
    return deduped[:10]


def _priority_gaps(pack_dir: Path, *, limit: int = 24) -> List[Dict[str, Any]]:
    gap_doc = load_json(pack_dir / 'subject_wire_gap_plan.json') or {}
    gaps = list(gap_doc.get('gaps') or [])
    gaps.sort(key=lambda g: -float(g.get('priority') or 0))
    return gaps[:limit]


def _static_priority_targets(pack_dir: Path, *, limit: int = 16) -> List[Dict[str, Any]]:
    """Fallback gap list from static index when gap plan / binding report not ready."""
    rows: List[Dict[str, Any]] = []
    for ent in _api_entries(pack_dir):
        path = ent.get('path') or ''
        if not path or path.endswith('.html'):
            continue
        role = ent.get('recommended_campaign_role') or ''
        sens = float(ent.get('sensitivity_score') or 0)
        if sens < 0.55 and role not in {
            'read_sensitive_state', 'verification_state_probe', 'account_state_probe',
        }:
            continue
        fields = list(ent.get('subject_fields') or []) + list(ent.get('sensitive_fields') or [])
        if not fields:
            fields = infer_subject_fields_from_path(path)
        rows.append({
            'path': path,
            'method': ent.get('method'),
            'plane': ent.get('primary_plane'),
            'role': role,
            'static_subject_fields': fields,
            'recommended_capture': f"{ent.get('primary_plane') or 'business'} / {role or 'runtime_index'}",
            'priority': sens,
            'source': 'api_plane_index',
        })
    for row in _stage1_targets(pack_dir):
        norm = normalize_api_path(row.get('path') or '')
        if any(normalize_api_path(r.get('path') or '') == norm for r in rows):
            continue
        rows.append({
            'path': row.get('path'),
            'method': row.get('method'),
            'plane': 'stage_1_target',
            'role': row.get('priority_tier'),
            'static_subject_fields': row.get('stage1_user_fields') or infer_subject_fields_from_path(row.get('path') or ''),
            'recommended_capture': 'acquisition_plan stage_1',
            'priority': float(row.get('stage1_score') or 0) / 100.0,
            'source': 'acquisition_plan',
        })
    rows.sort(key=lambda r: -float(r.get('priority') or 0))
    return rows[:limit]


def _no_capture_targets(pack_dir: Path, *, limit: int = 20) -> List[Dict[str, Any]]:
    fb = load_json(pack_dir / 'final_binding_report.json') or {}
    rows = []
    for rec in fb.get('records') or []:
        if rec.get('match_type') != 'no_capture':
            continue
        if not rec.get('subject_candidates') and not infer_subject_fields_from_path(rec.get('api') or ''):
            continue
        rows.append({
            'api': rec.get('api'),
            'rank': rec.get('rank'),
            'plane': rec.get('business_label'),
            'subject_candidates': rec.get('subject_candidates') or infer_subject_fields_from_path(rec.get('api') or ''),
        })
    if rows:
        rows.sort(key=lambda r: str(r.get('rank') or 'Z'))
        return rows[:limit]

    # Pre-campaign fallback: high-sensitivity static APIs not yet in intake.
    intake_paths = {
        normalize_api_path(c.get('path') or '')
        for c in (load_json(pack_dir / 'baseline_intake_report.json') or {}).get('captures') or []
    }
    fallback = []
    for ent in _api_entries(pack_dir):
        path = ent.get('path') or ''
        norm = normalize_api_path(path)
        if not path or norm in intake_paths:
            continue
        if float(ent.get('sensitivity_score') or 0) < 0.7:
            continue
        subj = list(ent.get('subject_fields') or []) or infer_subject_fields_from_path(path)
        if not subj and not ent.get('sensitive_fields'):
            continue
        fallback.append({
            'api': path,
            'rank': ent.get('risk_tier') or 'P2',
            'plane': ent.get('primary_plane'),
            'subject_candidates': subj or list(ent.get('sensitive_fields') or []),
        })
    fallback.sort(key=lambda r: str(r.get('rank') or 'Z'))
    return fallback[:limit]


def build_baseline_capture_requirements(pack_dir: Path) -> Dict[str, Any]:
    pack_dir = Path(pack_dir)
    layout = ensure_baseline_for_pack(pack_dir)
    gaps = _priority_gaps(pack_dir)
    static_targets = _static_priority_targets(pack_dir) if not gaps else []
    no_capture = _no_capture_targets(pack_dir)
    frontier = load_json(pack_dir / 'coverage_frontier.json') or {}
    intake = load_json(pack_dir / 'baseline_intake_report.json') or {}
    checklist = build_project_operator_checklist(pack_dir)

    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': _utc_now(),
        'pack_dir': str(pack_dir),
        'project_name': _project_name(pack_dir, layout),
        'baseline_dir': str(layout.baseline_dir),
        'baseline_dir_display': rel_display(layout.baseline_dir, base=layout.workspace),
        'project_hosts': _project_hosts(pack_dir),
        'static_api_count': len(_api_entries(pack_dir)),
        'checklist_source': 'project_static_pack' if _api_entries(pack_dir) else 'generic_fallback',
        'summary': {
            'current_capture_count': intake.get('capture_count') or 0,
            'gap_plan_count': len(gaps),
            'static_priority_count': len(static_targets),
            'no_capture_sensitive_targets': len(no_capture),
            'recommended_har': True,
        },
        'operator_checklist': checklist,
        'stage_1_target_apis': _stage1_targets(pack_dir)[:8],
        'priority_gaps': gaps,
        'static_priority_targets': static_targets,
        'no_capture_targets': no_capture,
        'frontier_hint': frontier.get('summary') or {},
    }


def render_baseline_capture_requirements_md(doc: Dict[str, Any]) -> str:
    baseline_rel = doc.get('baseline_dir_display') or '<项目>/baseline'
    har_path = f'{baseline_rel}/capture_full.har'
    project = doc.get('project_name') or '本项目'
    hosts = doc.get('project_hosts') or []
    lines = [
        '# Baseline 采集要求',
        '',
        f'**项目**：{project}',
        f"生成时间：{doc.get('generated_at')}",
        f"清单来源：`{doc.get('checklist_source') or 'project_static_pack'}`（静态恢复 **{doc.get('static_api_count', 0)}** 个 API）",
        '',
        '请使用**合法测试账号**完成以下操作，并导出**完整 HAR**（含 request + response + headers）。',
        '',
    ]
    if hosts:
        lines.extend([
            '## 本应用业务域名（抓包时确认 Host）',
            '',
            *[f'- `{h}`' for h in hosts[:4]],
            '',
        ])
    lines.extend([
        '## 存放位置',
        '',
        f'抓包请放入项目目录 **`{baseline_rel}/`**（已自动创建）。',
        '',
        '支持格式：',
        f'- **推荐** `{har_path}` — Charles/Burp/mitmproxy 完整导出',
        '- 或任意 `*.http` — Raw HTTP（请求 + 响应）',
        f'- 或 `{baseline_rel}/extra_captures.http` — 追加多条 Raw HTTP',
        '',
        '## 操作清单（按本应用静态分析生成）',
        '',
    ])
    for i, step in enumerate(doc.get('operator_checklist') or [], start=1):
        pri = step.get('priority')
        pri_tag = ' **[必做]**' if pri == 'required' else ''
        lines.extend([
            f"### {i}. {step.get('title')}{pri_tag}",
            f"- **目的**：{step.get('purpose')}",
            f"- **建议页面**：{step.get('pages')}",
        ])
        if step.get('hosts'):
            lines.append(f"- **域名**：{', '.join(f'`{h}`' for h in step['hosts'][:2])}")
        if step.get('fields'):
            lines.append(f"- **关注字段**：`{', '.join(step['fields'][:6])}`")
        apis = step.get('example_apis') or []
        if apis:
            lines.append('- **本应用 API 示例**：')
            for api in apis[:5]:
                path = api.get('path') or ''
                if path:
                    lines.append(f"  - {_format_api_row(path, str(api.get('method') or ''))}")
        else:
            lines.append(f"- **路径关键词**：`{step.get('paths_hint')}`")
        lines.append('')

    stage1 = doc.get('stage_1_target_apis') or []
    if stage1:
        lines.extend(['## Stage-1 优先目标 API（materialize 用）', ''])
        for row in stage1[:6]:
            fields = ', '.join(row.get('stage1_user_fields') or []) or '—'
            lines.append(
                f"- `{row.get('method', 'GET')} {row.get('path')}` — score={row.get('stage1_score')} — fields: `{fields}`"
            )
        lines.append('')

    lines.extend(['## 当前缺口（优先补抓）', ''])
    gaps = doc.get('priority_gaps') or []
    static_targets = doc.get('static_priority_targets') or []
    if gaps:
        for g in gaps[:12]:
            fields = ', '.join(g.get('static_subject_fields') or []) or '—'
            lines.append(f"- `{g.get('path')}` — subject: `{fields}` — {g.get('recommended_capture') or ''}")
    elif static_targets:
        lines.append('> 尚无 gap plan / 抓包；以下由 **api_plane_index + acquisition_plan** 推导：')
        lines.append('')
        for g in static_targets[:12]:
            fields = ', '.join(g.get('static_subject_fields') or []) or '—'
            lines.append(
                f"- `{g.get('method', 'GET')} {g.get('path')}` — subject: `{fields}` — {g.get('recommended_capture') or ''}"
            )
    else:
        lines.append('- 静态未恢复敏感 API，请至少完成登录 + 一条成功业务请求。')
    lines.extend(['', '## 战役层 no_capture 高价值 API', ''])
    no_cap = doc.get('no_capture_targets') or []
    if no_cap:
        for row in no_cap[:12]:
            subj = ', '.join(row.get('subject_candidates') or []) or '—'
            lines.append(f"- `{row.get('api')}` [{row.get('rank')}] — subject: `{subj}`")
    else:
        lines.append('- （导入 baseline 并运行 binding campaign 后会自动填充）')
    lines.extend([
        '',
        '## 导入命令',
        '',
        '抓包放入 baseline 后执行：',
        '',
        '```bash',
        'python -m minidrifter.cli workbench resume \\',
        f'  -i {doc.get("pack_dir")} \\',
        f'  -f {har_path} \\',
        '  --import-after \\',
        '  --bootstrap-after',
        '```',
        '',
        '若使用 `.http` 文件，将 `-f` 改为对应路径；也可在 baseline 目录放好后运行 `baseline-bootstrap -i <OUTPUT> --rescan`。',
        '',
    ])
    return '\n'.join(lines)


def write_baseline_capture_requirements(pack_dir: Path) -> Dict[str, Path]:
    pack_dir = Path(pack_dir)
    doc = build_baseline_capture_requirements(pack_dir)
    json_path = pack_dir / 'baseline_capture_requirements.json'
    md_path = pack_dir / 'baseline_capture_requirements.md'
    write_json(json_path, doc)
    md_path.write_text(render_baseline_capture_requirements_md(doc), encoding='utf-8')
    return {'json': json_path, 'md': md_path}
