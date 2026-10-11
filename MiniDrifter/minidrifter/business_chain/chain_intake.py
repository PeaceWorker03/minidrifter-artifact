# -*- coding: utf-8 -*-
"""Chain-first user material intake — load, render, validate against business chains."""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from minidrifter.business_chain.chain_hop_enrichment import (
    build_semantic_user_action,
    resolve_entry_context,
)
from minidrifter.business_chain.chain_ui_guide import (
    build_ui_capture_guide,
    render_ui_guide_markdown,
)
from minidrifter.business_chain.schema import BUSINESS_PURPOSE, SCHEMA_VERSION
from minidrifter.materials.intake_param_hints import load_intake_report, normalize_api_path

_PATH_SEGMENT_RE = re.compile(r'/(list|detail|device|order|invoice|member|pay|coupon|address)', re.I)


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _load_json(path: Path) -> Any:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding='utf-8'))


def load_chain_material_plan(pack_dir: Path) -> Dict[str, Any]:
    """Load chain_material_request_plan.json; refresh from business chains if missing."""
    pack_dir = Path(pack_dir)
    plan_path = pack_dir / 'chain_material_request_plan.json'
    if plan_path.exists():
        return _load_json(plan_path) or {}
    if (pack_dir / 'business_chains.json').exists():
        from minidrifter.business_chain.export import refresh_business_chains_for_pack
        refresh_business_chains_for_pack(pack_dir)
        if plan_path.exists():
            return _load_json(plan_path) or {}
    return {'schema_version': SCHEMA_VERSION, 'requests': [], 'request_count': 0}


def _chains_by_id(pack_dir: Path) -> Dict[str, Dict[str, Any]]:
    from minidrifter.business_chain.chain_run_context import load_chain_registry
    return load_chain_registry(pack_dir)


def _page_hint_for_path(pack_dir: Path, api_path: str) -> Optional[str]:
    """Resolve pages/foo/bar from api_call_sites source.file or page_surface keyword."""
    pack_dir = Path(pack_dir)
    norm = normalize_api_path(api_path)
    tail = norm.rsplit('/', 1)[-1] if norm else ''

    calls = _load_json(pack_dir / 'api_call_sites.json') or []
    if isinstance(calls, dict):
        calls = calls.get('api_call_sites') or calls.get('calls') or []
    for call in calls:
        url = normalize_api_path((call.get('resolved_url') or '').split('?', 1)[0])
        if tail and tail not in url:
            continue
        src = (call.get('source') or {})
        fpath = (src.get('file') or '').replace('\\', '/')
        if fpath.startswith('pages/'):
            page = fpath.rsplit('.', 1)[0]
            if page.endswith('/index'):
                return page
            return page
        m = re.search(r'(pages/[\w./-]+)', fpath)
        if m:
            return m.group(1).rstrip('/')

    surface = _load_json(pack_dir / 'page_surface.json') or {}
    pages = surface.get('pages') or []
    keywords: List[str] = []
    for seg in _PATH_SEGMENT_RE.findall(norm):
        keywords.append(seg.lower())
    if tail:
        keywords.append(tail.lower())
    for pg in pages:
        pid = (pg.get('page_id') or '').lower()
        if any(kw in pid for kw in keywords if len(kw) > 2):
            return pg.get('page_id')
    return None


def _chain_unlock_label(chain: Dict[str, Any]) -> str:
    hops = chain.get('hops') or []
    parts: List[str] = []
    for h in hops[:5]:
        path = h.get('path') or ''
        short = path.rsplit('/', 1)[-1] or path
        if short:
            parts.append(short)
    return ' → '.join(parts) if parts else (chain.get('entry_path') or 'entry')


def _guide_for_capture(
    cap: Dict[str, Any],
    guides: List[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    """Match a deduped capture_anchor to the best rule/LLM guide."""
    cap_api = normalize_api_path(cap.get('api') or '')
    static_prod = normalize_api_path((cap.get('static_producer') or {}).get('api') or '')
    for guide in guides:
        capture_path = normalize_api_path(guide.get('capture_path') or '')
        entry_path = normalize_api_path(guide.get('entry_path') or '')
        if capture_path and capture_path == cap_api:
            return guide
        if static_prod and entry_path == static_prod:
            return guide
    for guide in guides:
        accept = [
            normalize_api_path(p)
            for p in (guide.get('capture_filter') or {}).get('accept_paths') or []
        ]
        if cap_api in accept:
            return guide
    return guides[0] if guides else None


def _capture_filter_hint(cap: Dict[str, Any], guide: Optional[Dict[str, Any]]) -> str:
    capture_api = cap.get('api') or ''
    api_tail = capture_api.rsplit('/', 1)[-1] if capture_api else ''
    filt = (guide or {}).get('capture_filter') or {}
    path_contains = filt.get('path_contains') or api_tail
    if 'listandmap' in capture_api.lower():
        return 'Path 含 `listAndMap` 或 `listandmap`（v1/v3 均可，以真机为准）'
    return f'Path 含 `{path_contains}` 或完整路径 `{capture_api}`'


def _expected_fields_confirm_hint(expected: List[str]) -> str:
    fields = [str(f) for f in (expected or []) if f][:4]
    if fields:
        return '、'.join(f'`{f}`' for f in fields)
    return '业务对象字段（如列表/详情中的 id）'


def _render_capture_anchor_section(
    cap: Dict[str, Any],
    guide: Optional[Dict[str, Any]],
    pack_dir: Path,
    *,
    idx: int,
    compact: bool = False,
) -> List[str]:
    """Human-operable markdown for one UI Material capture task."""
    capture_api = cap.get('api') or ''
    page = cap.get('page') or ''
    static_prod = (cap.get('static_producer') or {}).get('api')
    consumer = (cap.get('consumer') or {}).get('api')
    alias = cap.get('runtime_alias') or {}
    unlocks = cap.get('unlocks_static_candidates') or []
    expected = cap.get('expected_fields') or []
    nav_steps = cap.get('navigation_steps') or []
    save_as = (guide or {}).get('save_as') or f"{cap.get('capture_id', 'capture')}.http"

    lines: List[str] = [
        f'### 3.{idx} `{cap.get("capture_id", "")}`',
        '',
    ]
    if guide and guide.get('one_line_task'):
        lines.append(f'**一句话任务：** {guide["one_line_task"]}')
    elif static_prod and static_prod != capture_api:
        fields = _expected_fields_confirm_hint(expected)
        lines.append(
            f'**一句话任务：** 在真机上触发 `{capture_api}`，导出含 {fields} 的完整 request/response。'
        )
    else:
        fields_hint = _expected_fields_confirm_hint(expected)
        lines.append(
            f'**一句话任务：** 在 `{page}` 触发 `{capture_api}` 并导出含 {fields_hint} 的完整 request/response。'
        )
    lines.append('')

    if cap.get('weak_evidence') or cap.get('evidence') == 'material_plan_fallback':
        lines.extend([
            '> ⚠️ **弱证据兜底**：页面路径来自材料计划推断，callsites 未完全验证。',
            '> 请按真机可见 UI 操作，**以抓包 Path 与 Response 字段为准**。',
            '',
        ])

    if static_prod and static_prod != capture_api:
        lines.extend([
            '**背景（给测试同学看）：**',
            f'- 链路静态入口是 `{static_prod}`，但小程序 UI **不会直接调用**它',
            f'- 真机实际发出的是 **`{capture_api}`**（或同类 `listAndMap` 请求）',
            f'- 你只需要抓后者；系统会用材料解锁 `{static_prod}` 做链式重放',
            '',
            '**不要抓这个：**',
            f'- ❌ 不要在抓包里专门筛选 `{static_prod}`',
            f'- ❌ 不要因为没有 `deptList` 请求就认为操作错了',
            '',
        ])
        if alias.get('from'):
            lines.append(
                f'> runtime alias：`{alias.get("from")}` ← `{alias.get("to")}` '
                f'（confidence {alias.get("confidence", 0)}）'
            )
            lines.append('')

    if guide and (guide.get('ui_steps') or guide.get('navigation_steps')):
        lines.extend(render_ui_guide_markdown(guide))
    elif nav_steps:
        lines.extend(['**从首页到目标页：**', ''])
        for i, step in enumerate(nav_steps, 1):
            action = step.get('action') if isinstance(step, dict) else str(step)
            lines.append(f'{i}. {action}')
        lines.append('')

    lines.extend(['**需要字段：**'])
    for f in expected:
        lines.append(f'- `{f}`')
    lines.append('- `token` / `Authorization` / headers（登录态）')
    lines.append('- list response body（完整响应体）')
    lines.extend([
        '',
        '**如何确认抓对了：**',
        f'- 请求 Path 匹配：{_capture_filter_hint(cap, guide)}',
        '- HTTP 状态码为 200',
        f'- Response body 是 JSON，且能看到字段：{_expected_fields_confirm_hint(expected)}',
        '',
    ])
    if unlocks:
        lines.extend(['**该材料将用于解锁以下静态候选链：**'])
        for u in unlocks:
            if u:
                lines.append(f'- `{u}`')
    if consumer:
        lines.append(f'- consumer：`{consumer}`')
    lines.extend([
        '',
        f'**抓包筛选：** {_capture_filter_hint(cap, guide)}',
        '',
        f'**保存为：** `baseline/user_materials/{save_as}`',
        '',
    ])
    if not compact:
        lines.extend([
            '---',
            '',
        ])
    return lines


def _fields_for_request(req: Dict[str, Any], chain: Dict[str, Any]) -> Dict[str, List[str]]:
    objects = list(req.get('target_fields') or chain.get('objects') or [])
    binding = list(req.get('binding_fields') or chain.get('binding_fields') or [])
    auth = ['token', 'Token', 'Authorization', 'header']
    for hop in chain.get('hops') or []:
        for f in hop.get('produces') or []:
            if f not in objects:
                objects.append(f)
    return {
        'business_objects': objects[:8],
        'binding_fields': binding[:6],
        'auth_materials': auth,
    }


def _intake_capture_paths(pack_dir: Path) -> Set[str]:
    report = load_intake_report(pack_dir) or {}
    paths: Set[str] = set()
    for cap in report.get('captures') or []:
        p = normalize_api_path(cap.get('path') or '')
        if p:
            paths.add(p)
    return paths


def _capture_already_imported(cap: Dict[str, Any], imported: Set[str]) -> bool:
    api = normalize_api_path(cap.get('api') or '')
    if api in imported:
        return True
    for hint in ('listandmap', 'login', 'getorderlist', 'citylist'):
        if hint in api and any(hint in p for p in imported):
            return True
    static = normalize_api_path((cap.get('static_producer') or {}).get('api') or '')
    return bool(static and static in imported)


def _normalize_save_as(save_as: str) -> str:
    """Return filename only for user_materials (strip duplicated prefix)."""
    s = (save_as or 'capture.http').replace('\\', '/').strip()
    for prefix in ('baseline/user_materials/', 'user_materials/'):
        if s.startswith(prefix):
            s = s[len(prefix):]
    return s or 'capture.http'


def _is_plane_recommendation(rec: Dict[str, Any]) -> bool:
    return bool(rec.get('api_plane') or rec.get('baseline_category'))


def _render_status_dashboard(
    pack_dir: Path,
    *,
    strategy: Optional[Dict[str, Any]],
    plan: Dict[str, Any],
    chains_count: int,
) -> List[str]:
    summary = (strategy or {}).get('summary') or {}
    ctx = _load_json(pack_dir / 'baseline_runtime_context.json') or {}
    intake = load_intake_report(pack_dir) or {}
    cov = _load_json(pack_dir / 'binding_coverage_report.json') or {}
    capture_n = intake.get('capture_count') or len(intake.get('captures') or [])
    field_n = summary.get('baseline_field_count') or ctx.get('field_count') or 0
    has_auth = bool(ctx.get('crypto_replay_ready'))
    satisfied_n = len(plan.get('satisfied_by_baseline') or [])
    pending_n = len(plan.get('requests') or [])
    must_n = sum(
        1 for r in ((strategy or {}).get('capture_recommendations') or [])
        if r.get('minimum') and not _is_plane_recommendation(r)
    )
    plane_gaps_n = len((strategy or {}).get('plane_capture_gaps') or [])
    lines = [
        '## 1. 当前状态',
        '',
        '| 项目 | 数值 |',
        '|---|---|',
        f'| 已导入抓包 | **{capture_n}** 条 |',
        f'| 对象池字段 | **{field_n}** 个 |',
        f'| 登录态 replay | {"✅ 就绪" if has_auth else "⏳ 待 login_baseline"} |',
        f'| 静态业务链 | **{summary.get("static_chain_count", chains_count)}** 条 |',
        f'| 对象池可跑链 | **{summary.get("pool_runnable_chains", "—")}** 条 |',
        f'| 已解锁入口 | **{satisfied_n}** 个 |',
        f'| 材料计划缺口 | **{pending_n}** 条 |',
        f'| 策略推荐待补 | **{must_n}** 条（P0） |',
    ]
    if plane_gaps_n:
        lines.append(f'| P4 平面可选扩展 | **{plane_gaps_n}** 条（§2.5） |')
    if cov.get('chains_attempted'):
        lines.append(
            f'| 上次 Campaign | 链 **{cov.get("chains_reached_m7", 0)}/{cov.get("chains_attempted", 0)}** M7；'
            f'高危 **{(cov.get("risk_coverage") or {}).get("covered_count", "—")}/'
            f'{(cov.get("risk_coverage") or {}).get("probe_eligible_total", "—")}** |'
        )
    plane_idx = _load_json(pack_dir / 'api_plane_index.json') or {}
    if plane_idx.get('api_count'):
        high_planes = sum(
            1 for p, s in (plane_idx.get('plane_summary') or {}).items()
            if float(s.get('sensitivity') or 0) >= 0.85 and int(s.get('detected_count') or 0) > 0
        )
        lines.append(f'| 敏感 API 平面（P4） | **{plane_idx.get("api_count")}** API / **{high_planes}** 高敏平面 |')
    lines.extend(['', ''])
    return lines


def _render_todo_checklist(
    pack_dir: Path,
    *,
    strategy: Optional[Dict[str, Any]],
    plan: Dict[str, Any],
    has_baseline: bool,
) -> List[str]:
    lines = ['## 2. 待办清单', '']
    recs = (strategy or {}).get('capture_recommendations') or []
    must = [r for r in recs if r.get('minimum') and not _is_plane_recommendation(r)]
    optional = [
        r for r in recs
        if not r.get('minimum') and r.get('plane') == 'A_must_capture' and not _is_plane_recommendation(r)
    ]
    requests = plan.get('requests') or []

    lines.append('### 2.1 登录基线')
    lines.append('')
    if has_baseline:
        lines.append('- [x] `login_baseline.http` — 已导入，可跳过')
    else:
        lines.extend([
            '- [ ] `login_baseline.http` — 登录后任选一条含 Token/cid 的业务请求',
            '  - 保存到 `baseline/user_materials/login_baseline.http`',
        ])
    lines.append('')

    if must or requests:
        lines.extend(['### 2.2 必抓（P0）', ''])
        todo_idx = 0
        seen_save: Set[str] = set()
        for req in requests:
            save = req.get('request_id') or 'capture.http'
            if save in seen_save:
                continue
            seen_save.add(save)
            todo_idx += 1
            paths = ', '.join(f'`{p}`' for p in (req.get('example_paths') or [])[:1]) or '—'
            fields = ', '.join(f'`{f}`' for f in (req.get('target_fields') or req.get('binding_fields') or [])[:4])
            lines.append(f'- [ ] **{todo_idx}.** {paths} → harvest {fields or "—"}')
        for rec in must:
            save = _normalize_save_as(rec.get('save_as') or 'capture.http')
            if save in seen_save:
                continue
            seen_save.add(save)
            todo_idx += 1
            paths = ', '.join(f'`{p}`' for p in (rec.get('example_paths') or [])[:1]) or rec.get('domain', '—')
            fields = ', '.join(f'`{f}`' for f in (rec.get('target_fields') or [])[:4])
            lines.append(
                f'- [ ] **{todo_idx}.** {rec.get("title") or rec.get("domain")} — '
                f'{paths} → harvest {fields}'
            )
            lines.append(f'  - 保存为 `baseline/user_materials/{save}`')
        lines.append('')
    else:
        lines.extend(['### 2.2 必抓（P0）', '', '- （无）当前 baseline 已满足必抓项，可直接跑 Campaign。', ''])

    if optional:
        lines.extend(['### 2.3 建议扩展（P1）', ''])
        for rec in optional[:6]:
            paths = ', '.join(f'`{p}`' for p in (rec.get('example_paths') or [])[:1]) or '—'
            fields = ', '.join(f'`{f}`' for f in (rec.get('target_fields') or [])[:3])
            lines.append(
                f'- [ ] **{rec.get("domain")}** {paths} → {fields} '
                f'（+{rec.get("unlocks_chains_estimate", 0)} 链）'
            )
        lines.append('')

    satisfied = plan.get('satisfied_by_baseline') or []
    imported = _intake_capture_paths(pack_dir)
    if satisfied or imported:
        lines.extend(['### 2.4 已有材料（勿重复抓）', ''])
        for row in satisfied[:8]:
            entry = row.get('static_entry') or row.get('entry_api') or '—'
            cap = row.get('matched_capture') or row.get('runtime_material_api') or '—'
            chains_n = len(row.get('unlocks_chains') or [])
            fields = ', '.join(row.get('binding_fields') or row.get('shared_fields') or []) or '—'
            lines.append(f'- [x] `{entry}` ← `{cap}` → **{chains_n}** 链；字段 `{fields}`')
        for p in sorted(imported):
            if any(p in (row.get('matched_capture') or '') for row in satisfied):
                continue
            if 'login' in p.lower():
                continue
            lines.append(f'- [x] `{p}` — 已导入')
        lines.append('')

    plane_gaps = (strategy or {}).get('plane_capture_gaps') or []
    baseline_sufficient: Set[str] = set()
    try:
        from minidrifter.verification.reporting.coverage_aware_intake_prompt import (
            baseline_sufficient_paths,
        )
        baseline_sufficient = baseline_sufficient_paths(pack_dir)
    except Exception:
        pass

    if plane_gaps:
        filtered_gaps = [
            g for g in plane_gaps
            if normalize_api_path(g.get('example_path') or '') not in baseline_sufficient
        ]
        if baseline_sufficient and len(filtered_gaps) < len(plane_gaps):
            lines.extend([
                '### 2.5 敏感 API 平面（P4，可选扩展）',
                '',
                '> **P1–P3 敏感读 API 已完成 baseline 对齐与 M0 replay**，见 §1.5；'
                '**请勿**重复抓取 personalCore / address/list / remain/money 的普通 baseline。',
                '> 链材料已够时可**不抓**；补 1 条/平面可扩大实名/钱包/个人资料等覆盖。',
                '',
            ])
        else:
            lines.extend([
                '### 2.5 敏感 API 平面（P4，可选扩展）',
                '',
                '> 链材料已够时可**不抓**；补 1 条/平面可扩大实名/钱包/个人资料等覆盖。',
                '',
            ])
        for gap in filtered_gaps[:5]:
            fields = ', '.join(f'`{f}`' for f in (gap.get('missing_harvest_fields') or [])[:4])
            path = gap.get('example_path') or '—'
            save = _normalize_save_as(gap.get('save_as') or 'plane.http')
            lines.append(
                f'- [ ] **{gap.get("title", gap.get("plane"))}**（{gap.get("baseline_category", "")}）'
                f' — `{path}` → {fields}'
            )
            lines.append(f'  - 保存为 `baseline/user_materials/{save}`')
        if not filtered_gaps:
            lines.append('- （无）当前敏感平面 baseline 已齐；P1–P3 见 §1.5，无需重复抓包。')
        lines.append('')

    return lines


def _render_capture_details(
    pack_dir: Path,
    *,
    ui_captures: List[Dict[str, Any]],
    guides: List[Dict[str, Any]],
    imported: Set[str],
    requests: List[Dict[str, Any]],
) -> List[str]:
    baseline_sufficient: Set[str] = set()
    try:
        from minidrifter.verification.reporting.coverage_aware_intake_prompt import (
            baseline_sufficient_paths,
        )
        baseline_sufficient = baseline_sufficient_paths(pack_dir)
    except Exception:
        pass
    pending_caps = [
        c for c in ui_captures
        if not _capture_already_imported(c, imported)
        and normalize_api_path(c.get('api') or '') not in baseline_sufficient
    ]
    if not pending_caps and not requests:
        return []
    lines = [
        '## 3. 抓包操作说明',
        '',
        '> 仅 **§2 待办** 中未勾选项需要下列步骤；已导入材料见 §2.4。',
        '',
    ]
    idx = 0
    for cap in pending_caps[:6]:
        idx += 1
        guide = _guide_for_capture(cap, guides)
        lines.extend(_render_capture_anchor_section(
            cap, guide, pack_dir, idx=idx, compact=True,
        ))
    return lines


def _render_run_commands(pack_dir: Path, *, has_baseline: bool) -> List[str]:
    lines = [
        '## 4. 导入与跑 Campaign',
        '',
        '**批量导入**（推荐，会合并 `baseline/user_materials/` 下全部 `.http`）：',
        '```',
        f'python -m minidrifter.cli run-closed-loop -i "{pack_dir}" '
        f'--skip-analyze --mode execute --i-know --campaign-source frontier '
        f'--max-chains 40 --max-http 600',
        '```',
        '',
        '**单文件追加：**',
        '```',
        f'python -m minidrifter.cli run-closed-loop -i "{pack_dir}" '
        f'--skip-analyze --resume-file baseline/user_materials/<文件名>.http',
        '```',
        '',
    ]
    if not has_baseline:
        lines.extend([
            '**首次请先导入登录基线：**',
            '```',
            f'python -m minidrifter.cli run-closed-loop -i "{pack_dir}" '
            f'--skip-analyze -f baseline/user_materials/login_baseline.http',
            '```',
            '',
        ])
    lines.append('> 报告：`binding_coverage_report.md` · `sensitive_binding_coverage_report.md` · `closed_loop_report.json`')
    lines.append('')
    return lines


def _render_appendix_static_candidates(static_candidates: List[Dict[str, Any]]) -> List[str]:
    static_only = [
        c for c in static_candidates
        if c.get('ui_reachability') in {
            'STATIC_ONLY_NEEDS_MATERIAL', 'STATIC_ONLY_REPLAYABLE', 'UNREACHABLE_UNKNOWN',
        }
    ][:12]
    if not static_only:
        return []
    lines = [
        '## 附录 A · 静态候选（B 面，勿抓包）',
        '',
        '> 系统用 §2 材料自动重放下列 API，**不需要**你逐条抓包。',
        '',
        '| # | API | 所需字段 |',
        '|---|---|---|',
    ]
    for j, cand in enumerate(static_only, 1):
        api = cand.get('api') or '—'
        req_fields = ', '.join(f'`{f}`' for f in (cand.get('required_fields') or [])[:3]) or '—'
        lines.append(f'| {j} | `{api}` | {req_fields} |')
    lines.extend(['', ''])
    return lines


def _render_appendix_plane_coverage(pack_dir: Path) -> List[str]:
    cov = _load_json(pack_dir / 'binding_coverage_report.json') or {}
    pc = cov.get('plane_coverage') or {}
    plane_idx = _load_json(pack_dir / 'api_plane_index.json') or {}
    summary = plane_idx.get('plane_summary') or {}
    if not pc and not summary:
        return []
    lines = [
        '## 附录 C · 敏感 API 平面覆盖（P4）',
        '',
        '| 平面 | 检出 | 材料化 | 已执行 | M0敏感读 | Live M0 | Baseline M0 | M7敏感读 | 变异测试 | Subject尝试 | Subject敏感成功 |',
        '|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|',
    ]
    rows = pc if pc else {
        pid: {
            'label': (summary.get(pid) or {}).get('label', pid),
            'detected': (summary.get(pid) or {}).get('detected_count', 0),
            'materialized': 0,
            'executed': 0,
            'sensitive_read_m0_success': 0,
            'sensitive_read_m7_success': 0,
            'sensitive_mutation_tested': 0,
            'subject_override_attempted': 0,
            'subject_override_sensitive_success': 0,
        }
        for pid in summary
    }
    for plane_id, row in sorted(rows.items(), key=lambda kv: -(kv[1].get('detected') or 0)):
        if int(row.get('detected') or 0) <= 0:
            continue
        lines.append(
            f"| {row.get('label', plane_id)} | {row.get('detected', 0)} | "
            f"{row.get('materialized', 0)} | {row.get('executed', 0)} | "
            f"{row.get('sensitive_read_m0_success', 0)} | "
            f"{row.get('live_sensitive_read_m0_success', 0)} | "
            f"{row.get('baseline_sensitive_read_m0_success', 0)} | "
            f"{row.get('sensitive_read_m7_success', 0)} | "
            f"{row.get('sensitive_mutation_tested', 0)} | "
            f"{row.get('subject_override_attempted', 0)} | "
            f"{row.get('subject_override_sensitive_success', 0)} |"
        )
    lines.extend([
        '',
        '> 链材料已就绪时可直接跑 §4 Campaign；§2.5 仅用于扩大敏感面覆盖。',
        '',
    ])
    return lines


def _render_appendix_reference(
    strategy: Optional[Dict[str, Any]],
    *,
    llm_meta: Dict[str, Any],
) -> List[str]:
    if not strategy:
        return []
    matrix = [m for m in (strategy.get('unlock_matrix') or []) if m.get('status') == 'missing']
    camp = [
        g for g in (strategy.get('campaign_feedback_gaps') or [])
        if g.get('source') == 'campaign_probe_m0_failed'
    ]
    if not matrix and not camp and llm_meta.get('llm_status') not in {'ok', 'skipped_ineligible'}:
        return []
    lines = ['## 附录 B · 参考', '']
    if matrix:
        lines.extend([
            '**缺字段影响**',
            '',
            '| 字段 | 域 | 阻断链 |',
            '|---|---|---|',
        ])
        for row in matrix[:8]:
            lines.append(
                f'| `{row.get("field")}` | {row.get("domain")} | {row.get("chains_blocked", 0)} |'
            )
        lines.append('')
    if camp:
        lines.extend(['**上次 Campaign M0 失败（已纳入策略优先级）**', ''])
        for g in camp[:6]:
            lines.append(f'- `{g.get("path", "—")}` → {g.get("m0_outcome", "m0_failed")}')
        lines.append('')
    if llm_meta.get('llm_status') == 'ok':
        lines.append(
            f'> LLM 补强：{llm_meta.get("enriched_count", 0)}/{llm_meta.get("eligible_count", 0)} 条'
            '（`chain_intake_llm_enrichment.json`）'
        )
        lines.append('')
    return lines


def render_chain_intake_prompt(pack_dir: Path, *, use_llm: bool = True) -> str:
    """Human-readable chain-first intake markdown — structured for operators."""
    pack_dir = Path(pack_dir)
    plan = load_chain_material_plan(pack_dir)
    chains_doc = _load_json(pack_dir / 'business_chains.json') or {}
    chains_count = chains_doc.get('chain_count') or len(chains_doc.get('chains') or [])
    chains = _chains_by_id(pack_dir)
    requests = plan.get('requests') or []
    satisfied = plan.get('satisfied_by_baseline') or []
    has_baseline = (pack_dir / 'baseline_runtime_context.json').exists()

    if not requests and not satisfied and not has_baseline:
        static_done = (pack_dir / 'summary.json').exists() or (
            pack_dir / 'workbench_run_report.json'
        ).exists()
        chains_refreshed = (pack_dir / 'business_chains.json').exists()
        lines = [
            '# MiniDrifter 抓包与验证指南',
            '',
            f'**验证目标**：{BUSINESS_PURPOSE}',
            '',
        ]
        if static_done and chains_refreshed:
            summary = _load_json(pack_dir / 'summary.json') or {}
            opt = summary.get('optimized_counts') or {}
            counts = summary.get('counts') or {}
            obf = (summary.get('project_profile') or {}).get('obfuscation') or {}
            biz_ops = opt.get('business_api_operations', counts.get('business_api_operations'))
            reached = counts.get('reached_api_cards')
            frozen = None
            cards_doc = _load_json(pack_dir / 'api_cards.json') or {}
            if isinstance(cards_doc, list):
                frozen = len(cards_doc)
            elif isinstance(cards_doc, dict):
                frozen = cards_doc.get('card_count') or len(cards_doc.get('cards') or [])
            lines.extend([
                '> 静态分析与业务链刷新**已完成**，但未生成链材料计划。',
                f'> - 业务链：**{chains_count}** 条',
                f'> - 可冻结 API card：{frozen if frozen is not None else "—"}',
                f'> - 业务 API operation：{biz_ops if biz_ops is not None else "—"}',
                f'> - 源码可达 card：{reached if reached is not None else "—"}',
            ])
            if obf.get('level') == 'high':
                lines.append(
                    f'> - 混淆度：**{obf.get("score", "—")}**（high），URL 多为变量拼接，'
                    '静态难以恢复具体 API path。'
                )
            lines.extend([
                '>',
                '> **下一步**：导入登录后任意成功业务请求的 Raw HTTP / HAR（见 `user_intake_checklist.json`），'
                '再重跑 workbench / binding campaign。阻塞工单见 `operator_request.md`。',
                '',
                '```powershell',
                'python -m minidrifter.cli workbench resume -i <OUTPUT> -f capture.har --import-after',
                'python -m minidrifter.cli workbench run -i <OUTPUT> -p <project> --skip-analyze --mode dry-run',
                '```',
                '',
            ])
        else:
            lines.extend([
                '> 尚未生成业务链材料计划。请先运行静态分析并执行 `refresh_business_chains_for_pack`。',
                '',
            ])
        return '\n'.join(lines)

    strategy: Optional[Dict[str, Any]] = None
    try:
        from minidrifter.business_chain.baseline_capture_strategy import (
            build_baseline_capture_strategy,
            write_baseline_capture_strategy,
        )
        strategy = build_baseline_capture_strategy(pack_dir)
        write_baseline_capture_strategy(pack_dir)
    except Exception:
        pass

    from minidrifter.quality.runtime_reachability.capture_anchor_planner import (
        build_dual_plane_plans,
    )
    dual_plan = _load_json(pack_dir / 'ui_capture_plan.json') or build_dual_plane_plans(pack_dir)
    ui_captures = (dual_plan.get('ui_capture_plan') or dual_plan).get('captures') or []
    if not ui_captures and isinstance(dual_plan.get('captures'), list):
        ui_captures = dual_plan['captures']
    static_plan = _load_json(pack_dir / 'static_candidate_test_plan.json') or dual_plan.get('static_candidate_test_plan') or {}
    static_candidates = static_plan.get('candidates') or []

    rule_guides: List[Dict[str, Any]] = []
    capture_by_api = {normalize_api_path(c['api']): c for c in ui_captures if c.get('api')}
    for req in requests[:8]:
        cid = req.get('chain_id') or ''
        chain = chains.get(cid) or {}
        entry_path = (req.get('example_paths') or [chain.get('entry_path') or ''])[0]
        entry_ctx = resolve_entry_context(pack_dir, entry_path, api_id=req.get('entry_api'))
        cap = capture_by_api.get(normalize_api_path(entry_path))
        if not cap:
            for c in ui_captures:
                unlocks = [normalize_api_path(u) for u in (c.get('unlocks_static_candidates') or [])]
                if normalize_api_path(entry_path) in unlocks:
                    cap = c
                    break
        rule_guides.append(build_ui_capture_guide(
            req, chain, entry_ctx, pack_dir, capture_anchor=cap,
        ))

    from minidrifter.business_chain.chain_ui_llm_enricher import (
        apply_cached_llm_enrichment,
        enrich_guides_with_llm,
    )
    guides, llm_meta = enrich_guides_with_llm(
        pack_dir, requests[:8], chains, rule_guides, use_llm=use_llm,
    )
    if not use_llm or llm_meta.get('llm_status') != 'ok':
        guides = apply_cached_llm_enrichment(guides, pack_dir)

    imported = _intake_capture_paths(pack_dir)
    lines = [
        '# MiniDrifter 抓包与验证指南',
        '',
        f'**验证目标**：{BUSINESS_PURPOSE}',
        '',
        '> **怎么读本文**：§1.5 = 敏感 API 验证状态与阻塞原因；§2 待办 = 你还要抓什么；§3 = 操作细节；§4 = 导入命令；附录 = 系统自动处理项。',
        '> **双平面**：**A 面**（本文 §2–3）= 真人抓包；**B 面**（附录 A）= 自动重放，勿逐 API 抓包。',
        '',
    ]
    lines.extend(_render_status_dashboard(
        pack_dir, strategy=strategy, plan=plan, chains_count=chains_count,
    ))
    try:
        from minidrifter.verification.reporting.coverage_aware_intake_prompt import (
            render_coverage_aware_intake_section,
            write_coverage_aware_intake_doc,
        )
        write_coverage_aware_intake_doc(pack_dir)
        lines.extend(render_coverage_aware_intake_section(pack_dir))
    except Exception:
        pass
    lines.extend(_render_todo_checklist(
        pack_dir, strategy=strategy, plan=plan, has_baseline=has_baseline,
    ))
    lines.extend(_render_capture_details(
        pack_dir,
        ui_captures=ui_captures,
        guides=guides,
        imported=imported,
        requests=requests,
    ))
    lines.extend(_render_run_commands(pack_dir, has_baseline=has_baseline))
    lines.extend(_render_appendix_static_candidates(static_candidates))
    lines.extend(_render_appendix_plane_coverage(pack_dir))
    lines.extend(_render_appendix_reference(strategy, llm_meta=llm_meta))
    return '\n'.join(lines)


def validate_uploaded_material_against_chain(
    pack_dir: Path,
    *,
    chain_id: Optional[str] = None,
    request_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Check whether user captures satisfy a chain material request."""
    pack_dir = Path(pack_dir)
    plan = load_chain_material_plan(pack_dir)
    chains = _chains_by_id(pack_dir)
    requests = plan.get('requests') or []

    if chain_id:
        chain_doc = chains.get(chain_id) or {}
        if chain_doc.get('chain_source') == 'runtime_object_flow':
            binding = list(chain_doc.get('binding_fields') or [])
            from minidrifter.materials.object_pool_writer import load_baseline_field_pool, pool_has
            pool = load_baseline_field_pool(pack_dir)
            missing = [f for f in binding if not pool_has(f, pool['field_names'], pool['fields'])]
            ctx = _load_json(pack_dir / 'baseline_runtime_context.json') or {}
            auth_ok = bool(ctx.get('crypto_replay_ready'))
            if not missing and auth_ok:
                return {
                    'schema_version': SCHEMA_VERSION,
                    'generated_at': _utc_now(),
                    'valid': True,
                    'chain_id': chain_id,
                    'reason': 'runtime_object_flow_pool_satisfied',
                    'auth_ok': True,
                    'missing_binding': [],
                    'missing_objects': [],
                }

    target_req: Optional[Dict[str, Any]] = None
    for req in requests:
        if request_id and req.get('request_id') == request_id:
            target_req = req
            break
        if chain_id and req.get('chain_id') == chain_id:
            target_req = req
            break
    if not target_req and requests:
        target_req = requests[0]

    if not target_req:
        chain = chains.get(chain_id) or {} if chain_id else {}
        binding = list(chain.get('binding_fields') or chain.get('objects') or [])
        ctx = _load_json(pack_dir / 'baseline_runtime_context.json') or {}
        agg = ((report := load_intake_report(pack_dir) or {}).get('decrypted_fields_aggregate') or {}).get('fields') or {}
        resolved = ctx.get('resolved_fields') or {}
        pool = set(agg.keys()) | {k for k, v in resolved.items() if isinstance(v, dict) and v.get('value')}
        auth_ok = bool(ctx.get('crypto_replay_ready')) and any(
            k.lower() in {'token', 'uid', 'cid'} for k in pool
        )
        missing_binding = [f for f in binding if f not in pool]
        satisfied_plan = plan.get('satisfied_by_baseline') or []
        if binding and not missing_binding and auth_ok:
            return {
                'schema_version': SCHEMA_VERSION,
                'generated_at': _utc_now(),
                'valid': True,
                'chain_id': chain_id,
                'reason': 'baseline_pool_satisfies_binding',
                'auth_ok': True,
                'missing_binding': [],
                'missing_objects': [],
                'found_fields': sorted(pool & set(binding))[:20],
                'satisfied_by_baseline_count': len(satisfied_plan),
            }
        return {
            'schema_version': SCHEMA_VERSION,
            'generated_at': _utc_now(),
            'valid': False,
            'reason': 'no_chain_material_request',
            'missing_fields': missing_binding,
            'auth_ok': auth_ok,
        }

    cid = target_req.get('chain_id')
    chain = chains.get(cid) or {}
    expected_paths = {
        normalize_api_path(p)
        for p in (target_req.get('example_paths') or [chain.get('entry_path') or ''])
        if p
    }
    surface_doc = _load_json(pack_dir / 'ui_capture_plan.json') or {}
    alias_doc = _load_json(pack_dir / 'runtime_alias_map.json') or {}
    for cap in surface_doc.get('captures') or []:
        if cap.get('capture_id') == target_req.get('request_id') or normalize_api_path(cap.get('api') or '') in expected_paths:
            expected_paths.add(normalize_api_path(cap.get('api') or ''))
            for u in cap.get('unlocks_static_candidates') or []:
                expected_paths.add(normalize_api_path(u))
    for alias in alias_doc.get('aliases') or []:
        if normalize_api_path(alias.get('static_api') or '') in expected_paths:
            expected_paths.add(normalize_api_path(alias.get('runtime_material_api') or ''))
    surface_legacy = _load_json(pack_dir / 'capture_surface_plan.json') or {}
    for surf in surface_legacy.get('surfaces') or []:
        if surf.get('request_id') == target_req.get('request_id'):
            for p in surf.get('capture_accept_paths') or []:
                expected_paths.add(normalize_api_path(p))
            break
    needed_objects: Set[str] = set(target_req.get('target_fields') or chain.get('objects') or [])
    needed_binding: Set[str] = set(target_req.get('binding_fields') or chain.get('binding_fields') or [])

    report = load_intake_report(pack_dir) or {}
    captures = report.get('captures') or []
    matched_capture = False
    found_fields: Set[str] = set()
    matched_path: Optional[str] = None

    for cap in captures:
        cap_path = normalize_api_path(cap.get('path') or '')
        if expected_paths and cap_path not in expected_paths:
            if not any(ep in cap_path or cap_path in ep for ep in expected_paths):
                continue
        matched_capture = True
        matched_path = cap.get('path')
        resp_proc = cap.get('response_crypto_processing') or {}
        for bag in (
            cap.get('response_fields') or [],
            sorted((resp_proc.get('produces_fields') or {}).keys()),
            cap.get('query_fields') or [],
            cap.get('header_fields') or [],
        ):
            for f in bag:
                found_fields.add(str(f))
        body = cap.get('response_body_preview') or cap.get('body_preview') or ''
        if isinstance(body, str):
            for f in needed_objects | needed_binding:
                if re.search(rf'["\']?{re.escape(f)}["\']?\s*[:=]', body, re.I):
                    found_fields.add(f)

    missing_objects = sorted(f for f in needed_objects if f and f not in found_fields)
    missing_binding = sorted(f for f in needed_binding if f and f not in found_fields)
    agg_count = (report.get('decrypted_fields_aggregate') or {}).get('field_count') or 0
    any_token_capture = any(
        (c.get('transport_assessment') or {}).get('token_present')
        for c in captures
    )
    auth_ok = any(
        f in found_fields
        for f in ('Token', 'token', 'Authorization', 'authorization', 'uid')
    ) or agg_count > 5 or any_token_capture or bool((report.get('baseline_field_count') or 0) > 5)

    valid = matched_capture and auth_ok and not missing_objects
    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': _utc_now(),
        'valid': valid,
        'chain_id': cid,
        'request_id': target_req.get('request_id'),
        'matched_capture': matched_capture,
        'matched_path': matched_path,
        'expected_paths': sorted(expected_paths),
        'found_fields': sorted(found_fields),
        'missing_objects': missing_objects,
        'missing_binding': missing_binding,
        'auth_ok': auth_ok,
        'unlocks_chain': _chain_unlock_label(chain),
        'reason': (
            'ok' if valid
            else 'missing_entry_capture' if not matched_capture
            else 'missing_auth' if not auth_ok
            else 'missing_business_objects'
        ),
    }


def build_chain_intake_checklist(pack_dir: Path, *, use_llm: bool = False) -> Dict[str, Any]:
    """Structured checklist derived from chain material plan (primary intake)."""
    pack_dir = Path(pack_dir)
    plan = load_chain_material_plan(pack_dir)
    chains = _chains_by_id(pack_dir)
    steps: List[Dict[str, Any]] = []
    rule_guides: List[Dict[str, Any]] = []

    for i, req in enumerate(plan.get('requests') or [], 1):
        cid = req.get('chain_id') or ''
        chain = chains.get(cid) or {}
        entry_path = (req.get('example_paths') or [chain.get('entry_path') or ''])[0]
        entry_ctx = resolve_entry_context(pack_dir, entry_path, api_id=req.get('entry_api'))
        rule_guides.append(build_ui_capture_guide(req, chain, entry_ctx, pack_dir))

    from minidrifter.business_chain.chain_ui_llm_enricher import (
        apply_cached_llm_enrichment,
        enrich_guides_with_llm,
    )
    if use_llm:
        guides, _ = enrich_guides_with_llm(
            pack_dir, plan.get('requests') or [], chains, rule_guides, use_llm=True,
        )
    else:
        guides = apply_cached_llm_enrichment(rule_guides, pack_dir)

    for i, (req, ui_guide) in enumerate(zip(plan.get('requests') or [], guides), 1):
        cid = req.get('chain_id') or ''
        chain = chains.get(cid) or {}
        entry_path = (req.get('example_paths') or [chain.get('entry_path') or ''])[0]
        entry_ctx = resolve_entry_context(pack_dir, entry_path, api_id=req.get('entry_api'))
        page = (
            req.get('entry_page')
            or req.get('page_label')
            or entry_ctx.get('entry_page')
            or entry_ctx.get('page_label')
        )
        fields = _fields_for_request(req, chain)
        steps.append({
            'step': i,
            'phase': 'required' if req.get('minimum') else 'recommended',
            'priority': req.get('priority') or 'medium',
            'request_type': 'chain_seed_capture',
            'material_id': req.get('request_id'),
            'chain_id': cid,
            'page_hint': page,
            'page_name_zh': ui_guide.get('page_name_zh') or ui_guide.get('page_name'),
            'entry_page': req.get('entry_page') or entry_ctx.get('entry_page'),
            'entry_event': req.get('entry_event') or entry_ctx.get('entry_event'),
            'entry_api': req.get('entry_api'),
            'entry_path': entry_path,
            'expected_response_fields': req.get('expected_response_fields') or entry_ctx.get('expected_response_fields') or [],
            'purpose': (
                ui_guide.get('one_line_task')
                or req.get('recommended_user_action')
                or build_semantic_user_action(chain, entry_ctx)
            ),
            'navigation_steps': ui_guide.get('navigation_steps') or [],
            'ui_operation_steps': ui_guide.get('ui_steps') or [],
            'llm_enriched': bool(ui_guide.get('llm_enriched')),
            'save_as': ui_guide.get('save_as'),
            'capture_filter': ui_guide.get('capture_filter'),
            'unlocks_chain': _chain_unlock_label(chain),
            'covers_fields': fields['business_objects'] + fields['binding_fields'],
            'binding_fields': fields['binding_fields'],
            'auth_materials': fields['auth_materials'],
            'paste_to': 'baseline/user_materials',
            'source': 'chain_material_request_plan',
        })

    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': _utc_now(),
        'pack_dir': str(pack_dir),
        'title': 'MiniDrifter 业务链材料清单（主）',
        'business_purpose': BUSINESS_PURPOSE,
        'primary_source': 'chain_material_request_plan.json',
        'legacy_fallback': 'material_requirements.json',
        'steps': steps,
    }
