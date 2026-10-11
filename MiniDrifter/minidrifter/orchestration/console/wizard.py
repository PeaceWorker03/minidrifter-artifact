# -*- coding: utf-8
"""Linear wizard — scan → select → static → baseline → verify → report → material loop."""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from minidrifter.core.utils import write_json
from minidrifter.orchestration.console.display import (
    artifact,
    panel,
    prompt_choice,
    prompt_path,
    status,
    table,
    write_finding_reports_md,
    load_json,
    ticket_card,
)
from minidrifter.orchestration.console.session import ConsoleSession
from minidrifter.orchestration.console.static_report import print_static_report
from minidrifter.orchestration.console.workspace_layout import (
    ProjectLayout,
    ensure_project_layout,
    ensure_workspace_root,
    list_baseline_capture_files,
    project_layout,
    rel_display,
    sync_baseline_to_pack,
)
from minidrifter.orchestration.console.baseline_batch import (
    import_all_baseline_captures,
    print_baseline_gap_guide,
    sync_supplement_needed_doc,
    write_baseline_slot_files,
)
from minidrifter.orchestration.workbench_run import _ensure_baseline_graph
from minidrifter.orchestration.intake_prompts import write_user_input_artifacts
from minidrifter.orchestration.project_dashboard import write_project_dashboard
from minidrifter.orchestration.workbench import run_workbench_intake_prompt
from minidrifter.orchestration.workspace_scanner import scan_workspace, write_workspace_manifest
from minidrifter.workspace.decompile_gate import (
    READY_DECOMPILED,
    classify_project_state,
)

TOTAL_STEPS = 7

STATE_LABELS = {
    'READY_DECOMPILED': ('OK', '可分析'),
    'NEED_DECOMPILE': ('BLOCK', '需反编译'),
    'BROKEN_DECOMPILE': ('BLOCK', '结构不完整'),
    'UNSUPPORTED_SHAPE': ('BLOCK', '非微信/未知'),
    'ENCRYPTED_OR_PROTECTED': ('BLOCK', '加密/保护'),
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _step(n: int, title: str, detail: str = '', *, level: str = 'RUN') -> None:
    print()
    print(status(f'步骤 {n}/{TOTAL_STEPS} · {title}', level))
    if detail:
        for line in detail.split('\n'):
            print(f'       {line}')


def _audit_workspace(ws: Path) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    doc = scan_workspace(ws)
    audited: List[Dict[str, Any]] = []
    for p in doc.get('projects') or []:
        root = Path(p['project_root'])
        gate = classify_project_state(root)
        audited.append({**p, **gate, 'audit_state': gate.get('state')})
    doc['projects'] = audited
    doc['ready_count'] = sum(1 for p in audited if p.get('audit_state') == READY_DECOMPILED)
    write_workspace_manifest(ws, doc)
    write_json(ws / 'workspace_audit.json', {
        'generated_at': _utc_now(),
        'workspace': rel_display(ws, base=ws),
        'projects': audited,
    })
    return doc, audited


def _show_homepage(ws: Path, audited: List[Dict[str, Any]]) -> None:
    rows = []
    ready_idx: List[int] = []
    for i, p in enumerate(audited):
        pid = p.get('project_id', '?')
        st = p.get('audit_state', '?')
        _, label = STATE_LABELS.get(st, ('??', st))
        rel_src = rel_display(p.get('project_root', ''), base=ws)
        has_out = (ws / pid / 'OUTPUT' / 'api_card_pack_manifest.json').exists()
        has_bl = bool(list_baseline_capture_files(project_layout(ws, pid)))
        rows.append((
            i + 1,
            pid,
            label,
            'Y' if has_out else '-',
            'Y' if has_bl else '-',
            rel_src,
        ))
        if st == READY_DECOMPILED:
            ready_idx.append(i + 1)
    panel('Workspace 小程序列表', [
        f'工作区: {rel_display(ws, base=ws.parent)}',
        f'共 {len(audited)} 个项目，{len(ready_idx)} 个可测试',
        '列: 静态=已有 OUTPUT 分析；Baseline=baseline/ 下已有抓包',
    ])
    table(['#', '项目', '审计', '静态', 'Baseline', '源码路径'], rows, col_widths=[4, 14, 10, 6, 8, 28])
    if not ready_idx:
        print(status('没有通过审计的项目。请将 wedecode 解包目录放入 Workspace/ 后重试。', 'BLOCK'))
    else:
        print(status(f'可测试项目编号: {ready_idx}', 'OK'))


def _pick_project(ws: Path, audited: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    ready = [p for p in audited if p.get('audit_state') == READY_DECOMPILED]
    if not ready:
        return None
    if len(ready) == 1:
        print(status(f'仅 1 个可测项目，自动选择: {ready[0].get("project_id")}', 'OK'))
        return ready[0]
    pick = prompt_choice('输入要测试的项目编号 (0=退出)')
    if pick == '0' or not pick.isdigit():
        return None
    idx = int(pick) - 1
    if 0 <= idx < len(audited):
        p = audited[idx]
        if p.get('audit_state') == READY_DECOMPILED:
            return p
        print(status(f'项目 {p.get("project_id")} 未通过审计: {p.get("message")}', 'BLOCK'))
    else:
        print(status('编号无效', 'BLOCK'))
    return None


def _show_baseline_requirements(layout: ProjectLayout, pack_dir: Path) -> None:
    md_path = pack_dir / 'user_input_prompt.md'
    lines: List[str] = [
        f'Baseline 目录: {rel_display(layout.baseline_dir, base=layout.workspace)}',
        '请保存以下 Raw HTTP 抓包（Charles/Burp/mitmproxy 导出）:',
        '',
        '【必填 1】登录后成功业务请求 — 含 Token、AppVersion、Authorization',
        '【必填 2】用户信息/个人中心 — 响应含 UserId',
        '【推荐】设备列表、订单列表、发票等业务接口',
        '',
        f'保存到: {rel_display(layout.baseline_dir, base=layout.workspace)}/',
        '  推荐: 每个 .http 一条请求+响应（1.http、2.http …）',
        '  或: extra_captures.http 内粘贴多条；工具会自动拆分',
    ]
    if md_path.exists():
        for line in md_path.read_text(encoding='utf-8').splitlines():
            if line.startswith('## 暂不需要'):
                break
            if line.strip().startswith('- material_id') or line.startswith('##'):
                lines.append(line)
    panel('Baseline 材料说明 — 需要保存哪些接口请求', lines[:45])
    artifact(layout.baseline_dir / 'README.txt', 'baseline 目录说明')
    if md_path.exists():
        artifact(md_path)


def _resolve_capture_text(raw: str, layout: ProjectLayout) -> str:
    text = raw.strip()
    if not text:
        return ''
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if len(lines) == 1:
        candidate = Path(lines[0].strip().strip('"').strip("'"))
        if not candidate.is_absolute() and not candidate.exists():
            candidate = layout.workspace / candidate
        if candidate.exists() and candidate.is_file():
            print(status(f'读取抓包: {rel_display(candidate, base=layout.workspace)}', 'OK'))
            return candidate.read_text(encoding='utf-8', errors='replace')
    return raw


def _save_pasted_capture(raw: str, layout: ProjectLayout) -> Path:
    layout.baseline_materials_dir.mkdir(parents=True, exist_ok=True)
    out = layout.baseline_materials_dir / f'pasted_{_utc_now()[:19].replace(":", "")}.http'
    out.write_text(raw, encoding='utf-8')
    artifact(out, '已保存到 baseline/user_materials')
    return out


def _read_capture_inbox(layout: ProjectLayout) -> str:
    baseline_files = list_baseline_capture_files(layout)

    panel('传入 Baseline 抓包', [
        f'项目 baseline: {rel_display(layout.baseline_dir, base=layout.workspace)}',
        '方式 A: 输入 .http / .har 文件路径（相对 Workspace 或绝对路径）',
        '方式 B: 文件已在 baseline/ → 直接 Enter 自动扫描全部 .http/.har 并导入',
        '方式 C: 编辑 extra_captures.http 追加材料后 Enter 自动导入',
        '方式 D: 粘贴 Raw HTTP → 追加到 extra_captures.http（完成后输入 END）',
    ])

    if baseline_files:
        print(status(f'baseline/ 已有 {len(baseline_files)} 个抓包文件', 'INFO'))
        for i, f in enumerate(baseline_files[:8]):
            print(f'       [{i+1}] {rel_display(f, base=layout.workspace)}')

    first = prompt_path('文件路径 (Enter=自动导入 baseline/ 全部 .http/.har)', '')
    if first:
        p = Path(first)
        if not p.is_absolute():
            p = layout.workspace / p
        if p.exists():
            return p.read_text(encoding='utf-8', errors='replace')
        print(status('文件不存在', 'BLOCK'))
        return ''

    if baseline_files:
        return '__AUTO_BATCH__'

    print(status('baseline/ 为空 — 请将抓包放入项目 baseline/ 目录，或粘贴 Raw HTTP（完成后输入 END）', 'INFO'))
    lines: List[str] = []
    try:
        while True:
            line = input()
            if line.strip().upper() == 'END':
                break
            lines.append(line)
    except (EOFError, KeyboardInterrupt):
        pass
    raw = _resolve_capture_text('\n'.join(lines), layout)
    if raw.strip():
        extra = layout.baseline_dir / 'extra_captures.http'
        extra.parent.mkdir(parents=True, exist_ok=True)
        prev = extra.read_text(encoding='utf-8', errors='replace') if extra.exists() else ''
        sep = '\n\n' if prev.strip() and not prev.endswith('\n\n') else ''
        extra.write_text(prev + sep + raw.strip() + '\n', encoding='utf-8')
        artifact(extra, '已追加到 extra_captures.http')
    return raw if raw.strip() else ''


def _baseline_ready(pack_dir: Path) -> Tuple[bool, Dict[str, Any]]:
    from minidrifter.orchestration.project_readiness import baseline_replay_ready
    ctx = load_json(pack_dir / 'baseline_runtime_context.json') or {}
    ok = baseline_replay_ready(ctx)
    return ok, ctx


def _import_baseline_batch(layout: ProjectLayout, pack_dir: Path, *, source_dir: Path) -> bool:
    ok, summary = import_all_baseline_captures(
        layout, pack_dir, source_dir=source_dir, materialize=True,
    )
    level = 'OK' if ok else 'BLOCK'
    print(status(
        f'解析 {summary.get("capture_count")} 条请求 | '
        f'可用 {summary.get("acceptable")} | fields={summary.get("field_count")} | '
        f'crypto={summary.get("crypto_replay_ready")} | N1={summary.get("n1_gate")}',
        level,
    ))
    if not ok:
        print_baseline_gap_guide(layout, pack_dir, summary)
    else:
        artifact(pack_dir / 'baseline_runtime_context.json')
    return ok


def _import_capture(
    layout: ProjectLayout,
    pack_dir: Path,
    raw: str,
    *,
    source_dir: Path,
) -> bool:
    if raw == '__AUTO_BATCH__':
        return _import_baseline_batch(layout, pack_dir, source_dir=source_dir)
    if raw.strip():
        extra = layout.baseline_dir / 'extra_captures.http'
        extra.parent.mkdir(parents=True, exist_ok=True)
        prev = extra.read_text(encoding='utf-8', errors='replace') if extra.exists() else ''
        if raw.strip() not in prev:
            sep = '\n\n' if prev.strip() else ''
            extra.write_text(prev + sep + raw.strip() + '\n', encoding='utf-8')
    return _import_baseline_batch(layout, pack_dir, source_dir=source_dir)


def _show_material_gaps(pack_dir: Path, layout: ProjectLayout) -> bool:
    """Print missing materials / tickets; return True if user should add baseline and retry."""
    tickets_doc = load_json(pack_dir / 'blocking_tickets.json') or {}
    tickets = tickets_doc.get('tickets') or []
    global_block = [t for t in tickets if t.get('severity') == 'blocking']
    materials = load_json(pack_dir / 'material_requests.json') or {}
    requests = materials.get('requests') or materials.get('material_requests') or []
    checklist = load_json(pack_dir / 'user_intake_checklist.json') or {}
    steps = checklist.get('steps') or []

    if not global_block and not requests and not steps:
        return False

    lines = [
        '测试过程中缺少运行态材料 — 详见 baseline/supplement_needed.md',
        f'补充目录: {rel_display(layout.additions_dir, base=layout.workspace)}/',
        f'或追加: {rel_display(layout.baseline_dir / "extra_captures.http", base=layout.workspace)}',
    ]
    fields: set[str] = set()
    for t in global_block[:3]:
        ticket_card(t)
        for ex in t.get('example_paths') or []:
            lines.append(f'  - 示例接口: {ex}')
    for r in requests[:5]:
        for f in r.get('missing_fields') or r.get('fields') or []:
            fields.add(str(f))
    for s in steps[:5]:
        if s.get('status') != 'satisfied':
            lines.append(f'  - {s.get("target_field") or s.get("purpose")}: {s.get("cli_command", "")[:80]}')
    if fields:
        lines.append('缺少字段: ' + ', '.join(sorted(fields)[:12]))
    sync_supplement_needed_doc(layout, pack_dir)
    panel('需要补充 Baseline', lines)
    artifact(layout.baseline_dir / 'supplement_needed.md')
    artifact(pack_dir / 'user_intake_checklist.json')
    artifact(pack_dir / 'material_requests.json')
    return True


def _run_full_verify(session: ConsoleSession, layout: ProjectLayout) -> Dict[str, Any]:
    from minidrifter.orchestration.workbench_run import run_workbench_pipeline

    pack_dir = layout.output_dir
    print(status('开始全量测试（静态已就绪 → Live 深链验证）', 'RUN'))
    print(status('测试日志将实时输出到本终端（同时写入 OUTPUT/search_progress.log）', 'INFO'))
    sys.stdout.flush()

    return run_workbench_pipeline(
        pack_dir=pack_dir,
        project_root=layout.source_dir,
        source_dir=layout.source_dir,
        skip_analyze=True,
        skip_verify=False,
        with_llm=session.get('with_llm', True),
        deep_think=session.get('deep_think', True),
        mode='execute',
        max_http=session.get('max_http', 250),
        max_llm=session.get('max_llm', 80),
        max_depth=session.get('max_depth', 5),
        beam_width=session.get('beam_width', 8),
        anchor_api_id=session.get('anchor_api') or None,
        i_know=True,
        resume=True,
        force_resume=True,
    )


def run_wizard(
    session: ConsoleSession,
    *,
    workspace: Optional[Path] = None,
    skip_verify: bool = False,
) -> int:
    ws = ensure_workspace_root(Path(workspace or session.get('workspace') or 'Workspace'))
    session.set('workspace', str(ws))

    # ── Step 1: Scan ──
    _step(1, '扫描 Workspace', rel_display(ws, base=ws.parent))
    doc, audited = _audit_workspace(ws)
    print(status(f'发现 {doc.get("project_count")} 个小程序目录', 'INFO'))

    # ── Step 2: Select ──
    _step(2, '选择小程序项目')
    _show_homepage(ws, audited)
    picked = _pick_project(ws, audited)
    if not picked:
        return 1

    project_id = picked.get('project_id') or Path(picked['project_root']).name
    layout = project_layout(ws, project_id)
    ensure_project_layout(layout)
    pack_dir = layout.output_dir

    session.set('project_root', str(layout.source_dir))
    session.set('pack_dir', str(pack_dir))
    session.set('source_dir', str(layout.source_dir))
    session.set('baseline_dir', str(layout.baseline_dir))
    session.relocate_session_to_pack()

    panel('已选项目', [
        f'项目: {project_id}',
        f'源码: {rel_display(layout.source_dir, base=ws)}',
        f'Baseline: {rel_display(layout.baseline_dir, base=ws)}',
        f'输出 OUTPUT: {rel_display(pack_dir, base=ws)}',
    ])

    # ── Step 3: Static ──
    _step(3, '静态分析 (API Cards / Crypto / IR / Graph)')
    from minidrifter.orchestration.console import actions
    try:
        if not (pack_dir / 'api_card_pack_manifest.json').exists():
            actions.action_static_analyze(session)
        else:
            print(status('OUTPUT 已有静态 pack，跳过 analyze', 'OK'))
        actions.action_verify_prepare(session)
        _ensure_baseline_graph(pack_dir)
        print_static_report(pack_dir)
    except Exception as exc:
        print(status(f'静态分析失败: {exc}', 'BLOCK'))
        return 1

    # ── Step 4: Baseline guide ──
    _step(4, 'Baseline 材料说明')
    run_workbench_intake_prompt(pack_dir)
    write_user_input_artifacts(pack_dir)
    _show_baseline_requirements(layout, pack_dir)
    for slot in write_baseline_slot_files(layout, pack_dir):
        artifact(slot, '材料槽位 / 扩展文件')

    # ── Step 5: Baseline intake ──
    _step(5, 'Baseline 抓包导入')
    has_bl, ctx = _baseline_ready(pack_dir)
    files = list_baseline_capture_files(layout)

    if files:
        if has_bl:
            print(status(
                f'OUTPUT 已有 baseline (fields={ctx.get("field_count")})；'
                f'baseline/ 有 {len(files)} 个抓包文件',
                'INFO',
            ))
            if prompt_choice('重新扫描 baseline/ 全部 .http 并导入? (1=是 Enter=复用已有)') != '1':
                print(status('跳过导入，复用 OUTPUT 内 baseline', 'OK'))
            elif not _import_capture(layout, pack_dir, '__AUTO_BATCH__', source_dir=layout.source_dir):
                return 1
        else:
            print(status(f'自动扫描 {len(files)} 个 .http 并分析全部有效请求…', 'RUN'))
            if not _import_capture(layout, pack_dir, '__AUTO_BATCH__', source_dir=layout.source_dir):
                if prompt_choice('导入未完全通过。已补充材料? (1=再试 Enter=退出)') == '1':
                    if not _import_capture(layout, pack_dir, '__AUTO_BATCH__', source_dir=layout.source_dir):
                        return 1
                else:
                    return 1
    elif has_bl:
        print(status(
            f'复用已有 baseline (fields={ctx.get("field_count")} crypto={ctx.get("crypto_replay_ready")})',
            'OK',
        ))
    else:
        raw = _read_capture_inbox(layout)
        if raw == '__AUTO_BATCH__':
            if not _import_capture(layout, pack_dir, raw, source_dir=layout.source_dir):
                return 1
        elif not raw.strip():
            print(status('未提供抓包，无法继续 Live 验证', 'BLOCK'))
            print(status(f'请将 .http 放入 {rel_display(layout.baseline_dir, base=ws)} 后重新运行', 'INFO'))
            return 1
        elif not _import_capture(layout, pack_dir, raw, source_dir=layout.source_dir):
            return 1

    if skip_verify:
        _step(7, '完成 (跳过 Live 验证)', level='OK')
        write_project_dashboard(pack_dir, project_name=project_id)
        return 0

    # ── Step 6: Full verify ──
    _step(6, '全量动态验证', 'Live HTTP + 链式规划 + Hop 裁决 + Finding 升级\n日志实时打印如下')
    session.set('i_know_acknowledged', True)
    try:
        result = _run_full_verify(session, layout)
    except KeyboardInterrupt:
        print(status('验证被用户中断', 'WARN'))
        return 130

    status_code = result.get('status', '')
    if status_code == 'needs_materials':
        _show_material_gaps(pack_dir, layout)
        if prompt_choice('已补充抓包? (1=重新扫描 baseline 并完整重跑 Enter=结束)') == '1':
            if _import_capture(layout, pack_dir, '__AUTO_BATCH__', source_dir=layout.source_dir):
                try:
                    result = _run_full_verify(session, layout)
                except KeyboardInterrupt:
                    return 130

    # Post-verify material feedback loop
    if _show_material_gaps(pack_dir, layout):
        if prompt_choice('补充 baseline 后重新完整测试? (1=是 Enter=否)') == '1':
            if _import_capture(layout, pack_dir, '__AUTO_BATCH__', source_dir=layout.source_dir):
                try:
                    _run_full_verify(session, layout)
                except KeyboardInterrupt:
                    return 130

    # ── Step 7: Report ──
    _step(7, '测试报告', level='OK')
    actions.action_show_results(session)
    write_project_dashboard(pack_dir, project_name=project_id)

    doc_f = load_json(pack_dir / 'finding_chain_reports.json')
    if doc_f:
        write_finding_reports_md(pack_dir, doc_f)

    ss = load_json(pack_dir / 'search_session.json') or {}
    lines = [
        f'输出目录: {rel_display(pack_dir, base=ws)}',
        f'Verdict: {ss.get("verdict") or result.get("verdict") or "?"}',
        f'Findings: {(ss.get("finding_lifecycle") or {}).get("confirmed", "?")}',
        f'HTTP: {(ss.get("budget") or {}).get("used_http")}/{(ss.get("budget") or {}).get("max_http")}',
        f'进度日志: {rel_display(pack_dir / "search_progress.log", base=ws)}',
    ]
    panel('流程结束', lines)
    artifact(pack_dir / 'workbench_run_report.json')
    artifact(pack_dir / 'finding_chain_reports.md')
    return 0
