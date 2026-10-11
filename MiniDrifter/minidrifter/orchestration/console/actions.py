# -*- coding: utf-8
"""Console action handlers — delegate to workbench / CLI modules."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from minidrifter.orchestration.console.display import (
    artifact,
    dashboard_summary,
    finding_card,
    load_json,
    panel,
    stage_line,
    status,
    ticket_card,
    write_finding_reports_md,
)
from minidrifter.orchestration.console.session import ConsoleSession


def _ensure_utf8_stdout() -> None:
    if hasattr(sys.stdout, 'reconfigure'):
        try:
            sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        except Exception:
            pass


def action_scan_workspace(session: ConsoleSession) -> None:
    from minidrifter.orchestration.workbench import run_workbench_scan

    ws = Path(session.get('workspace') or '.')
    if not ws.is_dir():
        print(status('Workspace path invalid', 'BLOCK'))
        return
    doc = run_workbench_scan(ws)
    rows = []
    for p in doc.get('projects') or []:
        flag = 'OK' if p.get('decompile_candidate') else 'SKIP'
        rows.append((flag, p.get('project_id'), p.get('shape'), p.get('file_count')))
    from minidrifter.orchestration.console.display import table
    table(['Flag', 'Project', 'Shape', 'Files'], rows)
    artifact(ws / 'MiniDrifter_workspace.json', 'workspace manifest')
    session.set('last_scan', str(ws))


def action_pick_project(session: ConsoleSession) -> None:
    ws = Path(session.get('workspace') or '.')
    manifest = load_json(ws / 'MiniDrifter_workspace.json')
    if not manifest:
        print(status('Run scan first', 'BLOCK'))
        return
    projects = manifest.get('projects') or []
    from minidrifter.orchestration.console.display import table
    table(['#', 'ID', 'Root'], [(i + 1, p.get('project_id'), p.get('project_root')) for i, p in enumerate(projects)])
    from minidrifter.orchestration.console.display import prompt_choice
    pick = prompt_choice('Project # (0=cancel)')
    if pick == '0' or not pick.isdigit():
        return
    idx = int(pick) - 1
    if 0 <= idx < len(projects):
        p = projects[idx]
        pid = p.get('project_id', 'pack')
        from minidrifter.orchestration.console.workspace_layout import ensure_project_layout, project_layout
        layout = project_layout(ws, pid)
        ensure_project_layout(layout)
        session.set('project_root', str(layout.source_dir))
        session.set('pack_dir', str(layout.output_dir))
        session.set('source_dir', str(layout.source_dir))
        session.set('baseline_dir', str(layout.baseline_dir))
        session.relocate_session_to_pack()
        print(status(f'Selected {pid}', 'OK'))


def action_gate(session: ConsoleSession) -> None:
    from minidrifter.orchestration.project_readiness import (
        check_decompile_readiness,
        check_pack_readiness,
    )

    pack = session.pack_path()
    proj = session.project_path()
    if pack and (pack / 'api_card_pack_manifest.json').exists():
        r = check_pack_readiness(pack)
        panel('Pack Readiness', [
            f'static_review: {r.get("ready_for_static_review")}',
            f'live_verify: {r.get("ready_for_live_verify")}',
            f'next: {r.get("next_stage")}',
        ])
        for b in r.get('blockers') or []:
            print(status(b.get('message', ''), 'BLOCK'))
    elif proj:
        r = check_decompile_readiness(proj)
        panel('Decompile Gate', [f'ready: {r.get("ready")}', f'shape: {(r.get("profile") or {}).get("shape")}'])
        for b in r.get('blockers') or []:
            print(status(b.get('message', ''), 'BLOCK'))
    else:
        print(status('Set project_root or pack_dir', 'BLOCK'))


def action_static_analyze(session: ConsoleSession) -> None:
    proj = session.project_path()
    pack = session.require_pack()
    if not proj:
        print(status('project_root required', 'BLOCK'))
        return
    from minidrifter.pipeline import MiniDrifterPipeline
    from minidrifter.freezers.api_card import APICardFreezer

    pack.mkdir(parents=True, exist_ok=True)
    print(status('Static analyze running...', 'RUN'))
    pipe = MiniDrifterPipeline(str(proj), str(pack), 'wechat')
    res = pipe.run()
    freezer = APICardFreezer.from_output_dir(str(pack), top_k_evidence=200)
    freezer.write(pack)
    shape = (res.get('project_profile') or {}).get('shape')
    print(status(f'Analyze done shape={shape}', 'OK'))
    artifact(pack / 'api_card_pack_manifest.json')


def action_verify_prepare(session: ConsoleSession) -> None:
    pack = session.require_pack()
    from minidrifter.orchestration.workbench_run import _run_verify_prepare
    from minidrifter.orchestration.project_dashboard import write_project_dashboard
    from minidrifter.orchestration.workbench import run_workbench_intake_prompt

    prep = _run_verify_prepare(pack, with_llm=session.get('with_llm', False))
    write_project_dashboard(pack, project_name=pack.name)
    run_workbench_intake_prompt(pack)
    inv = (prep.get('erd') or {}).get('erd_inventory') or {}
    print(status(f'cards={ (prep.get("erd") or {}).get("card_count")} stage1={(prep.get("plan") or {}).get("plan_summary", {}).get("stage_1_target_count")}', 'OK'))
    artifact(pack / 'project_dashboard.json')
    artifact(pack / 'user_input_prompt.md')


def action_show_dashboard(session: ConsoleSession) -> None:
    pack = session.require_pack()
    doc = load_json(pack / 'project_dashboard.json')
    if not doc:
        from minidrifter.orchestration.project_dashboard import write_project_dashboard
        paths = write_project_dashboard(pack, project_name=pack.name)
        doc = load_json(Path(paths['json']))
    if doc:
        dashboard_summary(doc)
        artifact(pack / 'project_dashboard.md')


def action_quick_setup(session: ConsoleSession) -> None:
    from minidrifter.orchestration.console.display import prompt_path
    from minidrifter.orchestration.console.workspace_defaults import (
        apply_session_defaults,
        suggest_pack_and_project,
    )

    default_pack, default_proj = suggest_pack_and_project()

    panel('首次配置（两项路径）', [
        'Pack dir = 分析/验证输出目录（如 sample_outputs/<slug>）',
        'Project  = Workspace 下解包后小程序源码目录',
    ])
    pack = prompt_path('Pack dir', session.get('pack_dir') or default_pack)
    proj = prompt_path('Project root', session.get('project_root') or default_proj)
    if pack:
        session.set('pack_dir', str(Path(pack).resolve()))
        session.relocate_session_to_pack()
    if proj:
        session.set('project_root', str(Path(proj).resolve()))
        apply_session_defaults(session, Path(proj))
    print(status('配置已保存', 'OK'))


def action_analyze_and_prepare(session: ConsoleSession) -> None:
    pack = session.require_pack()
    if not (pack / 'api_card_pack_manifest.json').exists():
        action_static_analyze(session)
    action_verify_prepare(session)
    print(status('静态 + N0/N1 准备完成', 'OK'))


def action_show_results(session: ConsoleSession) -> None:
    action_show_findings(session)
    action_search_summary(session)
    action_list_tickets(session)


def action_scan_and_pick(session: ConsoleSession) -> None:
    from minidrifter.orchestration.console.display import prompt_path, table, prompt_choice
    from minidrifter.orchestration.console.workspace_layout import (
        ensure_project_layout,
        project_layout,
        rel_display,
    )

    ws = Path(session.get('workspace') or '.')
    if not ws.is_dir():
        print(status('Workspace path invalid', 'BLOCK'))
        return
    action_scan_workspace(session)
    manifest = load_json(ws / 'MiniDrifter_workspace.json')
    projects = (manifest or {}).get('projects') or []
    if not projects:
        print(status('未发现小程序项目', 'WARN'))
        return
    table(
        ['#', 'ID', '源码路径'],
        [
            (i + 1, p.get('project_id'), rel_display(p.get('project_root', ''), base=ws))
            for i, p in enumerate(projects)
        ],
    )
    pick = prompt_choice('项目编号 (0=取消)')
    if pick.isdigit() and int(pick) > 0:
        idx = int(pick) - 1
        if 0 <= idx < len(projects):
            p = projects[idx]
            pid = p.get('project_id', 'pack')
            layout = project_layout(ws, pid)
            ensure_project_layout(layout)
            session.set('project_root', str(layout.source_dir))
            session.set('pack_dir', str(layout.output_dir))
            session.set('source_dir', str(layout.source_dir))
            session.set('baseline_dir', str(layout.baseline_dir))
            session.relocate_session_to_pack()
            print(status(f'已选 {pid} → OUTPUT: {rel_display(layout.output_dir, base=ws)}', 'OK'))


def action_refresh_baseline(session: ConsoleSession) -> bool:
    """Re-scan all baseline/*.http and re-import (incremental merge)."""
    from minidrifter.orchestration.console.workspace_layout import (
        ensure_project_layout,
        project_layout,
        rel_display,
    )
    from minidrifter.orchestration.console.baseline_batch import import_all_baseline_captures

    pack = session.require_pack()
    ws = Path(session.get('workspace') or '.')
    proj = session.project_path()
    if not proj:
        print(status('project_root 未设置', 'BLOCK'))
        return False
    pid = Path(proj).name
    layout = project_layout(ws, pid)
    ensure_project_layout(layout)
    print(status('重新扫描 baseline/ 全部抓包…', 'RUN'))
    ok, summary = import_all_baseline_captures(
        layout, pack, source_dir=Path(session.get('source_dir') or proj), materialize=True,
    )
    level = 'OK' if ok else 'WARN'
    print(status(
        f'captures={summary.get("capture_count")} fields={summary.get("field_count")} '
        f'missing={len(summary.get("missing_required") or [])}',
        level,
    ))
    artifact(layout.baseline_dir / 'baseline_manifest.json')
    artifact(layout.baseline_dir / 'supplement_needed.md')
    return ok


def action_paste_capture(session: ConsoleSession, *, optional: bool = False) -> bool:
    from minidrifter.orchestration.console.display import prompt_path
    from minidrifter.verification.resume_manager import auto_resume_from_capture_file

    pack = session.require_pack()
    baseline_hint = session.get('baseline_dir') or ''
    hint = '抓包文件路径 (.http/.txt)，或 baseline/ 下文件'
    if baseline_hint:
        hint += f' [{baseline_hint}]'
    fpath = prompt_path(hint, '')
    if not fpath:
        if optional:
            return False
        print(status('未提供文件', 'BLOCK'))
        return False
    if not Path(fpath).exists():
        print(status('文件不存在', 'BLOCK'))
        return False
    result = auto_resume_from_capture_file(pack, Path(fpath))
    print(status(f'已导入: {result.get("steps_done")}', 'OK'))
    if result.get('import_error'):
        print(status(result['import_error'], 'WARN'))
    artifact(pack / 'baseline_runtime_context.json')
    return True


def action_list_tickets(session: ConsoleSession) -> None:
    pack = session.require_pack()
    doc = load_json(pack / 'blocking_tickets.json') or {'tickets': []}
    tickets = doc.get('tickets') or []
    if not tickets:
        print(status('No open tickets', 'OK'))
        return
    global_t = [t for t in tickets if t.get('severity') == 'blocking']
    chain_t = [t for t in tickets if t.get('severity') != 'blocking']
    panel('Open Tickets', [
        f'Global blocking: {len(global_t)}',
        f'Chain blocking: {len(chain_t)}',
    ])
    for t in tickets[:8]:
        ticket_card(t)
    if len(tickets) > 8:
        print(status(f'... and {len(tickets) - 8} more in blocking_tickets.json', 'INFO'))


def action_resolve_ticket(session: ConsoleSession) -> None:
    from minidrifter.orchestration.console.display import prompt_path, prompt_choice
    from minidrifter.verification.resume_manager import apply_ticket_resolution

    pack = session.require_pack()
    doc = load_json(pack / 'blocking_tickets.json') or {'tickets': []}
    tickets = doc.get('tickets') or []
    if not tickets:
        print(status('No tickets', 'INFO'))
        return
    for i, t in enumerate(tickets[:10]):
        print(f'  [{i+1}] {t.get("ticket_id", "")[:40]} · {t.get("failure_class")} · {(t.get("evidence") or {}).get("api")}')
    pick = prompt_choice('Ticket #')
    fpath = prompt_path('Capture file', '')
    if not pick.isdigit() or not fpath:
        return
    idx = int(pick) - 1
    if 0 <= idx < len(tickets):
        tid = tickets[idx]['ticket_id']
        raw = Path(fpath).read_text(encoding='utf-8', errors='replace')
        apply_ticket_resolution(pack, tid, raw, source_label=fpath)
        print(status(f'Resolved {tid}', 'OK'))


def action_show_findings(session: ConsoleSession) -> None:
    pack = session.require_pack()
    doc = load_json(pack / 'finding_chain_reports.json')
    if not doc:
        print(status('No findings yet — run verify first', 'WARN'))
        return
    md_path = write_finding_reports_md(pack, doc)
    panel('Findings Summary', [
        f'Confirmed: {doc.get("confirmed_count")}',
        f'Hypothesis: {doc.get("hypothesis_count")}',
        f'Rejected: {doc.get("rejected_count")}',
    ])
    for r in (doc.get('reports') or [])[:5]:
        finding_card(r)
    artifact(md_path, 'narrative markdown')
    artifact(pack / 'finding_chain_reports.json')


def action_search_summary(session: ConsoleSession) -> None:
    pack = session.require_pack()
    ss = load_json(pack / 'search_session.json') or load_json(pack / 'workbench_run_report.json')
    if not ss:
        print(status('No search session', 'WARN'))
        return
    inner = ss.get('search_session') or ss.get('verify', {}).get('search_session') or ss
    cov = inner.get('coverage') or ss.get('coverage') or {}
    budget = inner.get('budget') or {}
    panel('Last Verify Run', [
        f'verdict: {inner.get("verdict") or ss.get("verdict")}',
        f'stop_reason: {inner.get("stop_reason")}',
        f'http: {cov.get("http_calls")}/{budget.get("max_http", "?")}',
        f'beam_chains: {cov.get("beam_chains")}',
        f'findings_confirmed: {cov.get("findings_confirmed")}',
        f'business_success: {cov.get("business_success")}',
    ])
    lh = load_json(pack / 'llm_health_summary.json')
    if lh:
        print(status(f'LLM events={lh.get("event_count")} errors={lh.get("llm_errors")}', 'INFO'))


def action_run_verify(session: ConsoleSession, *, live: bool = False, resume: bool = False, skip_confirm: bool = False) -> None:
    from minidrifter.orchestration.console.display import confirm
    from minidrifter.orchestration.workbench_run import run_workbench_pipeline

    pack = session.require_pack()
    mode = 'execute' if live else 'dry-run'
    if live and not skip_confirm:
        if not session.get('i_know_acknowledged') and not confirm('将发送真实 HTTP 到目标主机，确认?'):
            print(status('已取消', 'INFO'))
            return
    if live:
        session.set('i_know_acknowledged', True)

    print(status(f'开始验证 mode={mode} ...', 'RUN'))
    result = run_workbench_pipeline(
        pack_dir=pack,
        project_root=session.project_path(),
        source_dir=Path(session.get('source_dir')) if session.get('source_dir') else session.project_path(),
        skip_analyze=True,
        with_llm=session.get('with_llm', True),
        deep_think=session.get('deep_think', True),
        mode=mode,
        max_http=session.get('max_http', 250),
        max_llm=session.get('max_llm', 80),
        max_depth=session.get('max_depth', 5),
        beam_width=session.get('beam_width', 5),
        anchor_api_id=session.get('anchor_api') or None,
        i_know=live,
        resume=resume,
        force_resume=resume,
    )
    panel('验证完成', [
        f'verdict: {result.get("verdict")}',
        (result.get('executive_summary') or '')[:200],
    ])
    artifact(pack / 'workbench_run_report.json')
    doc = load_json(pack / 'finding_chain_reports.json')
    if doc and doc.get('confirmed_count'):
        print(status(f'confirmed findings: {doc.get("confirmed_count")}', 'OK'))


def action_full_pipeline(session: ConsoleSession) -> None:
    """Legacy — redirects to smart flow."""
    st_mod = __import__('minidrifter.orchestration.console.state', fromlist=['detect_state'])
    st = st_mod.detect_state(session)
    if st.get('recommend') == 'setup':
        action_quick_setup(session)
    if st.get('recommend') in ('analyze', 'static'):
        action_analyze_and_prepare(session)
    action_run_verify(session, live=True, resume=True, skip_confirm=True)


def action_settings(session: ConsoleSession) -> None:
    from minidrifter.orchestration.console.display import prompt_path, prompt_choice

    panel('Current Settings', [
        f'workspace: {session.get("workspace")}',
        f'project_root: {session.get("project_root")}',
        f'pack_dir (OUTPUT): {session.get("pack_dir")}',
        f'baseline_dir: {session.get("baseline_dir")}',
        f'source_dir: {session.get("source_dir")}',
        f'mode: {session.get("mode")}  with_llm: {session.get("with_llm")}  deep_think: {session.get("deep_think")}',
        f'max_http: {session.get("max_http")}  anchor: {session.get("anchor_api")}',
    ])
    sub = prompt_choice('Set [1]workspace [2]project [3]pack [4]source [5]max_http [6]anchor [7]toggle_llm [8]toggle_deep [0]back')
    if sub == '1':
        session.set('workspace', prompt_path('Workspace', session.get('workspace', '')))
    elif sub == '2':
        session.set('project_root', prompt_path('Project root', session.get('project_root', '')))
    elif sub == '3':
        session.set('pack_dir', prompt_path('Pack dir', session.get('pack_dir', '')))
        session.relocate_session_to_pack()
    elif sub == '4':
        session.set('source_dir', prompt_path('Source dir (crypto)', session.get('source_dir', '')))
    elif sub == '5':
        v = prompt_path('max_http', str(session.get('max_http', 250)))
        if v.isdigit():
            session.set('max_http', int(v))
    elif sub == '6':
        session.set('anchor_api', prompt_path('anchor api_id', session.get('anchor_api', '')))
    elif sub == '7':
        session.set('with_llm', not session.get('with_llm', True))
    elif sub == '8':
        session.set('deep_think', not session.get('deep_think', True))


def action_preflight(session: ConsoleSession) -> None:
    from minidrifter.verification.replay_preflight import run_replay_preflight
    from minidrifter.core.utils import write_json

    pack = session.require_pack()
    src = Path(session.get('source_dir')) if session.get('source_dir') else session.project_path()
    report = run_replay_preflight(pack, source_dir=src, live_probe=False)
    write_json(pack / 'replay_preflight_report.json', report)
    panel('Preflight', [
        f'ready: {report.get("ready")}',
        f'checks: {(report.get("summary") or {}).get("checks_passed")}/{(report.get("summary") or {}).get("checks_total")}',
        f'warnings: {(report.get("summary") or {}).get("warning_count")}',
    ])
    for b in report.get('blockers') or []:
        print(status(b.get('message', ''), 'BLOCK'))
    for w in (report.get('warnings') or [])[:5]:
        print(status(w.get('message', ''), 'WARN'))


def action_intake_prompt(session: ConsoleSession) -> None:
    from minidrifter.orchestration.workbench import run_workbench_intake_prompt

    pack = session.require_pack()
    checklist = run_workbench_intake_prompt(pack)
    panel('User Input Checklist', [checklist.get('summary') or ''])
    for step in (checklist.get('steps') or [])[:6]:
        print(f'  Step {step.get("step")} [{step.get("phase")}]: {step.get("purpose")}')
    artifact(pack / 'user_input_prompt.md')
    artifact(pack / 'material_requirements.json')
