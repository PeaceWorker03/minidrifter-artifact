# -*- coding: utf-8 -*-
"""MiniDrifter Console — wizard-first entry (MiniDrifter / repo root)."""
from __future__ import annotations

import argparse
from pathlib import Path

from minidrifter.orchestration.console import actions
from minidrifter.orchestration.console.session import ConsoleSession
from minidrifter.orchestration.console.wizard import run_wizard
from minidrifter.orchestration.console.workspace_layout import (
    default_workspace as resolve_default_workspace,
    ensure_workspace_root,
    find_MiniDrifter_root,
)


def _run_legacy_menu(session: ConsoleSession) -> None:
    from minidrifter.orchestration.console.display import menu, panel, prompt_choice, status
    from minidrifter.orchestration.console.state import detect_state

    actions._ensure_utf8_stdout()

    ACTION_MAP = {
        'setup': actions.action_quick_setup,
        'scan': actions.action_scan_and_pick,
        'analyze': actions.action_analyze_and_prepare,
        'static': actions.action_analyze_and_prepare,
        'paste_capture': actions.action_paste_capture,
        'paste_and_verify': lambda s: (
            actions.action_paste_capture(s) and actions.action_run_verify(s, live=True, resume=True, skip_confirm=True)
        ),
        'live_verify': lambda s: actions.action_run_verify(s, live=True, resume=True, skip_confirm=True),
    }

    while True:
        st = detect_state(session)
        pack = session.get('pack_dir') or '-'
        name = Path(pack).name if pack != '-' else '-'
        panel('MiniDrifter · 菜单模式', [
            f'项目输出: {name}',
            f'阶段: {st.get("phase_label")}',
            f'推荐: {st.get("recommend_label")}',
        ])
        menu('主菜单', [
            ('', f'[Enter] {st.get("recommend_label")}'),
            ('1', '扫描 Workspace 并选择项目'),
            ('2', '静态分析 + 验证准备'),
            ('3', '导入 baseline 抓包'),
            ('3b', '重扫 baseline/ 全部 .http 并导入'),
            ('4', 'Live 深链验证'),
            ('5', '查看结果 / Findings'),
            ('6', '设置'),
            ('0', '退出'),
        ])
        pick = prompt_choice()
        if pick in ('0', 'q'):
            break
        if pick == '':
            pick = st.get('recommend') or 'live_verify'
        if pick == '1':
            actions.action_scan_and_pick(session)
        elif pick == '2':
            actions.action_analyze_and_prepare(session)
        elif pick == '3':
            actions.action_paste_capture(session)
        elif pick == '3b':
            actions.action_refresh_baseline(session)
        elif pick == '4':
            actions.action_run_verify(session, live=True, resume=True, skip_confirm=True)
        elif pick == '5':
            actions.action_show_results(session)
        elif pick == '6':
            actions.action_settings(session)
        elif pick in ACTION_MAP:
            ACTION_MAP[pick](session)
        else:
            print(status('无效选项', 'WARN'))


def main(argv: list[str] | None = None, *, default_workspace: str | None = None) -> None:
    MiniDrifter_root = find_MiniDrifter_root()
    ws_default = default_workspace or str(resolve_default_workspace(MiniDrifter_root=MiniDrifter_root))

    parser = argparse.ArgumentParser(
        description='MiniDrifter — 小程序链式安全验证向导',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            '工作区结构:\n'
            '  Workspace/<项目>/           反编译源码\n'
            '  Workspace/<项目>/baseline/  运行态抓包\n'
            '  Workspace/<项目>/OUTPUT/    测试输出\n\n'
            '从仓库根目录: python MiniDrifter/run_minidrifter.py\n'
            '或从 MiniDrifter: python run_minidrifter.py'
        ),
    )
    parser.add_argument(
        '--workspace', '-w',
        default=ws_default,
        help='工作区目录（默认: <仓库根>/Workspace）',
    )
    parser.add_argument('--menu', action='store_true', help='菜单模式（可重复操作各步骤）')
    parser.add_argument('--skip-verify', action='store_true', help='仅静态+baseline，不跑 Live 验证')
    parser.add_argument(
        '--refresh-baseline',
        action='store_true',
        help='仅重扫 baseline/ 抓包并导入（需已选项目且存在 OUTPUT pack）',
    )
    parser.add_argument('--pack', '-i', default=None, help='(菜单) 指定 OUTPUT/pack 目录')
    parser.add_argument('--project', '-p', default=None, help='(菜单) 指定源码目录')
    args = parser.parse_args(argv)

    actions._ensure_utf8_stdout()

    ws_path = Path(args.workspace)
    if not ws_path.is_absolute():
        ws_path = (MiniDrifter_root / ws_path).resolve()
    ws_path = ensure_workspace_root(ws_path)

    if args.menu:
        session = ConsoleSession(ws_path / 'MiniDrifter_console_session.json')
        session.set('workspace', str(ws_path))
        session.set('MiniDrifter_root', str(MiniDrifter_root))
        if args.pack:
            session.set('pack_dir', str(Path(args.pack).resolve()))
        if args.project:
            session.set('project_root', str(Path(args.project).resolve()))
        _run_legacy_menu(session)
        return

    session = ConsoleSession(ws_path / 'MiniDrifter_console_session.json')
    session.set('workspace', str(ws_path))
    session.set('MiniDrifter_root', str(MiniDrifter_root))
    if args.pack:
        session.set('pack_dir', str(Path(args.pack).resolve()))
    if args.project:
        session.set('project_root', str(Path(args.project).resolve()))
        session.set('source_dir', str(Path(args.project).resolve()))

    if args.refresh_baseline:
        if not session.get('pack_dir') or not session.get('project_root'):
            print('请指定 --project 与 --pack，或先运行完整向导选择项目')
            raise SystemExit(1)
        ok = actions.action_refresh_baseline(session)
        raise SystemExit(0 if ok else 1)

    code = run_wizard(session, workspace=ws_path, skip_verify=args.skip_verify)
    raise SystemExit(code)


if __name__ == '__main__':
    main()
