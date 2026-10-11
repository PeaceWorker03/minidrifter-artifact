# -*- coding: utf-8 -*-
"""Detect project phase → one recommended next action."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from minidrifter.orchestration.console.display import load_json
from minidrifter.orchestration.console.session import ConsoleSession
from minidrifter.orchestration.project_readiness import check_pack_readiness
from minidrifter.runtime.workspace_paths import find_workspace_root
from minidrifter.orchestration.console.workspace_defaults import suggest_pack_and_project


def _pack_has_static(pack: Path) -> bool:
    return (pack / 'api_card_pack_manifest.json').exists() or (pack / 'all_api_cards.json').exists()


def _open_tickets(pack: Path) -> List[Dict[str, Any]]:
    doc = load_json(pack / 'blocking_tickets.json') or {}
    return doc.get('tickets') or []


def detect_state(session: ConsoleSession) -> Dict[str, Any]:
    """Return phase + recommended action for smart menu."""
    pack = session.pack_path()
    proj = session.project_path()

    if not pack:
        ws = find_workspace_root()
        pack_hint, proj_hint = suggest_pack_and_project()
        return {
            'phase': 'setup',
            'phase_label': '未配置项目',
            'recommend': 'setup',
            'recommend_label': '首次配置（Workspace 项目 + pack 输出目录）',
            'hint': f'优先使用 Workspace 下反编译目录，例如 project={proj_hint or "Workspace/<小程序>"}',
            'can_verify': False,
        }

    pack = Path(pack)
    readiness = check_pack_readiness(pack)
    tickets = _open_tickets(pack)
    global_block = [t for t in tickets if t.get('severity') == 'blocking']
    chain_block = [t for t in tickets if t.get('severity') != 'blocking']

    findings = load_json(pack / 'finding_chain_reports.json') or {}
    confirmed = findings.get('confirmed_count') or 0
    last = load_json(pack / 'search_session.json') or {}

    if not _pack_has_static(pack):
        if not proj:
            return {
                'phase': 'setup',
                'phase_label': '缺少静态 pack',
                'recommend': 'setup',
                'recommend_label': '设置 Workspace 下 project 路径后做静态分析',
                'hint': '需要 -p 指向 Workspace/<小程序名> 解包目录',
                'can_verify': False,
            }
        return {
            'phase': 'static',
            'phase_label': '待静态分析',
            'recommend': 'analyze',
            'recommend_label': '静态分析 + N0/N1 准备',
            'hint': '首次约 1–3 分钟',
            'can_verify': False,
        }

    if not readiness.get('ready_for_live_verify'):
        if global_block:
            fc = global_block[0].get('failure_class', 'auth')
            return {
                'phase': 'blocked',
                'phase_label': f'全局阻塞 · {fc}',
                'recommend': 'paste_capture',
                'recommend_label': '粘贴新登录抓包后继续',
                'hint': global_block[0].get('user_instruction', ''),
                'can_verify': False,
                'tickets_global': len(global_block),
                'tickets_chain': len(chain_block),
            }
        return {
            'phase': 'materials',
            'phase_label': '待运行态材料',
            'recommend': 'paste_capture',
            'recommend_label': '粘贴 baseline HTTP 抓包',
            'hint': '见 <项目>/baseline/README.txt 或 OUTPUT/user_input_prompt.md',
            'can_verify': False,
        }

    if global_block:
        return {
            'phase': 'blocked',
            'phase_label': 'Token 可能过期',
            'recommend': 'paste_and_verify',
            'recommend_label': '粘贴新抓包 → 续跑验证',
            'hint': '使用 intake 报告推荐的 capture 路径',
            'can_verify': True,
            'tickets_global': len(global_block),
        }

    ss_verdict = last.get('verdict') or '?'
    return {
        'phase': 'ready',
        'phase_label': f'可验证 · 已有 {confirmed} 条 confirmed',
        'recommend': 'live_verify',
        'recommend_label': 'Live 深链验证（Apex-PoC）',
        'hint': f'上次: {ss_verdict} · Enter 直接开始',
        'can_verify': True,
        'findings_confirmed': confirmed,
        'last_verdict': ss_verdict,
    }
