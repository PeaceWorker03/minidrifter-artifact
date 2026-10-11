# -*- coding: utf-8
"""MiniDrifter Workbench — unified multi-project tool orchestration."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from minidrifter.core.utils import write_json
from minidrifter.orchestration.intake_prompts import build_intake_checklist, write_user_input_artifacts
from minidrifter.orchestration.project_readiness import (
    check_decompile_readiness,
    check_pack_readiness,
    gate_workspace_project,
)
from minidrifter.orchestration.workspace_scanner import scan_workspace, write_workspace_manifest

WORKBENCH_STAGES = (
    'scan',           # 1. 识别工作区下所有小程序
    'gate_decompile', # 2. 反编译/结构就绪检查
    'static_analyze', # 3. N0 静态提取 + freeze
    'erd_n1',         # 4. N0/N1 分类 + acquisition plan
    'intake_prompt',  # 5. 输出用户输入清单
    'materialize',    # 6. N1 物化
    'verify_plan',    # 7. 链路规划 + 深度 LLM 链
    'live_verify',    # 8. 执行验证 + HITL
    'report',         # 9. 报告
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def run_workbench_scan(workspace: Path) -> Dict[str, Any]:
    doc = scan_workspace(workspace)
    write_workspace_manifest(workspace, doc)
    return doc


def run_workbench_gate(project_root: Path) -> Dict[str, Any]:
    return check_decompile_readiness(project_root)


def run_workbench_intake_prompt(pack_dir: Path) -> Dict[str, Any]:
    pack_dir = Path(pack_dir)
    acquisition = None
    preflight = None
    ap = pack_dir / 'acquisition_plan.json'
    pf = pack_dir / 'replay_preflight_report.json'
    if ap.exists():
        acquisition = json.loads(ap.read_text(encoding='utf-8'))
    if pf.exists():
        preflight = json.loads(pf.read_text(encoding='utf-8'))
    checklist = build_intake_checklist(
        pack_dir=str(pack_dir),
        acquisition_plan=acquisition,
        preflight=preflight,
    )
    write_json(pack_dir / 'user_intake_checklist.json', checklist)
    write_user_input_artifacts(pack_dir, acquisition_plan=acquisition)
    return checklist


def build_workbench_roadmap(
    *,
    workspace: Optional[Path] = None,
    project_root: Optional[Path] = None,
    pack_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    """Single document describing where user is and what to do next."""
    stages: List[Dict[str, Any]] = []

    if workspace:
        scan = scan_workspace(workspace)
        stages.append({'stage': 'scan', 'status': 'ok', 'project_count': scan.get('project_count')})

    if project_root:
        gate = check_decompile_readiness(project_root)
        stages.append({
            'stage': 'gate_decompile',
            'status': 'ok' if gate.get('ready') else 'blocked',
            'blockers': gate.get('blockers'),
        })

    if pack_dir:
        pack_dir = Path(pack_dir)
        pack_gate = check_pack_readiness(pack_dir)
        stages.append({
            'stage': 'pack_readiness',
            'status': 'ok' if pack_gate.get('ready_for_live_verify') else 'partial',
            'detail': pack_gate,
        })

        next_user_action = None
        if not pack_gate.get('ready_for_live_verify'):
            next_user_action = {
                'action': 'paste_http_captures',
                'command': f'python -m minidrifter.cli intake-baseline -i {pack_dir} --raw-file <capture.txt> --import-after',
                'checklist_file': str(pack_dir / 'user_intake_checklist.json'),
            }
        else:
            next_user_action = {
                'action': 'run_verify',
                'command': f'python -m minidrifter.cli run-deep-verify -i {pack_dir} --mode execute --i-know --with-llm --deep-think',
            }

        return {
            'schema_version': '1.0.0',
            'generated_at': _utc_now(),
            'stages': stages,
            'pipeline_order': list(WORKBENCH_STAGES),
            'next_user_action': next_user_action,
            'goal': '发现链式身份凭证错位（subject/object binding mismatch）',
        }

    return {
        'schema_version': '1.0.0',
        'generated_at': _utc_now(),
        'stages': stages,
        'pipeline_order': list(WORKBENCH_STAGES),
    }
