# -*- coding: utf-8
"""Decompile / static-analysis readiness gate with explicit project states."""
from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from minidrifter.core.profile import ProjectProfileDetector
from minidrifter.orchestration.project_readiness import check_decompile_readiness, check_pack_readiness

READY_DECOMPILED = 'READY_DECOMPILED'
NEED_DECOMPILE = 'NEED_DECOMPILE'
BROKEN_DECOMPILE = 'BROKEN_DECOMPILE'
UNSUPPORTED_SHAPE = 'UNSUPPORTED_SHAPE'
ENCRYPTED_OR_PROTECTED = 'ENCRYPTED_OR_PROTECTED'


def classify_project_state(project_root: Path) -> Dict[str, Any]:
    """Map profile → wedecode-like status for UI."""
    project_root = Path(project_root)
    suffix = project_root.suffix.lower()

    if suffix in ('.wxapkg', '.zip', '.rar', '.7z'):
        return {
            'state': NEED_DECOMPILE,
            'ready': False,
            'message': 'Archive detected — run wedecode/unveil unpack first or point to decompiled directory.',
        }

    report = check_decompile_readiness(project_root)
    profile = report.get('profile') or {}
    shape = profile.get('shape') or 'mixed_or_unknown'
    obf = (profile.get('obfuscation') or {}).get('level')

    if report.get('ready'):
        state = READY_DECOMPILED
    elif shape == 'mixed_or_unknown' and not profile.get('has_app_json'):
        state = BROKEN_DECOMPILE
    elif obf == 'high' and profile.get('file_count', 0) < 5:
        state = ENCRYPTED_OR_PROTECTED
    elif profile.get('platform_guess') != 'wechat':
        state = UNSUPPORTED_SHAPE
    else:
        state = BROKEN_DECOMPILE

    return {
        'state': state,
        'ready': state == READY_DECOMPILED,
        'shape': shape,
        'blockers': report.get('blockers'),
        'warnings': report.get('warnings'),
        'message': _state_message(state, report),
        'next_action': 'static_analyze' if state == READY_DECOMPILED else 'fix_or_decompile',
    }


def _state_message(state: str, report: Dict[str, Any]) -> str:
    if state == READY_DECOMPILED:
        return 'Project satisfies MiniDrifter analysis prerequisites.'
    if state == NEED_DECOMPILE:
        return 'Provide decompiled directory or unpack wxapkg first.'
    blockers = report.get('blockers') or []
    if blockers:
        return blockers[0].get('message', 'Decompile gate failed.')
    return 'Project cannot enter MiniDrifter analysis.'


def gate_pack(pack_dir: Path) -> Dict[str, Any]:
    return check_pack_readiness(pack_dir)
