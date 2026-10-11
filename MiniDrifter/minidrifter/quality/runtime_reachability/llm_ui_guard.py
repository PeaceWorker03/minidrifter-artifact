# -*- coding: utf-8 -*-
"""LLM hard gate — only usable_for_capture materials get detailed UI steps."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from minidrifter.quality.runtime_reachability.ui_api_reachability import (
    is_weak_evidence,
    usable_for_capture,
)

# Thresholds for LLM step generation.
_DIRECT_MIN_CONF = 0.85
_NAV_WRAPPER_MIN_CONF = 0.80


def llm_eligible_for_steps(task: Dict[str, Any]) -> bool:
    """Whether LLM may generate step-by-step UI capture instructions."""
    if not task.get('usable_for_capture', False):
        return False
    if task.get('ui_reachability') in {
        'STATIC_ONLY_NEEDS_MATERIAL',
        'STATIC_ONLY_REPLAYABLE',
        'UNREACHABLE_UNKNOWN',
    }:
        return False
    ev = task.get('evidence') or task.get('best_capture_evidence') or ''
    conf = float(task.get('confidence') or task.get('capture_confidence') or 0)
    if is_weak_evidence(ev):
        return False
    if ev == 'api_call_site_direct':
        return conf >= _DIRECT_MIN_CONF
    if ev in {'navigate_to_call', 'chunk_require_backtrace', 'runtime_material_alias'}:
        return conf >= _NAV_WRAPPER_MIN_CONF
    if task.get('capture_anchor_confirmed') or task.get('runtime_alias_confirmed'):
        return True
    return conf >= _NAV_WRAPPER_MIN_CONF


def weak_evidence_notice(task: Dict[str, Any]) -> str:
    """User-facing text when API cannot be a direct capture target."""
    api = task.get('api') or task.get('static_producer_api') or '该接口'
    anchor = task.get('capture_anchor_api') or task.get('material_source_api')
    unlocks = task.get('unlocks_static_candidates') or []
    lines = [
        f'该 API `{api}` 是静态候选测试接口，但当前未发现可靠 UI 触发路径。',
        '系统不会要求用户直接抓取该接口。',
    ]
    if anchor:
        lines.append(f'请先采集可达入口 `{anchor}`，用于提供运行态材料（token/headers/业务字段）。')
    if unlocks:
        lines.append('该材料将用于解锁以下静态候选链：')
        for u in unlocks[:8]:
            lines.append(f'- `{u}`')
    else:
        lines.append('请按「UI 材料采集」区的 capture_anchor 任务抓包。')
    return '\n'.join(lines)


def sanitize_llm_vocabulary(text: str) -> str:
    """Strip misleading account-count wording from LLM output."""
    replacements = [
        ('单账户', '运行态上下文'),
        ('双账户', '双平面材料模型'),
        ('两个账户', '两类采集平面'),
    ]
    out = text
    for old, new in replacements:
        out = out.replace(old, new)
    return out


def filter_tasks_for_llm(tasks: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """Split tasks into LLM-eligible and static-only notices."""
    eligible: List[Dict[str, Any]] = []
    ineligible: List[Dict[str, Any]] = []
    for t in tasks:
        if llm_eligible_for_steps(t):
            eligible.append(t)
        else:
            ineligible.append({**t, 'notice': weak_evidence_notice(t)})
    return {'eligible': eligible, 'ineligible': ineligible}
