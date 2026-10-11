# -*- coding: utf-8 -*-
"""Unify blocking feedback into UserActionTicket + operator_request.md."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from minidrifter.core.utils import write_json
from minidrifter.verification.user_ticket import ACCEPTED_FORMATS, TicketRegistry, build_user_ticket

NEXT_ACTION_TICKET_MAP = {
    'import_as_login_bootstrap_sample': {
        'failure_class': 'blocked_no_baseline',
        'user_instruction': '请粘贴登录或首次鉴权成功请求的 Raw HTTP / HAR。',
        'resume_action': 'refresh_baseline_and_continue',
    },
    'import_as_authenticated_sample_and_materialize': {
        'failure_class': 'blocked_intake',
        'user_instruction': '请粘贴登录后任意成功业务 API 的完整 request/response。',
        'resume_action': 'refresh_baseline_and_continue',
    },
    'import_plaintext_fields_only': {
        'failure_class': 'signature_bound',
        'user_instruction': '检测到密文 transport；请提供含明文 Token/session 的抓包，或补充可重算 signature 的材料。',
        'resume_action': 'refresh_baseline_and_continue',
    },
    'import_decrypted_context_and_replay': {
        'failure_class': 'blocked_intake',
        'user_instruction': '请粘贴含密文字段的成功抓包以启用解密 replay。',
        'resume_action': 'refresh_baseline_and_continue',
    },
    'n1_pruned_ciphertext_no_chain': {
        'failure_class': 'blocked_intake',
        'user_instruction': '纯密文抓包且无静态解密链；请提供明文 session 字段或 --source-dir 解析密钥。',
        'resume_action': 'refresh_baseline_and_continue',
    },
    'provide_capture_file': {
        'failure_class': 'waiting_for_entry_capture',
        'user_instruction': '请按 chain_intake_prompt 提供业务入口抓包。',
        'resume_action': 'refresh_baseline_and_continue',
    },
    'refresh_baseline_capture': {
        'failure_class': 'auth_expired',
        'user_instruction': '登录态已过期；请重新登录并粘贴新的成功业务请求。',
        'resume_action': 'refresh_baseline_and_continue',
    },
    'review_deferred_material_gaps': {
        'failure_class': 'missing_object',
        'user_instruction': '部分链路缺少业务对象字段；请补充 list/detail 类抓包。',
        'resume_action': 'acquire_object_and_continue',
    },
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _pack_str(pack_dir: Path) -> str:
    return str(Path(pack_dir).resolve())


def normalize_ticket(
    ticket: Dict[str, Any],
    *,
    pack_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    """Enrich ticket with resume_command and canonical user-facing fields."""
    out = dict(ticket)
    tid = out.get('ticket_id') or 'ticket_unknown'
    pack = _pack_str(pack_dir) if pack_dir else '<pack>'
    out.setdefault('accepted_formats', list(ACCEPTED_FORMATS))
    out.setdefault('can_continue_other_chains', True)
    evidence = out.get('evidence') or {}
    out.setdefault('blocked_api', evidence.get('api') or out.get('blocked_api') or '')
    out.setdefault('blocked_stage', out.get('blocked_stage') or 'M0_BUILD')
    out.setdefault('root_cause', out.get('root_cause') or out.get('failure_class') or 'unknown')
    missing = out.get('missing_fields') or [
        m.get('field') for m in (out.get('missing_materials') or []) if m.get('field')
    ]
    out['missing_fields'] = [f for f in missing if f]
    out.setdefault(
        'user_action',
        out.get('user_instruction') or out.get('user_action') or '请补充运行态材料',
    )
    out.setdefault(
        'resume_command',
        f'python -m minidrifter.cli workbench resume -i "{pack}" -f <capture.http|capture.har> --ticket-id {tid}',
    )
    out['next_action_summary'] = out.get('next_action_summary') or out.get('resume_action') or out.get('root_cause')
    return out


def ticket_from_next_action(
    next_action: str,
    *,
    pack_dir: Path,
    path: str = '',
    chain_id: Optional[str] = None,
    missing_fields: Optional[List[str]] = None,
) -> Dict[str, Any]:
    meta = NEXT_ACTION_TICKET_MAP.get(next_action) or {
        'failure_class': 'blocked_intake',
        'user_instruction': f'阻塞动作: {next_action}',
        'resume_action': 'refresh_baseline_and_continue',
    }
    ticket = build_user_ticket(
        attribution={
            'failure_class': meta['failure_class'],
            'primary_action': next_action,
            'path': path,
            'diagnosis': meta['user_instruction'],
        },
        test_case={'path': path, 'chain_id': chain_id},
        chain_id=chain_id,
    )
    ticket['resume_action'] = meta['resume_action']
    ticket['user_instruction'] = meta['user_instruction']
    ticket['missing_fields'] = missing_fields or []
    if missing_fields:
        ticket['missing_materials'] = [
            {'field': f, 'why_needed': f'下游链路需要 {f}'} for f in missing_fields
        ]
    return normalize_ticket(ticket, pack_dir=pack_dir)


def emit_ticket(pack_dir: Path, ticket: Dict[str, Any]) -> Dict[str, Any]:
    pack_dir = Path(pack_dir)
    registry = TicketRegistry(pack_dir)
    normalized = normalize_ticket(ticket, pack_dir=pack_dir)
    emitted = registry.emit(normalized)
    write_operator_request_md(pack_dir)
    return emitted


def sync_tickets_from_intake_report(pack_dir: Path, report: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Create tickets for blocked captures in intake report."""
    pack_dir = Path(pack_dir)
    emitted: List[Dict[str, Any]] = []
    for cap in report.get('captures') or []:
        status = cap.get('overall_status') or ''
        if status.startswith('acceptable'):
            continue
        na = cap.get('next_action') or 'blocked_intake'
        ticket = ticket_from_next_action(
            na,
            pack_dir=pack_dir,
            path=cap.get('path') or '',
            missing_fields=[],
        )
        ticket['blocked_stage'] = 'INTAKE'
        ticket['evidence'] = {
            'api': cap.get('path') or '',
            'capture_index': cap.get('capture_index'),
            'message': status,
        }
        emitted.append(emit_ticket(pack_dir, ticket))
    if report.get('n1_gate', {}).get('overall') == 'pruned_all':
        ticket = ticket_from_next_action(
            'n1_pruned_ciphertext_no_chain',
            pack_dir=pack_dir,
        )
        emitted.append(emit_ticket(pack_dir, ticket))
    write_operator_request_md(pack_dir)
    return emitted


def sync_ticket_from_hop_block(
    pack_dir: Path,
    hop_verdict: Dict[str, Any],
    *,
    chain_id: Optional[str] = None,
    hop_index: Optional[int] = None,
) -> Optional[Dict[str, Any]]:
    attr = hop_verdict.get('attribution') or {}
    fc = attr.get('failure_class')
    if not fc:
        return None
    missing = hop_verdict.get('missing_materials') or []
    missing_fields = [m.get('field') for m in missing if m.get('field')]
    ticket = build_user_ticket(
        attribution=attr,
        test_case=hop_verdict.get('test_case') or {
            'path': hop_verdict.get('path'),
            'api_id': hop_verdict.get('api_id'),
            'chain_id': chain_id,
        },
        chain_id=chain_id,
    )
    ticket['missing_materials'] = missing
    ticket['missing_fields'] = missing_fields
    ticket['blocked_stage'] = hop_verdict.get('blocked_stage') or 'M0_BUILD'
    ticket['resume_from_hop'] = hop_index
    ticket['material_request'] = hop_verdict.get('material_request')
    if hop_verdict.get('material_request'):
        mr = hop_verdict['material_request']
        ticket['why_deeper_blocked'] = mr.get('why_deeper_blocked') or ''
        ticket['expected_paths'] = mr.get('expected_paths') or ticket.get('example_paths') or []
    normalized = normalize_ticket(ticket, pack_dir=pack_dir)
    emitted = emit_ticket(pack_dir, normalized)
    try:
        from minidrifter.verification.field_to_blocked_hops import record_blocked_hops_from_ticket
        record_blocked_hops_from_ticket(pack_dir, emitted, hop_verdict=hop_verdict, chain_id=chain_id, hop_index=hop_index)
    except Exception:
        pass
    return emitted


def write_operator_request_md(pack_dir: Path) -> None:
    pack_dir = Path(pack_dir)
    doc = json.loads((pack_dir / 'blocking_tickets.json').read_text(encoding='utf-8')) if (
        pack_dir / 'blocking_tickets.json'
    ).exists() else {'tickets': []}
    tickets = doc.get('tickets') or []
    lines = [
        '# MiniDrifter 操作请求（阻塞工单）',
        '',
        f'生成时间: {_utc_now()}',
        f'开放工单: **{len(tickets)}**',
        '',
        '> 所有阻塞已统一为 ticket。使用下方 `resume_command` 导入材料后继续。',
        '',
    ]
    if not tickets:
        lines.append('当前无开放阻塞工单。')
    for t in tickets:
        norm = normalize_ticket(t, pack_dir=pack_dir)
        lines.extend([
            f"## {norm.get('ticket_id')}",
            '',
            f"- **阻塞接口**: `{norm.get('blocked_api') or '—'}`",
            f"- **阻塞阶段**: {norm.get('blocked_stage')}",
            f"- **根因**: `{norm.get('root_cause')}`",
            f"- **缺失字段**: {', '.join(norm.get('missing_fields') or []) or '—'}",
            f"- **操作**: {norm.get('user_action')}",
            f"- **可继续其他链**: {'是' if norm.get('can_continue_other_chains') else '否'}",
            f"- **接受格式**: {', '.join(norm.get('accepted_formats') or [])}",
            '',
            '```powershell',
            norm.get('resume_command') or '',
            '```',
            '',
        ])
    (pack_dir / 'operator_request.md').write_text('\n'.join(lines), encoding='utf-8')
