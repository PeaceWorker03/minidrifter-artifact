# -*- coding: utf-8
"""UserActionTicket / MaterialRequestTicket — diagnosable, resumable feedback."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from minidrifter.core.utils import write_json

ACCEPTED_FORMATS = ['raw_http', 'har', 'burp_item', 'mitmproxy_flow']

RESUME_ACTIONS = frozenset({
    'refresh_baseline_and_continue',
    'acquire_object_and_continue',
    'repair_schema_and_continue',
    'switch_domain_and_continue',
    'human_confirm_and_continue',
    'revise_graph_and_continue',
    'pause_chain_only',
    'pause_global',
})


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _map_resume_action(primary_action: str, failure_class: str) -> str:
    if failure_class == 'auth_expired' or primary_action == 'refresh_baseline':
        return 'refresh_baseline_and_continue'
    if primary_action == 'acquire_object' or failure_class == 'business_state_blocked':
        return 'acquire_object_and_continue'
    if primary_action in ('schema_repair', 'fix_build_or_skip'):
        return 'repair_schema_and_continue'
    if primary_action == 'switch_domain':
        return 'switch_domain_and_continue'
    if primary_action == 'quarantine_chain':
        return 'pause_chain_only'
    if primary_action == 'pause_execute_class':
        return 'pause_global'
    if primary_action == 'revise_graph_hypothesis':
        return 'revise_graph_and_continue'
    return 'refresh_baseline_and_continue'


def build_user_ticket(
    *,
    attribution: Optional[Dict[str, Any]] = None,
    policy: Optional[Dict[str, Any]] = None,
    test_case: Optional[Dict[str, Any]] = None,
    execution: Optional[Dict[str, Any]] = None,
    chain_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Convert L0-L6 diagnosis → structured ticket for GUI/CLI resume."""
    attr = attribution or {}
    pol = policy or {}
    tc = test_case or {}
    ex = execution or {}

    fc = attr.get('failure_class') or 'unknown'
    layer = attr.get('layer') or 'L4_business_state'
    action = attr.get('primary_action') or pol.get('action') or ''
    path = tc.get('path') or attr.get('path') or ''
    resume = _map_resume_action(action, fc)

    global_pause = resume == 'pause_global' or fc == 'auth_expired'
    can_continue_other = fc not in ('auth_expired', 'app_version_blocked') or layer != 'L2_auth'

    instructions = {
        'auth_expired': '请重新登录小程序，并粘贴一条新的成功业务请求 request/response（含 Token）。',
        'business_state_blocked': '请提供列表/详情接口 response，或换一个有对应业务数据的基准账号。',
        'build_failed': '请粘贴该接口在真机/开发者工具中成功发出的 Raw HTTP。',
        'transport_url_routing': '请确认 base_url 或提供同域成功请求样本。',
        'validation_error': '请提供该接口的成功 request 样本以修复参数结构。',
    }
    user_instruction = instructions.get(fc) or attr.get('diagnosis') or pol.get('reason') or '请补充运行态材料'

    ticket = {
        'schema_version': '1.0.0',
        'ticket_id': f"ticket_{fc}_{stable_slug(path)}_{_utc_now()[:19].replace(':', '')}",
        'generated_at': _utc_now(),
        'severity': 'blocking' if global_pause else 'chain_blocking',
        'status': 'open',
        'layer': layer,
        'failure_class': fc,
        'diagnosis': attr.get('diagnosis') or fc,
        'primary_action': action,
        'chain_id': chain_id or tc.get('chain_id'),
        'evidence': {
            'api': path,
            'api_id': tc.get('api_id') or attr.get('api_id'),
            'status': ex.get('http_status'),
            'message': ex.get('response_snippet') or ex.get('build_status') or fc,
            'outcome': ex.get('call_outcome') or attr.get('atomic_label'),
        },
        'user_instruction': user_instruction,
        'accepted_formats': ACCEPTED_FORMATS,
        'resume_action': resume,
        'blocked_scope': 'global_auth' if global_pause else f'chain:{chain_id or path}',
        'can_continue_other_chains': can_continue_other and not global_pause,
        'example_paths': _example_paths(fc, path),
        'field': pol.get('target_field'),
        'missing_materials': [],
        'why_deeper_blocked': '',
    }
    from minidrifter.ir.converters import to_universal_failure, to_universal_feedback_ticket

    ticket['universal_failure'] = to_universal_failure(
        fc, detail=ticket['diagnosis'], layer=layer,
    )
    ticket['universal_feedback'] = to_universal_feedback_ticket(ticket)
    return ticket


def stable_slug(path: str) -> str:
    return path.replace('/', '_').replace('\\', '_')[:48] or 'global'


def _example_paths(fc: str, path: str) -> List[str]:
    """Generic hints only — app-specific paths belong in profile packs."""
    hints = [path] if path else []
    if fc == 'auth_expired':
        hints.append('(同路径重新登录后的成功 request/response)')
    elif fc == 'business_state_blocked':
        hints.append('(一跳 list/detail 接口 response)')
    return [h for h in hints if h]


class TicketRegistry:
    def __init__(self, pack_dir: Path) -> None:
        self.pack_dir = Path(pack_dir)
        self.open_path = self.pack_dir / 'blocking_tickets.json'
        self.jsonl_path = self.pack_dir / 'user_tickets.jsonl'
        self._open: List[Dict[str, Any]] = []
        self._load()

    def _load(self) -> None:
        if self.open_path.exists():
            doc = json.loads(self.open_path.read_text(encoding='utf-8'))
            self._open = doc.get('tickets') or []

    def emit(self, ticket: Dict[str, Any]) -> Dict[str, Any]:
        dup = [t for t in self._open if t.get('failure_class') == ticket.get('failure_class')
               and t.get('evidence', {}).get('api') == ticket.get('evidence', {}).get('api')]
        if dup:
            return dup[-1]
        if ticket.get('severity') == 'informational':
            self._append_jsonl(ticket)
            return ticket
        self._open.append(ticket)
        self._persist()
        self._append_jsonl(ticket)
        return ticket

    def resolve(self, ticket_id: str, *, note: str = '') -> bool:
        for i, t in enumerate(self._open):
            if t.get('ticket_id') == ticket_id:
                resolved = {**t, 'status': 'resolved', 'resolved_at': _utc_now(), 'note': note}
                self._open.pop(i)
                self._persist()
                self._append_jsonl(resolved)
                return True
        return False

    def blocking_global(self) -> List[Dict[str, Any]]:
        return [t for t in self._open if t.get('severity') == 'blocking']

    def _persist(self) -> None:
        write_json(self.open_path, {
            'schema_version': '1.0.0',
            'generated_at': _utc_now(),
            'tickets': self._open,
        })

    def _append_jsonl(self, ticket: Dict[str, Any]) -> None:
        self.jsonl_path.parent.mkdir(parents=True, exist_ok=True)
        existing = self.jsonl_path.read_text(encoding='utf-8') if self.jsonl_path.exists() else ''
        self.jsonl_path.write_text(existing + json.dumps(ticket, ensure_ascii=False) + '\n', encoding='utf-8')

    def format_console(self, ticket: Dict[str, Any]) -> str:
        lines = [
            '',
            '=' * 64,
            f"[MiniDrifter Ticket] {ticket.get('severity')} · {ticket.get('failure_class')}",
            '=' * 64,
            f"Layer: {ticket.get('layer')}  |  Resume: {ticket.get('resume_action')}",
            f"API: {ticket.get('evidence', {}).get('api')}",
            f"Diagnosis: {ticket.get('diagnosis')}",
            '',
            ticket.get('user_instruction') or '',
            '',
        ]
        ex = ticket.get('example_paths') or []
        if ex:
            lines.append('推荐抓包路径:')
            for p in ex[:5]:
                lines.append(f'  · {p}')
        mats = ticket.get('missing_materials') or []
        if mats:
            lines.append('')
            lines.append('缺失材料（深挖需要）:')
            for m in mats[:5]:
                field = m.get('field') or '?'
                why = m.get('why_needed') or m.get('capture_hint') or ''
                lines.append(f'  · {field}: {why[:100]}')
        if ticket.get('why_deeper_blocked'):
            lines.append('')
            lines.append(f"阻断原因: {ticket.get('why_deeper_blocked')[:200]}")
        lines.append(f"格式: {', '.join(ticket.get('accepted_formats') or [])}")
        if ticket.get('can_continue_other_chains'):
            lines.append('其他链路可继续；仅当前链/域暂停。')
        else:
            lines.append('建议暂停全局验证直至材料更新。')
        lines.append('=' * 64)
        return '\n'.join(lines)
