# -*- coding: utf-8
"""MiniDrifter Console — unified terminal output format."""
from __future__ import annotations

import json
import textwrap
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

# ── Output format spec (Console UI v1) ─────────────────────────────────────
# [PANEL]   titled box for sections
# [STATUS]  OK | WARN | BLOCK | RUN | INFO
# [ARTIFACT] path + one-line description
# [TABLE]   aligned columns
# [TICKET]  HITL diagnostic card
# [FINDING] chain vulnerability summary
# [STAGE]   pipeline progress line

WIDTH = 72
STATUS_ICONS = {
    'OK': '[OK]',
    'WARN': '[!!]',
    'BLOCK': '[XX]',
    'RUN': '[>>]',
    'INFO': '[--]',
}


def _line(char: str = '-') -> str:
    return char * WIDTH


def panel(title: str, lines: Sequence[str], *, footer: Optional[str] = None) -> None:
    print('+' + _line('=') + '+')
    print(f'| {title}')
    print('+' + _line('-') + '+')
    for ln in lines:
        for wrap in textwrap.wrap(ln, width=WIDTH - 4) or ['']:
            print(f'| {wrap}')
    if footer:
        print('+' + _line('-') + '+')
        print(f'| {footer}')
    print('+' + _line('=') + '+')


def status(label: str, level: str = 'INFO') -> str:
    icon = STATUS_ICONS.get(level.upper(), '[--]')
    return f'{icon} {label}'


def artifact(path: str | Path, desc: str = '') -> None:
    p = str(path)
    print(f'  {status("ARTIFACT", "INFO")} {p}')
    if desc:
        print(f'       {desc}')


def table(headers: Sequence[str], rows: Sequence[Sequence[Any]], *, col_widths: Optional[List[int]] = None) -> None:
    if not rows:
        print('  (empty)')
        return
    widths = col_widths or []
    if not widths:
        for i, h in enumerate(headers):
            w = len(str(h))
            for row in rows:
                if i < len(row):
                    w = max(w, len(str(row[i])))
            widths.append(min(w + 2, 28))
    hdr = ''.join(str(h).ljust(widths[i]) for i, h in enumerate(headers))
    print(f'  {hdr}')
    print(f'  {_line("-")[:sum(widths)]}')
    for row in rows:
        cells = []
        for i, cell in enumerate(row):
            s = str(cell)[: widths[i] - 1]
            cells.append(s.ljust(widths[i]))
        print(f'  {"".join(cells)}')


def stage_line(name: str, st: str, **extra: Any) -> None:
    tail = ' '.join(f'{k}={v}' for k, v in extra.items() if v is not None)
    lvl = 'OK' if st in ('ok', 'completed', 'skipped') else ('BLOCK' if st in ('failed', 'blocked') else 'RUN')
    print(f'  {status(name, lvl)} {st}' + (f' | {tail}' if tail else ''))


def ticket_card(ticket: Dict[str, Any]) -> None:
    sev = ticket.get('severity') or '?'
    fc = ticket.get('failure_class') or '?'
    layer = ticket.get('layer') or '?'
    api = (ticket.get('evidence') or {}).get('api') or '?'
    lines = [
        f'Ticket: {ticket.get("ticket_id", "?")[:48]}',
        f'Severity: {sev}  |  Layer: {layer}  |  Class: {fc}',
        f'API: {api}',
        f'Diagnosis: {ticket.get("diagnosis") or "?"}',
        f'Action: {ticket.get("user_instruction") or ticket.get("resume_action") or "?"}',
    ]
    ex = ticket.get('example_paths') or []
    if ex:
        lines.append('Paths: ' + ', '.join(ex[:3]))
    if ticket.get('can_continue_other_chains'):
        lines.append('Other chains can continue.')
    panel(f'HITL Ticket · {fc}', lines)


def finding_card(report: Dict[str, Any]) -> None:
    narrative = report.get('binding_narrative') or report.get('finding_type') or '?'
    steps = report.get('evidence_steps') or []
    hop = ' → '.join(s.get('path', '?') for s in steps[:5])
    lines = [
        f'ID: {report.get("finding_id")}  |  Status: {report.get("status")}  |  Severity: {report.get("severity")}',
        f'Type: {report.get("finding_type")}',
        f'Narrative: {narrative}',
    ]
    if hop:
        lines.append(f'Chain: {hop}')
    for s in steps:
        if s.get('is_finding_step') or s.get('mutation_type') == 'M7_subject_object_mismatch':
            diff = (s.get('param_diff') or {}).get('changed_fields') or []
            rs = s.get('response_summary') or {}
            lines.append(
                f'Mutation {s.get("mutation_type")}: params={diff} binding={rs.get("binding_status")}'
            )
            break
    panel(f'Finding · {report.get("status", "?")}', lines)


def dashboard_summary(doc: Dict[str, Any]) -> None:
    rows = [
        ('Project', doc.get('project_name')),
        ('API cards', doc.get('api_card_count')),
        ('N0 / N1', f'{doc.get("n0_count")} / {doc.get("n1_count")}'),
        ('Crypto ready', doc.get('crypto_replay_ready')),
        ('Baseline', doc.get('has_baseline')),
        ('Stage-1 targets', doc.get('stage_1_targets')),
        ('Next', doc.get('recommended_next')),
    ]
    table(['Field', 'Value'], rows, col_widths=[18, 48])


def session_banner(session: Dict[str, Any]) -> None:
    lines = [
        f'Workspace : {session.get("workspace") or "(unset)"}',
        f'Project   : {session.get("project_root") or "(unset)"}',
        f'Pack dir  : {session.get("pack_dir") or "(unset)"}',
        f'Source    : {session.get("source_dir") or "(unset)"}',
        f'Mode      : {session.get("mode", "dry-run")}  |  LLM: {session.get("with_llm")}  |  Deep: {session.get("deep_think")}',
        f'Budget    : max_http={session.get("max_http", 250)}  anchor={session.get("anchor_api") or "-"}',
    ]
    panel('MiniDrifter Console · Account-aware ERD Chain Verification', lines)


def menu(title: str, items: Sequence[Tuple[str, str]]) -> None:
    print()
    print('+' + _line('=') + '+')
    print(f'| {title}')
    print('+' + _line('-') + '+')
    for key, label in items:
        print(f'|  [{key}] {label}')
    print('+' + _line('=') + '+')


def prompt_choice(hint: str = 'Select') -> str:
    try:
        return input(f'\n  {hint} > ').strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return '0'


def prompt_path(hint: str, default: str = '') -> str:
    suffix = f' [{default}]' if default else ''
    try:
        val = input(f'  {hint}{suffix}: ').strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return default
    return val or default


def confirm(msg: str) -> bool:
    try:
        ans = input(f'  {msg} [y/N]: ').strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    return ans in ('y', 'yes')


def write_finding_reports_md(pack_dir: Path, reports_doc: Dict[str, Any]) -> Path:
    """P4: human-readable chain finding report."""
    pack_dir = Path(pack_dir)
    lines = [
        '# MiniDrifter Chain Finding Reports',
        '',
        f'Generated: {reports_doc.get("generated_at")}',
        f'Confirmed: {reports_doc.get("confirmed_count")} | '
        f'Hypothesis: {reports_doc.get("hypothesis_count")} | '
        f'Rejected: {reports_doc.get("rejected_count")}',
        '',
    ]
    for r in reports_doc.get('reports') or []:
        lines.append(f'## {r.get("finding_id")} — {r.get("status")} ({r.get("severity")})')
        lines.append('')
        lines.append(r.get('binding_narrative') or '')
        lines.append('')
        for s in r.get('evidence_steps') or []:
            role = s.get('role') or s.get('test_stage') or '?'
            mut = s.get('mutation_type') or 'M0'
            rs = s.get('response_summary') or {}
            lines.append(
                f'- **{s.get("path")}** [{role}] {mut} → '
                f'{rs.get("call_outcome")} binding={rs.get("binding_status")}'
            )
        lines.append('')
    out = pack_dir / 'finding_chain_reports.md'
    out.write_text('\n'.join(lines), encoding='utf-8')
    return out


def load_json(path: Path) -> Any:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding='utf-8'))
