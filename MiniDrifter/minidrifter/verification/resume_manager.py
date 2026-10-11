# -*- coding: utf-8
"""Resume verification after user resolves tickets."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from minidrifter.core.utils import write_json
from minidrifter.verification.user_ticket import TicketRegistry

RESUME_STEPS = (
    'apply_capture',
    'import_baseline',
    'rematerialize_templates',
    'refresh_business_chains',
    'continue_chain_strict',
    'revive_quarantined_chains',
    'continue_search',
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _load_json(path: Path) -> Any:
    if path.exists():
        return json.loads(path.read_text(encoding='utf-8'))
    return None


def baseline_fingerprint(pack_dir: Path) -> str:
    ctx = _load_json(Path(pack_dir) / 'baseline_runtime_context.json') or {}
    return str(ctx.get('generated_at') or ctx.get('baseline_hash') or '')


def prepare_verify_resume(
    pack_dir: Path,
    *,
    dismiss_chain_tickets: bool = True,
    force_clear_global: bool = False,
) -> Dict[str, Any]:
    """Before --resume verify: reconcile tickets vs baseline freshness, reset circuits hint."""
    pack_dir = Path(pack_dir)
    registry = TicketRegistry(pack_dir)
    baseline_at = baseline_fingerprint(pack_dir)
    prev_session = _load_json(pack_dir / 'search_session.json') or {}

    resolved: List[str] = []
    remaining = list(registry._open)

    for ticket in list(registry._open):
        tid = ticket.get('ticket_id', '')
        sev = ticket.get('severity')
        fc = ticket.get('failure_class')
        ticket_at = ticket.get('generated_at') or ''

        if sev == 'blocking' and fc == 'auth_expired':
            if force_clear_global or (baseline_at and baseline_at > ticket_at):
                registry.resolve(tid, note='baseline_refreshed')
                resolved.append(tid)
            continue

        if dismiss_chain_tickets and sev == 'chain_blocking':
            registry.resolve(tid, note='resume_dismiss_chain')
            resolved.append(tid)

    checkpoint = {
        'schema_version': '1.0.0',
        'generated_at': _utc_now(),
        'baseline_fingerprint': baseline_at,
        'prior_stop_reason': prev_session.get('stop_reason'),
        'prior_http': (prev_session.get('budget') or {}).get('used_http'),
        'resolved_tickets': resolved,
        'open_tickets': len(registry._open),
        'can_continue': not registry.blocking_global() or force_clear_global,
    }
    write_json(pack_dir / 'search_checkpoint.json', checkpoint)

    # Reset circuit breaker state for fresh resume attempt
    circuits_path = pack_dir / 'apex_circuits.json'
    if circuits_path.exists() and (resolved or force_clear_global):
        doc = _load_json(circuits_path) or {}
        doc['counts'] = {}
        doc['open'] = {}
        doc['pause_execute'] = False
        doc['resume_cleared_at'] = _utc_now()
        write_json(circuits_path, doc)

    return checkpoint


def build_resume_plan(pack_dir: Path, ticket: Dict[str, Any]) -> Dict[str, Any]:
    action = ticket.get('resume_action') or 'refresh_baseline_and_continue'
    steps: List[Dict[str, Any]] = [
        {'step': 'apply_capture', 'action': 'intake-baseline --import-after'},
    ]
    if action in ('refresh_baseline_and_continue', 'repair_schema_and_continue'):
        steps.append({'step': 'import_baseline', 'action': 'merge baseline_runtime_context.json'})
        steps.append({'step': 'rematerialize_templates', 'action': 'chain-targeted materialize --force'})
        steps.append({'step': 'refresh_business_chains', 'action': 'refresh_business_chains_for_pack'})
    if action == 'acquire_object_and_continue':
        steps.append({'step': 'update_object_pool', 'action': 'harvest fields from new capture'})
        steps.append({'step': 'refresh_business_chains', 'action': 'refresh_business_chains_for_pack'})
    if action in ('revise_graph_and_continue', 'switch_domain_and_continue'):
        steps.append({'step': 'revive_quarantined_chains', 'action': 'beam.try_revive_all'})
    steps.append({'step': 'continue_chain_strict', 'action': 'run-closed-loop --skip-analyze'})
    steps.append({'step': 'continue_search', 'action': 'workbench run --resume --verify-mode chain_strict'})
    return {
        'schema_version': '1.0.0',
        'generated_at': _utc_now(),
        'ticket_id': ticket.get('ticket_id'),
        'resume_action': action,
        'steps': steps,
    }


def _resolve_source_dir(pack_dir: Path, source_dir: Optional[Path] = None) -> Optional[Path]:
    if source_dir and Path(source_dir).is_dir():
        return Path(source_dir)
    sess = _load_json(Path(pack_dir) / 'MiniDrifter_console_session.json') or {}
    for key in ('source_dir', 'project_root'):
        p = sess.get(key)
        if p and Path(p).is_dir():
            return Path(p)
    ws_parent = Path(pack_dir).parent.parent
    project_id = Path(pack_dir).name
    candidate = ws_parent / project_id
    if candidate.is_dir():
        return candidate
    return None


def apply_ticket_resolution(
    pack_dir: Path,
    ticket_id: str,
    raw_http: str,
    *,
    source_label: str = 'user_resume',
    source_dir: Optional[Path] = None,
    rematerialize: bool = True,
) -> Dict[str, Any]:
    """Full resume pipeline after user pastes capture."""
    from minidrifter.materials.baseline_intake import build_intake_report

    pack_dir = Path(pack_dir)
    src = _resolve_source_dir(pack_dir, source_dir)
    registry = TicketRegistry(pack_dir)
    ticket = next((t for t in registry._open if t.get('ticket_id') == ticket_id), None)
    if not ticket:
        open_doc = _load_json(pack_dir / 'blocking_tickets.json') or {}
        ticket = next((t for t in open_doc.get('tickets') or [] if t.get('ticket_id') == ticket_id), {})

    report = build_intake_report(
        raw_http, pack_dir, source_label=source_label, source_dir=src,
        source_path=Path(source_label) if source_label else None,
    )
    write_json(pack_dir / 'baseline_intake_report.json', report)

    resolved_fields: List[str] = []
    agg = report.get('decrypted_fields_aggregate') or {}
    resolved_fields.extend((agg.get('fields') or {}).keys())
    for cap in report.get('captures') or []:
        harvest = cap.get('object_harvest') or {}
        resolved_fields.extend(harvest.get('produced_fields') or [])

    missing_before = list(ticket.get('missing_fields') or []) if ticket else []
    revived_chains: List[str] = []
    if missing_before:
        from minidrifter.verification.field_to_blocked_hops import clear_field_blocks, chains_blocked_by_fields
        for field in missing_before:
            revived_chains.extend(clear_field_blocks(pack_dir, [field]))
        revived_chains = list(dict.fromkeys(revived_chains))
    elif resolved_fields:
        from minidrifter.verification.field_to_blocked_hops import chains_blocked_by_fields
        revived_chains = chains_blocked_by_fields(pack_dir, resolved_fields)

    plan = build_resume_plan(pack_dir, ticket or {'resume_action': 'refresh_baseline_and_continue'})
    if revived_chains:
        plan['revive_chain_ids'] = revived_chains
        plan['partial_resume'] = True
    result: Dict[str, Any] = {
        'intake': report,
        'plan': plan,
        'steps_done': ['apply_capture'],
        'revived_chains': revived_chains,
    }

    try:
        from minidrifter.cli import cmd_import_baseline
        import argparse

        mat_dir = pack_dir / 'user_materials'
        mat_dir.mkdir(parents=True, exist_ok=True)
        from minidrifter.materials.har_sequence import looks_like_har
        ext = '.har' if looks_like_har(raw_http) else '.http'
        cap_path = mat_dir / f'resume_{ticket_id[:24]}{ext}'
        cap_path.write_text(raw_http, encoding='utf-8')

        if looks_like_har(raw_http):
            from minidrifter.materials.intelligent_intake import run_intelligent_baseline_intake
            run_intelligent_baseline_intake(
                pack_dir, raw_http, source_dir=src,
                source_label=str(cap_path), import_after=True,
            )
        else:
            cmd_import_baseline(argparse.Namespace(
                input_dir=str(pack_dir),
                materials_dir=str(mat_dir),
                output=str(pack_dir),
                intake_report=str(pack_dir / 'baseline_intake_report.json'),
            ))
        result['steps_done'].append('import_baseline')

        if rematerialize:
            import json
            ctx_path = pack_dir / 'baseline_runtime_context.json'
            ctx = json.loads(ctx_path.read_text(encoding='utf-8')) if ctx_path.exists() else {}
            intake_report = _load_json(pack_dir / 'baseline_intake_report.json')
            from minidrifter.business_chain.chain_targets import run_chain_targeted_materialize
            run_chain_targeted_materialize(
                pack_dir, ctx,
                limit=120,
                force=True,
                intake_report=intake_report,
            )
            result['steps_done'].append('rematerialize_templates')
            try:
                from minidrifter.business_chain.export import refresh_business_chains_for_pack
                refresh_business_chains_for_pack(pack_dir)
                result['steps_done'].append('refresh_business_chains')
            except Exception as exc:
                result['chain_refresh_error'] = str(exc)
    except BaseException as exc:
        result['import_error'] = str(exc)

    if ticket_id:
        registry.resolve(ticket_id, note='capture_applied')
    try:
        from minidrifter.verification.ticket_normalizer import write_operator_request_md
        write_operator_request_md(pack_dir)
    except Exception:
        pass
    prepare_verify_resume(pack_dir, dismiss_chain_tickets=True, force_clear_global=False)
    write_json(pack_dir / 'resume_plan.json', plan)
    result['checkpoint'] = _load_json(pack_dir / 'search_checkpoint.json')
    return result


def auto_resume_from_capture_file(
    pack_dir: Path,
    capture_file: Path,
    *,
    ticket_id: Optional[str] = None,
    source_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    """One-shot: paste capture → import → rematerialize → prepare checkpoint."""
    raw = Path(capture_file).read_text(encoding='utf-8', errors='replace')
    pack_dir = Path(pack_dir)
    registry = TicketRegistry(pack_dir)
    tid = ticket_id
    if not tid:
        global_t = registry.blocking_global()
        tid = global_t[0].get('ticket_id') if global_t else None
        if not tid and registry._open:
            tid = registry._open[-1].get('ticket_id')
    if not tid:
        tid = 'manual_resume'
    return apply_ticket_resolution(
        pack_dir, tid, raw, source_label=str(capture_file), source_dir=source_dir,
    )
