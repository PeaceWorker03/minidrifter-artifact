# -*- coding: utf-8 -*-
"""P4-fix-4 — sensitive API replay with capture context inheritance + fallback."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, List, Optional

from minidrifter.business_chain.chain_run_context import load_json
from minidrifter.materials.intake_param_hints import load_intake_report, normalize_api_path
from minidrifter.verification.campaign_planner import build_test_case
from minidrifter.verification.chain_strict_runner import HOP_STATUS_OK
from minidrifter.verification.executor import execute_test_case
from minidrifter.verification.hop_policy import inherit_baseline_params
from minidrifter.verification.response_oracle import analyze_response
from minidrifter.verification.sensitive_read_metrics import attach_sensitive_read_metrics
from minidrifter.verification.sensitive_replay_context_builder import (
    lookup_replay_context,
    write_sensitive_replay_context,
)

REPLAY_STRATEGIES = (
    'exact_capture_replay',
    'template_with_capture_context',
    'template_only',
)


def _merged_baseline_context(
    baseline_context: Dict[str, Any],
    replay_ctx: Dict[str, Any],
) -> Dict[str, Any]:
    ctx = deepcopy(baseline_context)
    inner = replay_ctx.get('replay_context') or {}
    pool = inner.get('pool') or {}
    resolved = dict(ctx.get('resolved_fields') or {})
    for k, v in pool.items():
        resolved[k] = {'value': v, 'source': 'sensitive_replay_context', 'status': 'resolved'}
    ctx['resolved_fields'] = resolved
    if inner.get('transport_style'):
        ctx['transport_style'] = inner['transport_style']
    return ctx


def _build_test_from_context(
    template: Dict[str, Any],
    *,
    baseline_context: Dict[str, Any],
    replay_ctx: Dict[str, Any],
    strategy: str,
    probe_role: str,
    index: int,
) -> Dict[str, Any]:
    inner = replay_ctx.get('replay_context') or {}
    tc = build_test_case(template, baseline_context=baseline_context, index=index)
    tc['test_stage'] = f'{probe_role}_{strategy}'
    tc['replay_strategy'] = strategy

    pool_overlay = dict(inner.get('pool') or {})
    pool_overlay.update(inner.get('environment_fields') or {})
    tc['chain_param_pool'] = pool_overlay

    method = str(
        inner.get('http_method')
        or (template.get('plain_template') or {}).get('method')
        or 'GET'
    ).upper()
    query = dict(inner.get('query') or {})
    body = dict(inner.get('body') or {})

    if strategy == 'exact_capture_replay':
        if method == 'GET' or query:
            tc['params'] = query
            tc['body_params'] = body if body else {}
        else:
            tc['body_params'] = body
            tc['params'] = {}
        tc['method'] = method
        plain = dict(template.get('plain_template') or {})
        plain['method'] = method
        tc['plain_template'] = plain
    elif strategy == 'template_with_capture_context':
        plain = template.get('plain_template') or {}
        merged_body = dict(plain.get('body_params') or {})
        merged_body.update(body)
        merged_params = dict(plain.get('params') or {})
        merged_params.update(query)
        tc['body_params'] = merged_body
        tc['params'] = merged_params
    # template_only: keep template defaults; pool overlay still applied via chain_param_pool

    capture_headers = inner.get('headers') or {}
    if capture_headers:
        ht = dict(template.get('http_template') or {})
        ht['headers'] = {**(ht.get('headers') or {}), **capture_headers}
        tc['http_template'] = ht

    return tc


def _baseline_intake_evidence(
    path: str,
    *,
    intake: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    norm = normalize_api_path(path)
    for cap in intake.get('captures') or []:
        if normalize_api_path(cap.get('path') or '') != norm:
            continue
        if not str(cap.get('overall_status') or '').startswith('acceptable'):
            continue
        body = (cap.get('response_crypto_processing') or {}).get('body_json')
        if not body or not isinstance(body, dict):
            continue
        return {
            'capture_index': cap.get('capture_index'),
            'body_json': body,
            'overall_status': cap.get('overall_status'),
        }
    return None


def replay_sensitive_m0_for_override(
    cand: Dict[str, Any],
    *,
    pack_dir: Path,
    baseline_context: Dict[str, Any],
    templates_by_id: Dict[str, Dict[str, Any]],
    mode: str = 'execute',
    source_dir: Optional[Path] = None,
    base_url: Optional[str] = None,
    preferred_strategy: Optional[str] = None,
    replay_context_doc: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Run M0 replay only — for subject override M0/M7 pair."""
    api_id = cand.get('api_id') or ''
    path = cand.get('path') or ''
    template = templates_by_id.get(api_id)
    if not template:
        return {'ok': False, 'reason': 'no_template'}

    intake = load_intake_report(pack_dir) or {}
    replay_ctx = lookup_replay_context(
        pack_dir, path, context_doc=replay_context_doc,
    ) or {'replay_context': {'pool': {}, 'body': {}, 'headers': {}}}
    inner = replay_ctx.get('replay_context') or {}
    preferred = preferred_strategy
    if inner.get('replay_mode') == 'plaintext_direct' and not preferred:
        preferred = 'exact_capture_replay'
    hop = {'api_id': api_id, 'path': path, 'role': 'subject_override', 'consumes': []}

    strategies: List[str] = []
    if preferred and preferred in REPLAY_STRATEGIES:
        strategies.append(preferred)
    strategies.extend(s for s in REPLAY_STRATEGIES if s not in strategies)

    last: Dict[str, Any] = {}
    for i, strategy in enumerate(strategies):
        attempt = _try_replay_strategy(
            strategy,
            template=template,
            baseline_context=baseline_context,
            replay_ctx=replay_ctx,
            pack_dir=pack_dir,
            hop=hop,
            intake=intake,
            mode=mode,
            source_dir=source_dir,
            base_url=base_url,
            probe_role='subject_override',
            index=9100 + i,
        )
        last = attempt
        analysis = attempt.get('analysis') or {}
        outcome = analysis.get('call_outcome')
        if outcome == HOP_STATUS_OK or (mode != 'execute' and outcome == 'dry_run_ok'):
            return {
                'ok': True,
                'strategy': strategy,
                'test_case': attempt.get('test_case'),
                'execution': attempt.get('execution'),
                'analysis': analysis,
                'http_calls': attempt.get('http_calls') or 0,
            }
    return {
        'ok': False,
        'reason': (last.get('analysis') or {}).get('call_outcome') or 'm0_failed',
        'http_calls': int(last.get('http_calls') or 0),
    }


def _try_replay_strategy(
    strategy: str,
    *,
    template: Dict[str, Any],
    baseline_context: Dict[str, Any],
    replay_ctx: Dict[str, Any],
    pack_dir: Path,
    hop: Dict[str, Any],
    intake: Dict[str, Any],
    mode: str,
    source_dir: Optional[Path],
    base_url: Optional[str],
    probe_role: str,
    index: int,
) -> Dict[str, Any]:
    merged_ctx = _merged_baseline_context(baseline_context, replay_ctx)
    tc = _build_test_from_context(
        template,
        baseline_context=merged_ctx,
        replay_ctx=replay_ctx,
        strategy=strategy,
        probe_role=probe_role,
        index=index,
    )
    tc = inherit_baseline_params(
        tc, hop, baseline_context=merged_ctx, intake_report=intake,
    )
    if mode == 'dry-run':
        return {
            'strategy': strategy,
            'mode': 'dry_run',
            'test_case': tc,
            'analysis': {'call_outcome': 'dry_run_ok'},
            'execution': {'executed': False, 'call_outcome': 'dry_run_ok'},
            'http_calls': 1,
        }

    ex = execute_test_case(
        tc, pack_dir=pack_dir, baseline_context=merged_ctx,
        mode=mode, source_dir=source_dir, base_url=base_url,
    )
    analysis = analyze_response(ex, tc, baseline_context=merged_ctx, pack_dir=pack_dir)
    return {
        'strategy': strategy,
        'mode': mode,
        'test_case': tc,
        'analysis': analysis,
        'execution': ex,
        'http_calls': 1 if ex.get('executed') is not False else 0,
    }


def replay_sensitive_api(
    cand: Dict[str, Any],
    *,
    pack_dir: Path,
    baseline_context: Dict[str, Any],
    templates_by_id: Dict[str, Dict[str, Any]],
    mode: str = 'dry-run',
    source_dir: Optional[Path] = None,
    base_url: Optional[str] = None,
    probe_role: str = 'sensitive_read',
    replay_context_doc: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Replay one sensitive API with context inheritance and evidence source tracking."""
    api_id = cand.get('api_id') or ''
    path = cand.get('path') or ''
    template = templates_by_id.get(api_id)
    if not template:
        return {
            'api_id': api_id,
            'path': path,
            'status': 'no_template',
            'evidence_source': None,
            'http_calls': 0,
        }

    intake = load_intake_report(pack_dir) or {}
    replay_ctx = lookup_replay_context(
        pack_dir, path, context_doc=replay_context_doc,
    ) or {'replay_context': {'pool': {}, 'body': {}, 'headers': {}}}
    inner = replay_ctx.get('replay_context') or {}
    preferred_strategy = 'exact_capture_replay' if inner.get('replay_mode') == 'plaintext_direct' else None

    hop = {
        'api_id': api_id,
        'path': path,
        'role': probe_role,
        'consumes': list((replay_ctx.get('replay_context') or {}).get('body') or {}),
    }

    attempts: List[Dict[str, Any]] = []
    http_calls = 0
    live_analysis: Optional[Dict[str, Any]] = None
    live_execution: Optional[Dict[str, Any]] = None
    winning_strategy: Optional[str] = None

    strategies: List[str] = []
    if preferred_strategy and preferred_strategy in REPLAY_STRATEGIES:
        strategies.append(preferred_strategy)
    strategies.extend(s for s in REPLAY_STRATEGIES if s not in strategies)

    for i, strategy in enumerate(strategies):
        if mode == 'execute' and http_calls > 0 and live_analysis:
            if live_analysis.get('call_outcome') == HOP_STATUS_OK:
                break
        attempt = _try_replay_strategy(
            strategy,
            template=template,
            baseline_context=baseline_context,
            replay_ctx=replay_ctx,
            pack_dir=pack_dir,
            hop=hop,
            intake=intake,
            mode=mode,
            source_dir=source_dir,
            base_url=base_url,
            probe_role=probe_role,
            index=9000 + i,
        )
        attempts.append({
            'strategy': strategy,
            'call_outcome': (attempt.get('analysis') or {}).get('call_outcome'),
            'build_status': (attempt.get('execution') or {}).get('build_status'),
        })
        http_calls += int(attempt.get('http_calls') or 0)
        analysis = attempt.get('analysis') or {}
        if analysis.get('call_outcome') == HOP_STATUS_OK:
            live_analysis = analysis
            live_execution = attempt.get('execution')
            winning_strategy = strategy
            break
        if mode != 'execute':
            live_analysis = analysis
            live_execution = attempt.get('execution')
            winning_strategy = strategy
            break
        live_analysis = analysis
        live_execution = attempt.get('execution')

    baseline_ev = _baseline_intake_evidence(path, intake=intake)
    m0_out = (live_analysis or {}).get('call_outcome')
    live_ok = m0_out == HOP_STATUS_OK

    row: Dict[str, Any] = {
        'api_id': api_id,
        'path': path,
        'status': 'm0_failed',
        'm0_outcome': m0_out,
        'm7_count': 0,
        'reached_m7': False,
        'findings': 0,
        'http_calls': http_calls,
        'probe_role': probe_role,
        'replay_attempts': attempts,
        'replay_strategy': winning_strategy,
        'capture_match_score': replay_ctx.get('capture_match_score'),
        'capture_index': replay_ctx.get('capture_index'),
        'evidence_source': None,
        'live_sensitive_read_m0_success': False,
        'baseline_sensitive_read_m0_success': False,
        'replay_failed_but_baseline_valid': False,
    }

    row = attach_sensitive_read_metrics(
        row,
        path=path,
        m0_analysis=live_analysis,
        m0_execution=live_execution,
    )

    if live_ok:
        row['evidence_source'] = 'replay' if winning_strategy != 'template_only' else 'live_campaign'
        if row.get('sensitive_read_m0_success'):
            row['status'] = 'live_m0_success'
            row['live_sensitive_read_m0_success'] = True
        else:
            row['status'] = 'm0_ok_no_sensitive'
    elif baseline_ev and not live_ok:
        row['replay_failed_but_baseline_valid'] = True
        row['evidence_source'] = 'baseline_intake'
        row['status'] = 'baseline_only'
        baseline_row = attach_sensitive_read_metrics(
            {
                'm0_outcome': HOP_STATUS_OK,
                'status': 'baseline_capture',
                'source': 'baseline_intake',
            },
            path=path,
            m0_analysis={'call_outcome': HOP_STATUS_OK},
            m0_execution={'body_json': baseline_ev['body_json'], 'status_code': 200},
        )
        if baseline_row.get('sensitive_read_m0_success'):
            row['baseline_sensitive_read_m0_success'] = True
            row['sensitive_read_m0_success'] = True
            row['sensitive_read_success'] = True
            row['sensitive_field_reads'] = baseline_row.get('sensitive_field_reads') or []
            row['sensitive_api'] = baseline_row.get('sensitive_api')
            row['replay_failed_but_baseline_valid'] = True

    return row


def ensure_sensitive_replay_context(pack_dir: Path) -> Dict[str, Any]:
    path = Path(pack_dir) / 'sensitive_replay_context.json'
    if path.exists():
        return load_json(path) or {}
    write_sensitive_replay_context(pack_dir)
    return load_json(path) or {}
