# -*- coding: utf-8 -*-
"""Account dynamic closed-loop — static → baseline → chain materialize → hop replay → M7 → verdict."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from minidrifter.core.utils import write_json
from minidrifter.runtime.source_dir import resolve_decompile_source_dir


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _log(stages: List[Dict[str, Any]], name: str, status: str, **extra: Any) -> None:
    stages.append({'stage': name, 'status': status, 'at': _utc_now(), **extra})


def _load_json(path: Path) -> Any:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding='utf-8'))


def _pack_has_static(pack_dir: Path) -> bool:
    return (pack_dir / 'api_card_pack_manifest.json').exists() or (pack_dir / 'all_api_cards.json').exists()


def _pack_has_chains(pack_dir: Path) -> bool:
    doc = _load_json(pack_dir / 'business_chains.json') or {}
    return bool(doc.get('chains'))


def _resolve_verify_mode(pack_dir: Path, *, chain_id: Optional[str] = None, verify_mode: Optional[str] = None) -> str:
    if verify_mode:
        return verify_mode
    if chain_id:
        return 'chain_strict'
    return 'campaign'


def _loop_state_from_verdict(verdict: Optional[str]) -> str:
    mapping = {
        'waiting_for_entry_capture': 'waiting_for_entry_capture',
        'chain_binding_drift': 'chain_binding_drift',
        'chain_completed_no_drift': 'chain_completed',
        'chain_blocked': 'chain_blocked',
        'preflight_blocked': 'preflight_blocked',
    }
    return mapping.get(verdict or '', 'completed')


def run_account_closed_loop(
    *,
    pack_dir: Path,
    project_root: Optional[Path] = None,
    capture_file: Optional[Path] = None,
    source_dir: Optional[Path] = None,
    skip_analyze: bool = False,
    mode: str = 'dry-run',
    max_http: int = 250,
    max_chains: int = 20,
    materialize: bool = True,
    verify: bool = True,
    chain_id: Optional[str] = None,
    with_llm: bool = False,
    force_materialize: bool = True,
    verify_mode: Optional[str] = None,
    beam_width: int = 8,
    campaign_source: str = 'rank_plan',
) -> Dict[str, Any]:
    """Closed-loop: analyze → batch intake → materialize → campaign verify → coverage report."""
    pack_dir = Path(pack_dir)
    pack_dir.mkdir(parents=True, exist_ok=True)
    stages: List[Dict[str, Any]] = []
    result: Dict[str, Any] = {
        'schema_version': '1.0.0',
        'generated_at': _utc_now(),
        'pack_dir': str(pack_dir),
        'flow': 'account_closed_loop',
        'stages': stages,
    }

    # --- Static analyze ---
    if project_root and not skip_analyze and not _pack_has_static(pack_dir):
        try:
            from minidrifter.pipeline import MiniDrifterPipeline
            from minidrifter.freezers.api_card import APICardFreezer
            pipe = MiniDrifterPipeline(str(project_root), str(pack_dir), 'wechat')
            prof = pipe.run().get('project_profile') or {}
            APICardFreezer.from_output_dir(str(pack_dir), top_k_evidence=200).write(pack_dir)
            _log(stages, 'static_analyze', 'ok', shape=prof.get('shape'))
        except Exception as exc:
            _log(stages, 'static_analyze', 'failed', error=str(exc))
            result['status'] = 'blocked'
            result['loop_state'] = 'blocked_no_static'
            result['error'] = str(exc)
            write_json(pack_dir / 'closed_loop_report.json', result)
            return result
    elif _pack_has_static(pack_dir):
        _log(stages, 'static_analyze', 'skipped', reason='pack_exists')
    else:
        _log(stages, 'static_analyze', 'skipped', reason='no_project_root')

    if not _pack_has_static(pack_dir):
        result['status'] = 'blocked'
        result['loop_state'] = 'blocked_no_static'
        result['error'] = 'no_static_pack'
        write_json(pack_dir / 'closed_loop_report.json', result)
        return result

    # --- Verify prepare ---
    try:
        from minidrifter.orchestration.workbench_run import _run_verify_prepare, _ensure_baseline_graph
        prep = _run_verify_prepare(pack_dir, with_llm=with_llm)
        _ensure_baseline_graph(pack_dir)
        from minidrifter.adapters.pack_resolver import write_adapter_resolution
        adapter = write_adapter_resolution(pack_dir)
        _log(stages, 'verify_prepare', 'ok', adapter=adapter.get('profile_id'))
        result['adapter_profile'] = adapter
    except Exception as exc:
        _log(stages, 'verify_prepare', 'warn', error=str(exc))

    src = resolve_decompile_source_dir(pack_dir, source_dir or project_root)

    # --- Crypto static extract ---
    try:
        from minidrifter.materials.intelligent_intake import ensure_crypto_static_profile
        crypto_doc = ensure_crypto_static_profile(pack_dir, source_dir=src)
        _log(
            stages, 'crypto_extract', 'ok',
            can_replay=crypto_doc.get('can_replay'),
            profile=(crypto_doc.get('crypto_static_profile') or {}).get('profile_id'),
        )
        result['crypto'] = crypto_doc
    except Exception as exc:
        _log(stages, 'crypto_extract', 'warn', error=str(exc))

    try:
        from minidrifter.orchestration.intake_prompts import write_user_input_artifacts
        from minidrifter.orchestration.project_dashboard import write_project_dashboard
        write_user_input_artifacts(pack_dir)
        write_project_dashboard(pack_dir, project_name=pack_dir.name)
    except Exception as exc:
        _log(stages, 'dashboard', 'warn', error=str(exc))

    # --- Baseline intake (single file append + batch directory merge) ---
    if capture_file and Path(capture_file).exists():
        from minidrifter.materials.intelligent_intake import run_intelligent_baseline_intake
        raw = Path(capture_file).read_text(encoding='utf-8', errors='replace')
        intake_result = run_intelligent_baseline_intake(
            pack_dir, raw,
            source_dir=src,
            source_label=str(capture_file),
            import_after=True,
            materialize_after=False,
        )
        _log(
            stages, 'intelligent_intake', intake_result.get('status', 'ok'),
            strategy=intake_result.get('verdict'),
            fields=(intake_result.get('baseline') or {}).get('field_count'),
        )
        result['intake'] = intake_result
        if intake_result.get('status') == 'blocked':
            result['status'] = 'blocked'
            result['loop_state'] = 'blocked_intake'
            result['next_action'] = 'refresh_baseline_capture'
            try:
                from minidrifter.verification.ticket_normalizer import emit_ticket, ticket_from_next_action
                emit_ticket(pack_dir, ticket_from_next_action(
                    'refresh_baseline_capture', pack_dir=pack_dir,
                ))
            except Exception:
                pass
            write_json(pack_dir / 'closed_loop_report.json', result)
            return result

    # Batch-scan baseline/ + CRBD_validation/trace only when single-file intake
    # did not already establish a runtime context (avoids double-parsing large HARs).
    if not (pack_dir / 'baseline_runtime_context.json').exists():
        try:
            from minidrifter.orchestration.console.workspace_layout import (
                default_workspace,
                project_layout,
            )
            from minidrifter.orchestration.console.baseline_batch import import_all_baseline_captures

            ws = default_workspace()
            proj_name = pack_dir.parent.name
            if (ws / proj_name).is_dir():
                layout = project_layout(ws, proj_name)
                ok, summary = import_all_baseline_captures(
                    layout, pack_dir, source_dir=src, materialize=False,
                )
                _log(
                    stages, 'baseline_batch_import', 'ok' if ok else 'warn',
                    capture_count=summary.get('capture_count'),
                    field_count=summary.get('field_count'),
                )
                result['baseline_batch'] = summary
        except Exception as exc:
            _log(stages, 'baseline_batch_import', 'warn', error=str(exc))
    else:
        _log(stages, 'baseline_batch_import', 'skipped', reason='context_already_present')

    ctx_path = pack_dir / 'baseline_runtime_context.json'
    if not ctx_path.exists():
        result['status'] = 'blocked'
        result['loop_state'] = 'blocked_no_baseline'
        result['next_action'] = 'provide_capture_file'
        try:
            from minidrifter.verification.ticket_normalizer import emit_ticket, ticket_from_next_action
            emit_ticket(pack_dir, ticket_from_next_action(
                'provide_capture_file', pack_dir=pack_dir,
            ))
        except Exception:
            pass
        write_json(pack_dir / 'closed_loop_report.json', result)
        return result

    ctx = _load_json(ctx_path) or {}

    # --- Chain-targeted materialize ---
    if materialize:
        try:
            from minidrifter.business_chain.chain_targets import run_chain_targeted_materialize
            mat = run_chain_targeted_materialize(
                pack_dir, ctx,
                chain_id=chain_id,
                limit=120,
                force=force_materialize,
            )
            _log(
                stages, 'chain_materialize', 'ok',
                summary=mat.get('summary'),
                chain_targets=len(mat.get('chain_target_api_ids') or []),
            )
            result['materialize'] = {
                'summary': mat.get('summary'),
                'chain_target_api_ids': mat.get('chain_target_api_ids'),
                'ready_for_replay': len(mat.get('ready_for_replay') or []),
            }
        except Exception as exc:
            _log(stages, 'chain_materialize', 'failed', error=str(exc))

    # --- Refresh business chains (post-materialize) ---
    try:
        from minidrifter.business_chain.export import refresh_business_chains_for_pack
        refresh_business_chains_for_pack(pack_dir)
        chains_doc = _load_json(pack_dir / 'business_chains.json') or {}
        _log(stages, 'business_chains', 'ok', chain_count=chains_doc.get('chain_count'))
    except Exception as exc:
        _log(stages, 'business_chains', 'warn', error=str(exc))

    # --- Dual-plane artifacts (runtime alias map from baseline captures) ---
    try:
        from minidrifter.quality.runtime_reachability import write_dual_plane_artifacts
        from minidrifter.business_chain.chain_intake import (
            build_chain_intake_checklist,
            render_chain_intake_prompt,
        )

        write_dual_plane_artifacts(pack_dir)
        checklist = build_chain_intake_checklist(pack_dir)
        prompt_path = pack_dir / 'chain_intake_prompt.md'
        prompt_path.write_text(render_chain_intake_prompt(pack_dir), encoding='utf-8')
        write_json(pack_dir / 'chain_intake_checklist.json', checklist)
        _log(stages, 'dual_plane_artifacts', 'ok')
    except Exception as exc:
        _log(stages, 'dual_plane_artifacts', 'warn', error=str(exc))

    verify_mode = _resolve_verify_mode(pack_dir, chain_id=chain_id, verify_mode=verify_mode)
    result['verify_mode'] = verify_mode

    # --- Campaign verify (breadth + depth) ---
    if verify:
        try:
            if verify_mode == 'campaign' and _pack_has_chains(pack_dir):
                from minidrifter.verification.chain_batch_runner import run_chain_batch_verification

                v = run_chain_batch_verification(
                    pack_dir,
                    mode=mode,
                    max_chains=max_chains,
                    max_http=max_http,
                    source_dir=src,
                    verbose=False,
                    campaign_source=campaign_source,
                )
                _log(
                    stages, 'chain_batch_verify', v.get('status', 'ok'),
                    chains_run=v.get('chains_run'),
                    http_calls=v.get('http_calls_total'),
                )
                result['verify'] = v
                result['verdict'] = v.get('verdict')
                result['coverage'] = v.get('coverage')
                result['loop_state'] = (
                    'chain_binding_drift' if v.get('verdict') == 'chain_binding_drift'
                    else 'chain_completed'
                )
            else:
                from minidrifter.orchestration.pipeline_runner import run_deep_verify

                v = run_deep_verify(
                    pack_dir,
                    mode=mode,
                    max_http=max_http,
                    max_seeds=max_chains,
                    beam_width=beam_width,
                    source_dir=src,
                    use_search=True,
                    search_mode='apex',
                    verify_mode=verify_mode,
                    chain_id=chain_id,
                    verbose=False,
                    skip_materialize=True,
                    force_materialize=False,
                )
                verdict = v.get('verdict') or (v.get('search_session') or {}).get('verdict')
                _log(stages, 'campaign_verify', v.get('status', 'ok'), verdict=verdict, verify_mode=verify_mode)
                result['verify'] = v
                result['verdict'] = verdict
                result['loop_state'] = _loop_state_from_verdict(verdict)
                result['coverage'] = v.get('coverage')

            from minidrifter.orchestration.binding_coverage_report import write_binding_coverage_report

            verify_doc = result.get('verify') or {}
            cov_path = write_binding_coverage_report(
                pack_dir,
                batch_results=verify_doc.get('chain_results'),
                search_session=verify_doc.get('search_session'),
                http_budget=max_http,
            )
            # chain_batch already wrote risk_coverage; re-merge from batch report if overwritten
            batch_doc = _load_json(pack_dir / 'chain_batch_report.json') or {}
            if batch_doc.get('risk_coverage'):
                merged = _load_json(cov_path) or {}
                merged['risk_coverage'] = batch_doc['risk_coverage']
                if batch_doc.get('risk_probe'):
                    merged['risk_probe'] = batch_doc['risk_probe']
                write_binding_coverage_report(pack_dir, merged)
            result['binding_coverage_report'] = str(cov_path)
            _log(stages, 'binding_coverage_report', 'ok')

            binding = _load_json(pack_dir / 'binding_verdict.json') or {}
            if binding.get('verdict') == 'waiting_for_entry_capture':
                chain_report = _load_json(pack_dir / 'chain_strict_report.json') or {}
                next_action = chain_report.get('next_action') or {}
                gaps = (_load_json(cov_path) or {}).get('deferred_material_gaps') or []
                if gaps:
                    result['next_action'] = 'review_deferred_material_gaps'
                    result['deferred_material_gaps'] = gaps
                else:
                    result['next_action'] = next_action.get('next_action') or 'review_deferred_material_gaps'
                result['loop_state'] = 'waiting_for_entry_capture'
                result['operator_prompt'] = str(pack_dir / 'chain_intake_prompt.md')
                result['expected_path'] = next_action.get('expected_path')
        except Exception as exc:
            _log(stages, 'campaign_verify', 'failed', error=str(exc))
            result['loop_state'] = 'chain_blocked'
            result['error'] = str(exc)
    else:
        result['loop_state'] = 'materialize_only'
        result['status'] = 'completed'

    if result.get('loop_state') in {'chain_completed', 'chain_binding_drift', 'materialize_only', 'completed'}:
        result['status'] = 'completed'
    elif result.get('loop_state') == 'waiting_for_entry_capture':
        result['status'] = 'waiting'
    elif not result.get('status'):
        result['status'] = result.get('loop_state', 'completed')

    write_json(pack_dir / 'closed_loop_report.json', result)
    return result


def resume_closed_loop_from_capture(
    pack_dir: Path,
    capture_text: str,
    *,
    source_label: str = 'closed_loop_resume',
    source_dir: Optional[Path] = None,
    mode: str = 'dry-run',
    chain_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Apply new capture then re-run materialize → chain_strict."""
    from minidrifter.materials.intelligent_intake import run_intelligent_baseline_intake

    pack_dir = Path(pack_dir)
    src = resolve_decompile_source_dir(pack_dir, source_dir)
    intake = run_intelligent_baseline_intake(
        pack_dir, capture_text,
        source_dir=src,
        source_label=source_label,
        import_after=True,
        materialize_after=False,
    )
    return run_account_closed_loop(
        pack_dir=pack_dir,
        source_dir=src,
        skip_analyze=True,
        mode=mode,
        materialize=True,
        verify=True,
        chain_id=chain_id,
        force_materialize=True,
    )
