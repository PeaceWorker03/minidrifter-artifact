# -*- coding: utf-8 -*-
"""End-to-end deep verification pipeline orchestrator."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from minidrifter.core.utils import write_json
from minidrifter.materials.materialization_meta import check_materialization_stale
from minidrifter.verification.analysis_report import (
    build_verification_analysis_report,
    write_analysis_report,
)
from minidrifter.verification.campaign_runner import run_verification_campaign
from minidrifter.verification.replay_preflight import run_replay_preflight


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _load_json(path: Path) -> Any:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding='utf-8'))


def _stage_log(stages: List[Dict[str, Any]], name: str, status: str, **extra: Any) -> None:
    stages.append({
        'stage': name,
        'status': status,
        'at': _utc_now(),
        **extra,
    })
    extra_s = ' '.join(f'{k}={v}' for k, v in extra.items() if v is not None)
    line = f'[MiniDrifter:pipeline] [{name}] {status}'
    if extra_s:
        line = f'{line} | {extra_s}'
    print(line, flush=True)


def _append_run_log(pack_dir: Path, line: str) -> None:
    log_path = Path(pack_dir) / 'full_verification_run.log'
    existing = ''
    if log_path.exists():
        try:
            existing = log_path.read_text(encoding='utf-8')
        except UnicodeDecodeError:
            existing = log_path.read_text(encoding='utf-8', errors='replace')
    log_path.write_text(existing + line + '\n', encoding='utf-8')


def _materialize_if_needed(
    pack_dir: Path,
    ctx: Dict[str, Any],
    *,
    skip_materialize: bool,
    force_materialize: bool,
    stages: List[Dict[str, Any]],
) -> None:
    if skip_materialize:
        _stage_log(stages, 'materialize', 'skipped', reason='skip_materialize flag')
        return

    tpl_path = pack_dir / 'materialized_api_templates.json'
    existing = _load_json(tpl_path)
    stale = check_materialization_stale(pack_dir, existing_templates=existing, baseline_context=ctx)
    need_mat = force_materialize or not existing or stale.get('stale')
    if not need_mat:
        _stage_log(stages, 'materialize', 'skipped', reason='fresh')
        return

    try:
        from minidrifter.business_chain.chain_targets import run_chain_targeted_materialize

        intake_report = _load_json(pack_dir / 'baseline_intake_report.json')
        mat = run_chain_targeted_materialize(
            pack_dir, ctx,
            limit=120,
            force=force_materialize,
            intake_report=intake_report,
        )
        write_json(tpl_path, mat)
        _stage_log(stages, 'materialize', 'ok', summary=mat.get('summary'))
        try:
            from minidrifter.business_chain.export import refresh_business_chains_for_pack
            refresh_business_chains_for_pack(pack_dir)
            _stage_log(stages, 'business_chains', 'ok')
        except Exception as exc:
            _stage_log(stages, 'business_chains', 'skipped', error=str(exc))
    except Exception as exc:
        _stage_log(stages, 'materialize', 'failed', error=str(exc))


def run_deep_verify(
    pack_dir: Path,
    *,
    source_dir: Optional[Path] = None,
    base_url: Optional[str] = None,
    mode: str = 'dry-run',
    max_tests: int = 8,
    campaign_rounds: int = 2,
    with_llm: bool = False,
    llm_dry_run: bool = False,
    skip_materialize: bool = False,
    force_materialize: bool = False,
    live_preflight: bool = False,
    only_safe: bool = True,
    use_search: bool = True,
    max_http: int = 250,
    max_seeds: int = 50,
    max_depth: int = 5,
    max_llm: int = 80,
    ig_threshold: float = 0.25,
    ig_prune: bool = True,
    search_mode: str = 'apex',
    beam_width: int = 5,
    anchor_api_id: Optional[str] = None,
    verbose: bool = True,
    deep_think: bool = False,
    with_llm_chain: bool = False,
    resume_mode: bool = False,
    force_resume: bool = False,
    verify_mode: str = 'apex',
    chain_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Run materialize → preflight → Apex-PoC / PBWS search (or legacy campaign) → analysis report."""
    pack_dir = Path(pack_dir)
    stages: List[Dict[str, Any]] = []
    _append_run_log(
        pack_dir,
        f'[{_utc_now()}] run_deep_verify start mode={mode} use_search={use_search} search_mode={search_mode}',
    )

    result: Dict[str, Any] = {
        'schema_version': '1.0.0',
        'generated_at': _utc_now(),
        'pack_dir': str(pack_dir),
        'mode': mode,
        'use_search': use_search,
        'search_mode': search_mode,
        'stages': stages,
    }

    ctx_path = pack_dir / 'baseline_runtime_context.json'
    if not ctx_path.exists():
        _stage_log(stages, 'baseline_check', 'failed', reason='missing baseline_runtime_context.json')
        result['status'] = 'blocked'
        result['blockers'] = ['missing_baseline']
        return result

    ctx = _load_json(ctx_path)
    _materialize_if_needed(
        pack_dir, ctx,
        skip_materialize=skip_materialize,
        force_materialize=force_materialize,
        stages=stages,
    )

    preflight = run_replay_preflight(
        pack_dir,
        source_dir=source_dir,
        base_url=base_url,
        live_probe=live_preflight and mode == 'execute',
    )
    write_json(pack_dir / 'replay_preflight_report.json', preflight)
    _stage_log(
        stages, 'preflight',
        'ok' if preflight.get('ready') else 'blocked',
        ready=preflight.get('ready'),
        blockers=len(preflight.get('blockers') or []),
        warnings=len(preflight.get('warnings') or []),
    )

    if not preflight.get('ready') and mode == 'execute':
        report = build_verification_analysis_report(pack_dir, preflight=preflight)
        paths = write_analysis_report(pack_dir, report)
        result['status'] = 'preflight_blocked'
        result['preflight'] = preflight
        result['analysis_report'] = paths
        _append_run_log(pack_dir, f'[{_utc_now()}] preflight_blocked')
        return result

    if use_search:
        try:
            from minidrifter.ir.export import export_universal_ir
            export_universal_ir(pack_dir)
            _stage_log(stages, 'universal_ir', 'ok')
        except Exception as exc:
            _stage_log(stages, 'universal_ir', 'warn', error=str(exc))

        try:
            from minidrifter.runtime.crypto.static_emit import emit_crypto_static_profile
            prof = _load_json(pack_dir / 'project_profile.json') or {}
            src = Path(prof.get('project_root')) if prof.get('project_root') else source_dir
            if src and src.exists():
                emit_crypto_static_profile(pack_dir, source_dir=src)
                _stage_log(stages, 'crypto_static_profile', 'ok')
        except Exception as exc:
            _stage_log(stages, 'crypto_static_profile', 'warn', error=str(exc))

        _append_run_log(
            pack_dir,
            f'[{_utc_now()}] verify_mode={verify_mode} search_mode={search_mode} max_http={max_http}',
        )
        if verify_mode == 'chain_strict':
            from minidrifter.verification.chain_strict_runner import run_chain_strict_verification

            session = run_chain_strict_verification(
                pack_dir,
                mode=mode,
                chain_id=chain_id,
                source_dir=source_dir,
                base_url=base_url,
                only_safe=only_safe,
                skip_preflight=True,
                verbose=verbose,
            )
            stage_name = 'chain_strict_verify'
        elif verify_mode == 'campaign':
            from minidrifter.verification.chain_batch_runner import run_chain_batch_verification

            session = run_chain_batch_verification(
                pack_dir,
                mode=mode,
                max_chains=max_seeds,
                max_http=max_http,
                source_dir=source_dir,
                base_url=base_url,
                only_safe=only_safe,
                verbose=verbose,
            )
            stage_name = 'chain_batch_verify'
        elif search_mode == 'apex':
            from minidrifter.verification.adaptive_poc_search import run_adaptive_poc_search

            session = run_adaptive_poc_search(
                pack_dir,
                mode=mode,
                only_safe=only_safe,
                max_http=max_http,
                max_seeds=max_seeds,
                max_depth=max_depth,
                beam_width=beam_width,
                source_dir=source_dir,
                base_url=base_url,
                baseline_context=ctx,
                skip_preflight=True,
                with_mutations=True,
                with_llm_policy=with_llm,
                with_llm_chain=with_llm_chain or (deep_think and with_llm),
                deep_think=deep_think,
                llm_dry_run=llm_dry_run,
                max_llm=max_llm,
                ig_threshold=ig_threshold,
                ig_prune=ig_prune,
                anchor_api_id=anchor_api_id,
                verbose=verbose,
                resume_mode=resume_mode,
                force_resume=force_resume,
            )
            stage_name = 'apex_poc_search'
        else:
            from minidrifter.verification.search_controller import run_verification_search

            session = run_verification_search(
                pack_dir,
                mode=mode,
                only_safe=only_safe,
                max_http=max_http,
                max_seeds=max_seeds,
                max_depth=max_depth,
                source_dir=source_dir,
                base_url=base_url,
                baseline_context=ctx,
                skip_preflight=True,
                with_mutations=True,
                with_llm_strategy=with_llm,
                with_llm_workflow=with_llm,
                llm_dry_run=llm_dry_run,
                max_llm=max_llm,
                ig_threshold=ig_threshold,
                ig_prune=ig_prune,
            )
            stage_name = 'pbws_search'

        cov = session.get('coverage') or {}
        _stage_log(
            stages, stage_name, session.get('status', 'completed'),
            verdict=session.get('verdict'),
            http_calls=cov.get('http_calls'),
            seeds_retired=cov.get('seeds_retired') or cov.get('atomic_probed'),
            findings_confirmed=cov.get('findings_confirmed'),
            business_success=cov.get('business_success'),
            beam_chains=cov.get('beam_chains'),
        )
        report = build_verification_analysis_report(pack_dir, preflight=preflight)
        paths = write_analysis_report(pack_dir, report)

        result['status'] = session.get('status', report.get('verdict'))
        result['verdict'] = report.get('verdict')
        result['executive_summary'] = report.get('executive_summary')
        result['preflight'] = preflight
        result['search_session'] = session
        result['coverage'] = cov if cov else session.get('coverage')
        result['analysis_report'] = paths
        try:
            from minidrifter.orchestration.binding_coverage_report import write_binding_coverage_report

            cov_path = write_binding_coverage_report(
                pack_dir,
                batch_results=session.get('chain_results'),
                search_session=session,
                http_budget=max_http,
            )
            result['binding_coverage_report'] = str(cov_path)
            _stage_log(stages, 'binding_coverage_report', 'ok')
        except Exception as exc:
            _stage_log(stages, 'binding_coverage_report', 'warn', error=str(exc))
        _append_run_log(
            pack_dir,
            f'[{_utc_now()}] search done verdict={result.get("verdict")} '
            f'http={cov.get("http_calls")} seeds={cov.get("seeds_retired")} '
            f'findings={cov.get("findings_confirmed")}',
        )
        return result

    round_summaries: List[Dict[str, Any]] = []
    last_campaign: Dict[str, Any] = {}

    for rnd in range(1, max(1, campaign_rounds) + 1):
        rnd_max = max_tests + (rnd - 1) * 3
        rnd_llm = with_llm and (rnd >= 2 or mode == 'execute')
        camp = run_verification_campaign(
            pack_dir,
            mode=mode,
            only_safe=only_safe,
            max_tests=rnd_max,
            source_dir=source_dir,
            base_url=base_url,
            baseline_context=ctx,
            with_llm=rnd_llm,
            llm_dry_run=llm_dry_run,
        )
        cov = camp.get('coverage') or {}
        round_summaries.append({
            'round': rnd,
            'max_tests': rnd_max,
            'with_llm': rnd_llm,
            'coverage': cov,
        })
        last_campaign = camp
        _stage_log(
            stages, f'campaign_round_{rnd}', 'ok',
            business_success=cov.get('business_success'),
            executed=cov.get('tests_executed'),
        )
        if cov.get('business_success', 0) > 0 and rnd >= 2:
            break

    report = build_verification_analysis_report(
        pack_dir,
        preflight=preflight,
        campaign_rounds=round_summaries,
    )
    paths = write_analysis_report(pack_dir, report)

    result['status'] = report.get('verdict')
    result['preflight'] = preflight
    result['campaign_rounds'] = round_summaries
    result['coverage'] = last_campaign.get('coverage')
    result['next_action_plan'] = last_campaign.get('next_action_plan')
    result['analysis_report'] = paths
    result['verdict'] = report.get('verdict')
    result['executive_summary'] = report.get('executive_summary')
    return result
