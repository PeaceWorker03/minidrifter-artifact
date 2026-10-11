# -*- coding: utf-8
"""Workbench run — single entry: gate → analyze → prepare → intake → verify → report."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from minidrifter.core.utils import write_json
from minidrifter.orchestration.intake_prompts import write_user_input_artifacts
from minidrifter.orchestration.project_dashboard import write_project_dashboard
from minidrifter.orchestration.project_readiness import (
    check_decompile_readiness,
    check_pack_readiness,
)
from minidrifter.orchestration.workbench import (
    run_workbench_intake_prompt,
    run_workbench_scan,
)
from minidrifter.reasoning.acquisition_planner import build_acquisition_plan
from minidrifter.reasoning.erd import build_evidence_requirements, build_verification_panel
from minidrifter.reasoning.pack_loader import load_pack


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _log(stages: List[Dict[str, Any]], name: str, status: str, **extra: Any) -> None:
    rec = {'stage': name, 'status': status, 'at': _utc_now(), **{k: v for k, v in extra.items() if v is not None}}
    stages.append(rec)
    tail = ' '.join(f'{k}={v}' for k, v in extra.items() if v is not None)
    print(f'[MiniDrifter:workbench] [{name}] {status}' + (f' | {tail}' if tail else ''), flush=True)


def _pack_has_static(pack_dir: Path) -> bool:
    return (pack_dir / 'api_card_pack_manifest.json').exists() or (pack_dir / 'all_api_cards.json').exists()


def _run_verify_prepare(pack_dir: Path, *, with_llm: bool = False) -> Dict[str, Any]:
    pack = load_pack(pack_dir)
    panel = build_verification_panel(pack['cards'], pack['manifest'])
    write_json(pack_dir / 'verification_readiness_panel.json', panel)

    erd_path = pack_dir / 'evidence_requirements.json'
    if erd_path.exists():
        erd = json.loads(erd_path.read_text(encoding='utf-8'))
    else:
        erd = build_evidence_requirements(pack['cards'], pack['manifest'])
        write_json(erd_path, erd)

    plan = build_acquisition_plan(pack['cards'], pack['manifest'], erd.get('items'))
    write_json(pack_dir / 'acquisition_plan.json', plan)

    binding_risk = None
    try:
        from minidrifter.verification.binding_risk_planner import build_binding_risk_plan
        binding_risk = build_binding_risk_plan(
            pack_dir, with_llm=with_llm, dry_run=not with_llm,
        )
        try:
            from minidrifter.business_chain.export import refresh_business_chains_for_pack
            refresh_business_chains_for_pack(pack_dir)
        except Exception:
            pass
    except Exception as exc:
        binding_risk = {'status': 'error', 'error': str(exc)}

    try:
        from minidrifter.ir.export import export_universal_ir
        export_universal_ir(pack_dir)
    except Exception:
        pass

    if with_llm:
        try:
            from minidrifter.reasoning.acquisition_advisor import run_acquisition_advisor
            run_acquisition_advisor(pack_dir, limit=25, dry_run=False)
        except Exception as exc:
            return {'panel': panel, 'erd': erd, 'plan': plan, 'llm_warning': str(exc)}

    return {'panel': panel, 'erd': erd, 'plan': plan, 'binding_risk': binding_risk}


def _run_static_analyze(project_root: Path, pack_dir: Path) -> Dict[str, Any]:
    from minidrifter.pipeline import MiniDrifterPipeline
    from minidrifter.freezers.api_card import APICardFreezer

    pack_dir.mkdir(parents=True, exist_ok=True)
    pipe = MiniDrifterPipeline(str(project_root), str(pack_dir), 'wechat')
    res = pipe.run()
    freezer = APICardFreezer.from_output_dir(str(pack_dir), top_k_evidence=200)
    freezer.write(pack_dir)
    return {'pipeline': res.get('project_profile'), 'shape': (res.get('project_profile') or {}).get('shape')}


def _ensure_baseline_graph(pack_dir: Path) -> bool:
    """Generate baseline template + runtime graph if missing."""
    pack_dir = Path(pack_dir)
    if (pack_dir / 'baseline_material_template.json').exists():
        return True
    try:
        from minidrifter.materials.pipeline import (
            build_baseline_material_pipeline,
            write_baseline_material_pipeline,
        )

        pack = load_pack(pack_dir)
        erd_path = pack_dir / 'evidence_requirements.json'
        erd_items = json.loads(erd_path.read_text(encoding='utf-8')).get('items') if erd_path.exists() else None
        result = build_baseline_material_pipeline(
            pack['cards'], pack['manifest'], erd_items=erd_items, stage1_limit=120,
        )
        write_baseline_material_pipeline(pack_dir, result)
        return True
    except Exception as exc:
        import sys
        print(f'[MiniDrifter:workbench] baseline_graph failed: {exc}', file=sys.stderr, flush=True)
        return False


def _import_baseline_if_needed(pack_dir: Path) -> Optional[Dict[str, Any]]:
    ctx_path = pack_dir / 'baseline_runtime_context.json'
    if ctx_path.exists():
        return None
    mat_dir = pack_dir / 'user_materials'
    if not mat_dir.is_dir():
        return None
    http_files = sorted(mat_dir.glob('*.http')) + sorted(mat_dir.glob('*.txt'))
    if not http_files:
        return None
    from minidrifter.cli import cmd_import_baseline
    import argparse

    cmd_import_baseline(argparse.Namespace(
        input_dir=str(pack_dir),
        materials_dir=str(mat_dir),
        output=str(pack_dir),
    ))
    return {'imported_from': str(mat_dir), 'files': len(http_files)}


def run_workbench_pipeline(
    *,
    pack_dir: Path,
    project_root: Optional[Path] = None,
    workspace: Optional[Path] = None,
    source_dir: Optional[Path] = None,
    base_url: Optional[str] = None,
    skip_analyze: bool = False,
    skip_verify: bool = False,
    skip_materialize: bool = False,
    with_llm: bool = False,
    mode: str = 'dry-run',
    max_http: int = 250,
    max_seeds: int = 50,
    max_depth: int = 5,
    max_llm: int = 80,
    beam_width: int = 5,
    deep_think: bool = False,
    anchor_api_id: Optional[str] = None,
    i_know: bool = False,
    resume: bool = False,
    resume_file: Optional[Path] = None,
    force_resume: bool = False,
    verify_mode: str = 'apex',
    chain_id: Optional[str] = None,
) -> Dict[str, Any]:
    """End-to-end Workbench: prepare pack → user prompts → deep verify → report."""
    pack_dir = Path(pack_dir)
    pack_dir.mkdir(parents=True, exist_ok=True)
    stages: List[Dict[str, Any]] = []

    result: Dict[str, Any] = {
        'schema_version': '1.0.0',
        'generated_at': _utc_now(),
        'pack_dir': str(pack_dir),
        'stages': stages,
    }

    # 0. Optional workspace scan
    if workspace:
        scan_doc = run_workbench_scan(Path(workspace))
        _log(stages, 'scan', 'ok', projects=scan_doc.get('project_count'))
        result['workspace_scan'] = scan_doc
        if not project_root and scan_doc.get('projects'):
            best = next((p for p in scan_doc['projects'] if p.get('decompile_candidate')), scan_doc['projects'][0])
            project_root = Path(best['project_root'])
            _log(stages, 'project_pick', 'ok', project_id=best.get('project_id'))

    # 1. Decompile gate
    if project_root:
        gate = check_decompile_readiness(Path(project_root))
        _log(stages, 'gate_decompile', 'ok' if gate.get('ready') else 'blocked', shape=gate.get('profile', {}).get('shape'))
        result['decompile_gate'] = gate
        if not gate.get('ready') and not _pack_has_static(pack_dir):
            result['status'] = 'blocked'
            result['blockers'] = gate.get('blockers')
            write_json(pack_dir / 'workbench_run_report.json', result)
            return result

    # 2. Static analyze + freeze
    if project_root and not skip_analyze and not _pack_has_static(pack_dir):
        try:
            prof = _run_static_analyze(Path(project_root), pack_dir)
            _log(stages, 'static_analyze', 'ok', shape=prof.get('shape'))
        except Exception as exc:
            _log(stages, 'static_analyze', 'failed', error=str(exc))
            if not _pack_has_static(pack_dir):
                result['status'] = 'blocked'
                result['error'] = str(exc)
                write_json(pack_dir / 'workbench_run_report.json', result)
                return result
    elif _pack_has_static(pack_dir):
        _log(stages, 'static_analyze', 'skipped', reason='pack_exists')
    else:
        _log(stages, 'static_analyze', 'skipped', reason='no_project_root')

    if not _pack_has_static(pack_dir):
        _log(stages, 'pack_check', 'failed', reason='no_api_cards')
        result['status'] = 'blocked'
        result['blockers'] = [{'code': 'no_static_pack', 'message': 'Run with --project or existing pack dir'}]
        write_json(pack_dir / 'workbench_run_report.json', result)
        return result

    # 3. ERD + acquisition plan
    try:
        prep = _run_verify_prepare(pack_dir, with_llm=with_llm)
        inv = (prep.get('erd') or {}).get('erd_inventory') or {}
        _log(
            stages, 'verify_prepare', 'ok',
            cards=(prep.get('erd') or {}).get('card_count'),
            stage1=(prep.get('plan') or {}).get('plan_summary', {}).get('stage_1_target_count'),
            n0_binding=inv.get('operation_with_binding_check'),
        )
    except Exception as exc:
        _log(stages, 'verify_prepare', 'failed', error=str(exc))
        prep = {}

    # 4. Baseline graph template
    if _ensure_baseline_graph(pack_dir):
        _log(stages, 'baseline_graph', 'ok')
    else:
        _log(stages, 'baseline_graph', 'skipped')

    try:
        from minidrifter.materials.baseline_capture_requirements import write_baseline_capture_requirements
        write_baseline_capture_requirements(pack_dir)
        _log(stages, 'baseline_capture_requirements', 'ok')
    except Exception as exc:
        _log(stages, 'baseline_capture_requirements', 'failed', error=str(exc))

    # 5. Import baseline from user_materials if needed
    imp = _import_baseline_if_needed(pack_dir)
    if imp:
        _log(stages, 'import_baseline', 'ok', files=imp.get('files'))

    pack_gate = check_pack_readiness(pack_dir)
    result['pack_readiness'] = pack_gate

    # 6. Dashboard + intake
    from minidrifter.orchestration.console.workspace_layout import ensure_baseline_for_pack

    layout = ensure_baseline_for_pack(pack_dir)
    dash_paths = write_project_dashboard(pack_dir, project_name=pack_dir.name)
    run_workbench_intake_prompt(pack_dir)
    _log(stages, 'dashboard', 'ok', json=dash_paths.get('json'))
    result['dashboard'] = dash_paths
    result['baseline_dir'] = str(layout.baseline_dir)

    if not pack_gate.get('ready_for_live_verify') and mode == 'execute':
        _log(stages, 'live_verify', 'blocked', reason='missing_baseline')
        result['status'] = 'needs_materials'
        result['next_action'] = {
            'action': 'paste_chain_captures',
            'baseline_dir': str(layout.baseline_dir),
            'files': [
                str(pack_dir / 'baseline_capture_requirements.md'),
                str(pack_dir / 'chain_intake_prompt.md'),
                str(pack_dir / 'chain_intake_checklist.json'),
                str(pack_dir / 'chain_material_request_plan.json'),
                str(pack_dir / 'material_requirements.json'),
            ],
            'command': (
                f'python -m minidrifter.cli workbench resume -i {pack_dir} '
                f'-f {layout.baseline_dir / "capture_full.har"} --import-after --bootstrap-after'
            ),
        }
        write_json(pack_dir / 'workbench_run_report.json', result)
        return result

    if skip_verify:
        _log(stages, 'live_verify', 'skipped')
        result['status'] = 'prepared'
        result['next_action'] = {
            'action': 'provide_baseline_captures',
            'baseline_dir': str(layout.baseline_dir),
            'files': [str(pack_dir / 'baseline_capture_requirements.md')],
            'command': (
                f'python -m minidrifter.cli workbench resume -i {pack_dir} '
                f'-f {layout.baseline_dir / "capture_full.har"} --import-after --bootstrap-after'
            ),
        }
        write_json(pack_dir / 'workbench_run_report.json', result)
        return result

    if mode == 'execute' and not i_know:
        result['status'] = 'blocked'
        result['blockers'] = [{'code': 'i_know_required', 'message': 'Live execute requires i_know=True / --i-know'}]
        write_json(pack_dir / 'workbench_run_report.json', result)
        return result

    # P3: resume — apply capture, reconcile tickets, continue verify
    resume_checkpoint = None
    if resume or resume_file:
        from minidrifter.verification.resume_manager import (
            auto_resume_from_capture_file,
            prepare_verify_resume,
        )
        if resume_file and Path(resume_file).exists():
            _log(stages, 'resume', 'applying_capture', file=str(resume_file))
            auto_resume_from_capture_file(pack_dir, Path(resume_file))
            result['resume_capture'] = str(resume_file)
        resume_checkpoint = prepare_verify_resume(
            pack_dir,
            dismiss_chain_tickets=True,
            force_clear_global=force_resume,
        )
        _log(
            stages, 'resume', 'ok',
            open_tickets=resume_checkpoint.get('open_tickets'),
            can_continue=resume_checkpoint.get('can_continue'),
        )
        result['resume_checkpoint'] = resume_checkpoint
        if not resume_checkpoint.get('can_continue') and not force_resume:
            result['status'] = 'blocked'
            result['blockers'] = [{'code': 'global_ticket', 'message': 'Refresh baseline or use --force-resume after capture'}]
            write_json(pack_dir / 'workbench_run_report.json', result)
            return result

    # 7. Deep verify
    from minidrifter.orchestration.pipeline_runner import run_deep_verify

    _log(stages, 'live_verify', 'running', mode=mode, max_http=max_http)
    verify = run_deep_verify(
        pack_dir,
        source_dir=source_dir or project_root,
        base_url=base_url,
        mode=mode,
        with_llm=with_llm,
        deep_think=deep_think,
        with_llm_chain=with_llm or deep_think,
        max_http=max_http,
        max_seeds=max_seeds,
        max_depth=max_depth,
        max_llm=max_llm,
        beam_width=beam_width,
        skip_materialize=skip_materialize,
        anchor_api_id=anchor_api_id,
        verbose=True,
        resume_mode=bool(resume or resume_file or force_resume),
        verify_mode=verify_mode,
        chain_id=chain_id,
    )
    result['verify'] = verify
    result['status'] = verify.get('status', 'completed')
    result['verdict'] = verify.get('verdict')
    result['executive_summary'] = verify.get('executive_summary')

    ss = verify.get('search_session') or {}
    cov = ss.get('coverage') or verify.get('coverage') or {}
    _log(
        stages, 'live_verify', verify.get('status', 'completed'),
        verdict=verify.get('verdict'),
        http_calls=cov.get('http_calls'),
        findings=cov.get('findings_confirmed'),
        beam_chains=cov.get('beam_chains'),
        stop_reason=ss.get('stop_reason'),
    )

    # Refresh dashboard after verify
    write_project_dashboard(pack_dir, project_name=pack_dir.name)
    write_json(pack_dir / 'workbench_run_report.json', result)
    return result
