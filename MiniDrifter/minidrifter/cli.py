# -*- coding: utf-8 -*-
from __future__ import annotations
import argparse
from pathlib import Path
from minidrifter.pipeline import MiniDrifterPipeline
from minidrifter.optimizers.postprocess import StaticResultOptimizer, write_optimizer_outputs
from minidrifter.core.utils import write_json, write_text
import shutil
from minidrifter.reporting.summary import build_summary_json, build_summary_md
from minidrifter.freezers.api_card import APICardFreezer
from minidrifter.reasoning.erd import build_evidence_requirements, build_verification_panel
from minidrifter.reasoning.acquisition_planner import build_acquisition_plan
from minidrifter.reasoning.card_auditor import run_card_auditor_batch
from minidrifter.reasoning.acquisition_advisor import run_acquisition_advisor
from minidrifter.materials.pipeline import build_baseline_material_pipeline, write_baseline_material_pipeline


def cmd_analyze(args: argparse.Namespace) -> None:
    pipe = MiniDrifterPipeline(args.input, args.output, args.platform)
    res = pipe.run()
    summary = res.get('project_profile', {})
    opt = res.get('optimizer_outputs', {})
    counts = {
        'raw_api_calls': len(res.get('api_call_sites', [])),
        'raw_reached_cards': len(res.get('api_cards', {}).get('reached_api_cards', [])),
        'normalized_operations': len(opt.get('normalized_api_operations', [])),
        'business_operations': len(opt.get('business_api_operations', [])),
        'ranked_candidates': len(opt.get('ranked_api_candidates', [])),
    }
    print(f"[MiniDrifter] shape={summary.get('shape')} obfuscation={summary.get('obfuscation',{}).get('level')} counts={counts}")
    print(f"[MiniDrifter] outputs written to: {args.output}")


def cmd_paper_static(args: argparse.Namespace) -> None:
    """Rebuild paper §5.2.2–5.2.3 artifacts + scores on an existing OUTPUT pack."""
    from minidrifter.rpgraph.export import write_rpgraph_pack
    from minidrifter.quality.contract_score import write_contract_score
    from minidrifter.quality.workflow_score import write_workflow_score
    from minidrifter.quality.gates.static_acceptance import gate_static_acceptance
    from minidrifter.quality.models import QualityReport

    from minidrifter.optimizers.postprocess import repair_business_api_pool
    from minidrifter.quality.resolvers.host_pool import repair_noise_default_host

    pack = Path(args.input_dir)
    if not pack.exists():
        raise SystemExit(f'pack not found: {pack}')
    if repair_noise_default_host(pack):
        print('[MiniDrifter] repaired noise default_business_host → business_explicit pool')
    biz_fix = repair_business_api_pool(pack)
    if biz_fix.get('changed'):
        print(
            f"[MiniDrifter] repaired business pool: {biz_fix.get('before')} → {biz_fix.get('after')} "
            f"(removed {biz_fix.get('removed')} page/engine noise)"
        )
    # Migrate legacy ccr_pack.json → rcr_pack.json (paper: RCR)
    legacy_ccr, rcr_path = pack / 'ccr_pack.json', pack / 'rcr_pack.json'
    if legacy_ccr.exists() and not rcr_path.exists():
        import json as _json
        doc = _json.loads(legacy_ccr.read_text(encoding='utf-8'))
        if 'rcrs' not in doc and 'ccrs' in doc:
            doc['rcrs'] = doc['ccrs']
        doc['representation'] = 'Reference Contract Representation (RCR)'
        if 'rcr_count' not in doc and 'ccr_count' in doc:
            doc['rcr_count'] = doc['ccr_count']
        write_json(rcr_path, doc)
        print('[MiniDrifter] migrated ccr_pack.json -> rcr_pack.json')
    summary = write_rpgraph_pack(pack, max_workflows=int(args.max_workflows or 120))
    cscore = write_contract_score(pack)
    wscore = write_workflow_score(pack)
    report = QualityReport()
    report.summary['pack_id'] = pack.name
    acc = gate_static_acceptance(pack, report)
    write_json(pack / 'static_acceptance.json', acc)
    print('[MiniDrifter] paper-static (RCR -> RPGraph -> RR-Drift chains)')
    print(f"  chains={summary.get('workflow_count')} drift_plans={summary.get('drift_plan_count')}")
    print(f"  contract_score={cscore.get('score')}% workflow_score={wscore.get('score')}% (thr={wscore.get('threshold')})")
    print(f"  static_acceptance.passed={acc.get('passed')} hard_fails={acc.get('hard_fail_count')}")
    print(f"  pack={pack}")


def cmd_audit_pack(args: argparse.Namespace) -> None:
    from minidrifter.reasoning.pack_loader import load_pack

    pack = load_pack(args.input_dir)
    panel = build_verification_panel(pack['cards'], pack['manifest'])
    out = Path(args.output or args.input_dir)
    write_json(out / 'verification_readiness_panel.json', panel)
    funnel = panel.get('funnel') or {}
    print(f"[MiniDrifter] audit panel: total={funnel.get('total_cards')} p0={funnel.get('priority_p0')} fuzz_pass={funnel.get('fuzzing_gate_pass')} -> {out}")


def cmd_detect_requirements(args: argparse.Namespace) -> None:
    from minidrifter.reasoning.pack_loader import load_pack

    pack = load_pack(args.input_dir)
    erd = build_evidence_requirements(pack['cards'], pack['manifest'])
    out = Path(args.output or args.input_dir)
    write_json(out / 'evidence_requirements.json', erd)
    inv = erd.get('erd_inventory') or {}
    print(f"[MiniDrifter] evidence requirements: cards={erd.get('card_count')} ops_binding={inv.get('operation_with_binding_check')} -> {out}")
    print(f"[MiniDrifter] blocking histogram: {inv.get('blocking_missing_histogram')}")


def cmd_plan_acquisition(args: argparse.Namespace) -> None:
    from minidrifter.reasoning.pack_loader import load_pack

    pack = load_pack(args.input_dir)
    out = Path(args.output or args.input_dir)
    erd_path = out / 'evidence_requirements.json'
    if erd_path.exists():
        import json
        erd = json.loads(erd_path.read_text(encoding='utf-8'))
    else:
        erd = build_evidence_requirements(pack['cards'], pack['manifest'])
        write_json(out / 'evidence_requirements.json', erd)

    plan = build_acquisition_plan(pack['cards'], pack['manifest'], erd.get('items'))
    write_json(out / 'acquisition_plan.json', plan)

    from minidrifter.orchestration.project_dashboard import write_project_dashboard
    dash = write_project_dashboard(out, project_name=out.name)
    print(f"[MiniDrifter] dashboard -> {dash.get('json')}")

    summary = plan.get('plan_summary') or {}
    print(
        f"[MiniDrifter] acquisition plan: stage1={summary.get('stage_1_target_count')} "
        f"auto={summary.get('auto_discovery_count')} deferred={summary.get('deferred_count')} "
        f"materials={summary.get('material_package_count')} -> {out}"
    )

    if getattr(args, 'with_llm', False):
        result = run_acquisition_advisor(
            out,
            limit=args.limit,
            dry_run=args.dry_run,
        )
        print(
            f"[MiniDrifter] acquisition advisor: selected={result['selected']} "
            f"status={result.get('status')} plan={result.get('plan')}"
        )
        if result.get('validation_errors'):
            print(f"[MiniDrifter] advisor validation: {result['validation_errors'][:5]}")


def cmd_workbench_scan(args: argparse.Namespace) -> None:
    from minidrifter.orchestration.workbench import run_workbench_scan

    ws = Path(args.workspace)
    doc = run_workbench_scan(ws)
    print(f"[MiniDrifter] workspace scan: {doc.get('project_count')} projects under {ws}")
    for p in doc.get('projects') or []:
        flag = 'OK' if p.get('decompile_candidate') else 'SKIP'
        print(f"  [{flag}] {p.get('project_id')} shape={p.get('shape')} files={p.get('file_count')}")
    print(f"[MiniDrifter] -> {ws / 'MiniDrifter_workspace.json'}")


def cmd_workbench_gate(args: argparse.Namespace) -> None:
    from minidrifter.orchestration.project_readiness import check_decompile_readiness, check_pack_readiness

    if getattr(args, 'pack_dir', None):
        pack = Path(args.pack_dir)
        report = check_pack_readiness(pack)
        print(f"[MiniDrifter] pack readiness: static={report.get('ready_for_static_review')} live={report.get('ready_for_live_verify')}")
    else:
        root = Path(args.project)
        report = check_decompile_readiness(root)
        print(f"[MiniDrifter] decompile gate: ready={report.get('ready')} shape={report.get('profile', {}).get('shape')}")
    for b in report.get('blockers') or []:
        print(f"  BLOCKER: {b.get('message')}")
    for w in (report.get('warnings') or [])[:5]:
        print(f"  WARN: {w.get('message')}")


def cmd_workbench_intake_prompt(args: argparse.Namespace) -> None:
    from minidrifter.orchestration.workbench import run_workbench_intake_prompt
    from minidrifter.orchestration.intake_prompts import format_request_for_console

    pack = Path(args.input_dir)
    checklist = run_workbench_intake_prompt(pack)
    print(f"[MiniDrifter] user intake checklist: {len(checklist.get('steps') or [])} steps -> {pack / 'user_intake_checklist.json'}")
    print(checklist.get('summary'))
    for step in checklist.get('steps') or []:
        print(f"  Step {step.get('step')} [{step.get('phase')}]: {step.get('purpose')}")
        for p in step.get('example_paths') or []:
            print(f"    e.g. {p}")


def cmd_workbench_roadmap(args: argparse.Namespace) -> None:
    from minidrifter.orchestration.workbench import build_workbench_roadmap

    roadmap = build_workbench_roadmap(
        workspace=Path(args.workspace) if getattr(args, 'workspace', None) else None,
        project_root=Path(args.project) if getattr(args, 'project', None) else None,
        pack_dir=Path(args.input_dir) if getattr(args, 'input_dir', None) else None,
    )
    nxt = roadmap.get('next_user_action') or {}
    print(f"[MiniDrifter] roadmap next: {nxt.get('action')}")
    if nxt.get('command'):
        print(f"  {nxt.get('command')}")


def cmd_baseline_bootstrap(args: argparse.Namespace) -> None:
    import json
    from pathlib import Path

    from minidrifter.orchestration.baseline_bootstrap import run_baseline_bootstrap

    pack = Path(args.input_dir)
    baseline_dir = Path(args.baseline_dir) if getattr(args, 'baseline_dir', None) else None
    if baseline_dir is None:
        baseline_dir = pack.parent / 'baseline'
    if getattr(args, 'rescan', False):
        baseline_dir.mkdir(parents=True, exist_ok=True)
    result = run_baseline_bootstrap(
        pack,
        source_dir=Path(args.source_dir) if getattr(args, 'source_dir', None) else pack.parent,
        rescan_baseline_dir=baseline_dir if getattr(args, 'rescan', False) else None,
        materialize=not getattr(args, 'skip_materialize', False),
        rebuild_sensitive_context=not getattr(args, 'skip_rebuild_context', False),
        limit=getattr(args, 'limit', 120),
    )
    print(json.dumps({
        'steps_completed': result.get('steps_completed'),
        'errors': result.get('errors'),
        'readiness': result.get('readiness', {}).get('funnel'),
        'rates': result.get('readiness', {}).get('rates'),
        'artifacts': result.get('artifacts'),
    }, indent=2, ensure_ascii=False))


def cmd_workbench_resume(args: argparse.Namespace) -> None:
    from pathlib import Path

    pack = Path(args.input_dir)
    cap_path = Path(args.file)
    raw = cap_path.read_text(encoding='utf-8', errors='replace')
    ticket_id = getattr(args, 'ticket_id', None)
    import_after = getattr(args, 'import_after', False)

    if ticket_id:
        from minidrifter.verification.resume_manager import apply_ticket_resolution

        result = apply_ticket_resolution(pack, ticket_id, raw, source_label=str(cap_path))
        print(f"[MiniDrifter] ticket resolved: {ticket_id}")
        print(f"[MiniDrifter] steps_done: {result.get('steps_done')}")
        if result.get('import_error'):
            print(f"[MiniDrifter] import warning: {result['import_error']}")
        if result.get('revived_chains'):
            print(f"[MiniDrifter] revived chains: {result.get('revived_chains')}")
        print(f"[MiniDrifter] resume plan -> {pack / 'resume_plan.json'}")
        print(f"[MiniDrifter] operator_request -> {pack / 'operator_request.md'}")
        print(f"[MiniDrifter] next: python -m minidrifter.cli run-closed-loop -i {pack} --skip-analyze --resume-file {cap_path}")
        return

    from minidrifter.orchestration.operator_session import apply_user_capture

    result = apply_user_capture(pack, raw, source_label=str(cap_path), source_path=cap_path)
    har_meta = result.get('har_sequence') or {}
    print(f"[MiniDrifter] intake applied captures={result.get('intake', {}).get('capture_count')}")
    if result.get('is_har'):
        print(f"[MiniDrifter] HAR sequence entries={har_meta.get('entry_count', '?')}")
    if result.get('capture_sequence'):
        print(f"[MiniDrifter] capture_sequence -> {result.get('capture_sequence')}")
    if import_after:
        from minidrifter.materials.intelligent_intake import run_intelligent_baseline_intake
        ir = run_intelligent_baseline_intake(
            pack, raw, source_label=str(cap_path), import_after=True,
        )
        print(f"[MiniDrifter] import_after status={ir.get('status', 'ok')}")
    if getattr(args, 'bootstrap_after', False):
        from minidrifter.orchestration.baseline_bootstrap import run_baseline_bootstrap
        bs = run_baseline_bootstrap(
            pack,
            source_dir=pack.parent,
            rescan_baseline_dir=None,
            materialize=True,
            rebuild_sensitive_context=True,
        )
        print(f"[MiniDrifter] bootstrap steps={bs.get('steps_completed')}")
        if bs.get('errors'):
            print(f"[MiniDrifter] bootstrap errors={bs.get('errors')}")
        print(f"[MiniDrifter] readiness -> {pack / 'baseline_readiness_report.json'}")
    print(f"[MiniDrifter] next: python -m minidrifter.cli workbench resume -i {pack} -f {cap_path} --import-after --bootstrap-after")
    print(f"[MiniDrifter] tickets -> {pack / 'operator_request.md'}")


def cmd_ir_export(args: argparse.Namespace) -> None:
    from minidrifter.ir.export import export_universal_ir

    pack = Path(args.input_dir)
    bundle = export_universal_ir(pack, profile_id=getattr(args, 'profile', None))
    print(f"[MiniDrifter] universal IR exported -> {bundle.get('artifacts', {}).get('universal_ir_bundle')}")
    print(f"[MiniDrifter] profile: {bundle.get('profile_id')}  adapter: {(bundle.get('adapter_profile') or {}).get('request_adapter')}")
    print(f"[MiniDrifter] n_tier: {bundle.get('summary', {}).get('n_tier_distribution')}")


def cmd_profile_resolve(args: argparse.Namespace) -> None:
    import json
    from minidrifter.adapters.registry import analyze_pack_adapters

    pack = Path(args.input_dir)
    result = analyze_pack_adapters(pack, profile_id=getattr(args, 'profile', None))
    from minidrifter.adapters.pack_resolver import write_adapter_resolution
    write_adapter_resolution(pack, profile_id=(result.get('profile') or {}).get('profile_id'))
    print(json.dumps({
        'profile_id': (result.get('profile') or {}).get('profile_id'),
        'project_adapter': (result.get('profile') or {}).get('project_adapter'),
        'request_adapter': (result.get('profile') or {}).get('request_adapter'),
        'crypto_profile': (result.get('profile') or {}).get('crypto_profile'),
        'framework': (result.get('project_detection') or {}).get('framework'),
        'primary_wrapper': (result.get('primary_wrapper') or {}).get('file'),
        'sample_recovered': result.get('sample_recovered_operations') or [],
    }, indent=2, ensure_ascii=False))


def cmd_crypto_extract(args: argparse.Namespace) -> None:
    import json
    from minidrifter.runtime.crypto.static_emit import emit_crypto_static_profile
    from minidrifter.runtime.crypto.registry import load_crypto_capability

    pack = Path(args.input_dir)
    source = Path(args.source_dir) if getattr(args, 'source_dir', None) else None
    if not source:
        prof = pack / 'project_profile.json'
        if prof.exists():
            source = Path(json.loads(prof.read_text(encoding='utf-8')).get('project_root') or '')

    doc = emit_crypto_static_profile(pack, source_dir=source, profile_id=getattr(args, 'profile', None))
    cap = load_crypto_capability(pack, source_dir=source)
    print(f"[MiniDrifter] crypto static profile -> {doc.get('artifact')}")
    print(f"[MiniDrifter] profile={doc.get('profile_id')} can_replay={doc.get('can_replay')} reason={doc.get('reason')}")
    mat = doc.get('material') or {}
    if mat.get('aes_key'):
        print(f"[MiniDrifter] aes_key={mat.get('aes_key')[:4]}*** cid={mat.get('cid')} host={mat.get('api_host')}")
    print(f"[MiniDrifter] capability: can_replay={cap.can_replay} transport={cap.transport_style}")


def cmd_mine_signature_profile(args: argparse.Namespace) -> None:
    import json
    from minidrifter.runtime.crypto.signature_profile_miner import emit_signature_profile

    pack = Path(args.input_dir)
    source = Path(args.source_dir) if getattr(args, 'source_dir', None) else None
    if not source:
        prof = pack / 'project_profile.json'
        if prof.exists():
            source = Path(json.loads(prof.read_text(encoding='utf-8')).get('project_root') or '')
    pool = None
    brc = pack / 'baseline_runtime_context.json'
    if brc.exists():
        ctx = json.loads(brc.read_text(encoding='utf-8'))
        pool = {
            k: str(v.get('value'))
            for k, v in (ctx.get('resolved_fields') or {}).items()
            if isinstance(v, dict) and v.get('value') not in (None, '')
        }
    out = emit_signature_profile(pack, source_dir=source, baseline_pool=pool)
    doc = json.loads(out.read_text(encoding='utf-8'))
    print(f"[MiniDrifter] signature_profile -> {out}")
    print(
        f"[MiniDrifter] profile={doc.get('signature_profile_id')} "
        f"can_recompute={doc.get('can_recompute_signature')} "
        f"confidence={doc.get('confidence')} reason={doc.get('reason')}"
    )


def cmd_write_sensitive_binding_coverage(args: argparse.Namespace) -> None:
    from minidrifter.orchestration.binding_coverage_report import write_binding_coverage_report
    from minidrifter.verification.reporting.sensitive_binding_coverage import (
        write_sensitive_binding_coverage_report,
    )

    pack = Path(args.input_dir)
    sac_path = write_sensitive_binding_coverage_report(pack)
    cov_path = write_binding_coverage_report(pack)
    print(f"[MiniDrifter] sensitive_binding_coverage -> {sac_path}")
    print(f"[MiniDrifter] binding_coverage_report -> {cov_path}")


def cmd_mine_subject_wire_candidates(args: argparse.Namespace) -> None:
    import json
    from minidrifter.classification.subject_wire_candidate_miner import mine_subject_wire_candidates

    pack = Path(args.input_dir)
    doc = mine_subject_wire_candidates(pack, write=True)
    summary = doc.get('summary') or {}
    print(
        f"[MiniDrifter] subject_wire_candidates -> {pack / 'subject_wire_candidates.json'} "
        f"total={summary.get('candidates_total', 0)} "
        f"mutable={summary.get('candidates_mutation_allowed', 0)}",
        flush=True,
    )
    if getattr(args, 'verbose', False):
        print(json.dumps(doc.get('candidates') or [], ensure_ascii=False, indent=2))


def cmd_plan_subject_wire_gap(args: argparse.Namespace) -> None:
    import json
    from minidrifter.classification.subject_wire_candidate_miner import mine_subject_wire_candidates
    from minidrifter.classification.subject_wire_gap_planner import build_subject_wire_gap_plan

    pack = Path(args.input_dir)
    mine_subject_wire_candidates(pack, write=True)
    doc = build_subject_wire_gap_plan(pack, write=True, max_gaps=getattr(args, 'max_gaps', 24))
    summary = doc.get('summary') or {}
    print(
        f"[MiniDrifter] subject_wire_gap_plan -> {pack / 'subject_wire_gap_plan.json'} "
        f"static_subject_like={summary.get('static_subject_like_sensitive_apis', 0)} "
        f"uncovered={summary.get('uncovered_high_priority', 0)} "
        f"categories={summary.get('recommended_capture_categories', 0)}",
        flush=True,
    )
    if getattr(args, 'verbose', False):
        print(json.dumps(doc.get('recommended_capture_categories') or [], ensure_ascii=False, indent=2))


def cmd_run_sensitive_subject_override(args: argparse.Namespace) -> None:
    import json
    from minidrifter.business_chain.chain_run_context import load_json
    from minidrifter.classification.subject_wire_candidate_miner import mine_subject_wire_candidates
    from minidrifter.verification.sensitive_target_enrollment import enroll_intake_sensitive_targets
    from minidrifter.verification.subject_override_runner import run_subject_override_batch

    if args.mode == 'execute' and not getattr(args, 'i_know', False):
        raise SystemExit('Refusing --mode execute without --i-know')

    pack = Path(args.input_dir)
    source = Path(args.source_dir) if getattr(args, 'source_dir', None) else None
    mine_subject_wire_candidates(pack, write=True)
    from minidrifter.classification.subject_wire_gap_planner import build_subject_wire_gap_plan
    build_subject_wire_gap_plan(pack, write=True)
    sr = load_json(pack / 'sensitive_read_report.json') or {}
    tpl_doc = load_json(pack / 'materialized_api_templates.json') or {}
    templates_by_id = {t['api_id']: t for t in (tpl_doc.get('templates') or []) if t.get('api_id')}
    baseline = load_json(pack / 'baseline_runtime_context.json') or {}
    for cand in enroll_intake_sensitive_targets(
        pack, covered_paths=set(), seen=set(), baseline_context=baseline,
    ):
        if cand.get('synthetic_template') and cand.get('api_id'):
            templates_by_id[cand['api_id']] = cand['synthetic_template']

    doc = run_subject_override_batch(
        pack,
        sr.get('results') or [],
        templates_by_id=templates_by_id,
        mode=args.mode,
        max_targets=getattr(args, 'max_targets', 10),
        max_http=getattr(args, 'max_http', 30),
        source_dir=source,
        base_url=getattr(args, 'base_url', None),
        verbose=getattr(args, 'verbose', False),
    )
    print(json.dumps(doc.get('subject_override') or {}, ensure_ascii=False, indent=2))


def cmd_build_sensitive_replay_context(args: argparse.Namespace) -> None:
    from minidrifter.verification.binding_campaign_runner import rebuild_binding_campaign_artifacts

    pack = Path(args.input_dir)
    rebuild_binding_campaign_artifacts(pack)
    print(f"[MiniDrifter] rebuilt -> {pack / 'sensitive_replay_context.json'}")
    print(f"[MiniDrifter] rebuilt -> {pack / 'subject_wire_candidates.json'}")
    print(f"[MiniDrifter] rebuilt -> {pack / 'object_wire_candidates.json'}")


def cmd_run_binding_campaign(args: argparse.Namespace) -> None:
    import json
    from minidrifter.verification.binding_campaign_runner import run_binding_campaign

    if args.mode == 'execute' and not getattr(args, 'i_know', False):
        raise SystemExit('[MiniDrifter] --mode execute requires --i-know')

    pack = Path(args.input_dir)
    source = Path(args.source_dir) if getattr(args, 'source_dir', None) else None
    result = run_binding_campaign(
        pack,
        mode=args.mode,
        source_dir=source,
        run_m7=args.mode == 'execute',
        max_targets=getattr(args, 'max_targets', 10),
        max_http=getattr(args, 'max_http', 30),
        base_url=getattr(args, 'base_url', None),
    )
    print(f"[MiniDrifter] final_binding_report -> {result.get('final_binding_report')}")
    print(f"[MiniDrifter] binding_campaign_report -> {result.get('binding_campaign_report')}")
    print(json.dumps(result.get('summary') or {}, ensure_ascii=False, indent=2))


def cmd_benchmark(args: argparse.Namespace) -> None:
    import json
    from minidrifter.benchmark.runner import collect_pack_metrics, run_benchmark

    if getattr(args, 'pack', None):
        m = collect_pack_metrics(Path(args.pack), profile_id=getattr(args, 'profile', None))
        print(json.dumps(m.get('metrics') or {}, indent=2, ensure_ascii=False))
    else:
        report = run_benchmark()
        print(f"[MiniDrifter] benchmark report -> packs/benchmark/last_benchmark_report.json ({len(report.get('results') or [])} packs)")


def cmd_workbench_run(args: argparse.Namespace) -> None:
    from minidrifter.orchestration.workbench_run import run_workbench_pipeline

    pack = Path(args.input_dir)
    result = run_workbench_pipeline(
        pack_dir=pack,
        project_root=Path(args.project) if getattr(args, 'project', None) else None,
        workspace=Path(args.workspace) if getattr(args, 'workspace', None) else None,
        source_dir=Path(args.source_dir) if getattr(args, 'source_dir', None) else None,
        base_url=getattr(args, 'base_url', None) or None,
        skip_analyze=getattr(args, 'skip_analyze', False),
        skip_verify=getattr(args, 'skip_verify', False),
        skip_materialize=getattr(args, 'skip_materialize', False),
        with_llm=getattr(args, 'with_llm', False),
        mode=getattr(args, 'mode', 'dry-run'),
        max_http=getattr(args, 'max_http', 250),
        max_seeds=getattr(args, 'max_seeds', 50),
        max_depth=getattr(args, 'max_depth', 5),
        max_llm=getattr(args, 'max_llm', 80),
        beam_width=getattr(args, 'beam_width', 5),
        deep_think=getattr(args, 'deep_think', False),
        anchor_api_id=getattr(args, 'anchor_api', None) or None,
        i_know=getattr(args, 'i_know', False),
        resume=getattr(args, 'resume', False),
        resume_file=Path(args.resume_file) if getattr(args, 'resume_file', None) else None,
        force_resume=getattr(args, 'force_resume', False),
        verify_mode=getattr(args, 'verify_mode', 'campaign'),
        chain_id=getattr(args, 'chain_id', None) or None,
    )
    print(f"\n[MiniDrifter] workbench run status={result.get('status')} verdict={result.get('verdict')}")
    if result.get('executive_summary'):
        print(f"[MiniDrifter] {result.get('executive_summary')}")
    nxt = result.get('next_action')
    if nxt:
        print(f"[MiniDrifter] NEXT: {nxt.get('action')}")
        for f in nxt.get('files') or []:
            print(f"  read: {f}")
    report = pack / 'workbench_run_report.json'
    print(f"[MiniDrifter] full report -> {report}")
    if result.get('status') == 'blocked' and not getattr(args, 'skip_verify', False):
        raise SystemExit(1)


def cmd_reason(args: argparse.Namespace) -> None:
    if args.task == 'card_auditor':
        result = run_card_auditor_batch(
            args.input_dir,
            tier=args.tier,
            card_id=args.card_id,
            limit=args.limit,
            dry_run=args.dry_run,
        )
        print(f"[MiniDrifter] card_auditor: selected={result['selected']} output={result['output']}")
        if not args.dry_run:
            print(f"[MiniDrifter] accepted={result.get('accepted')} rejected={result.get('rejected')} errors={result.get('errors')}")
    elif args.task == 'acquisition_advisor':
        result = run_acquisition_advisor(
            args.input_dir,
            limit=args.limit,
            dry_run=args.dry_run,
        )
        print(f"[MiniDrifter] acquisition_advisor: selected={result['selected']} status={result.get('status')} output={result['output']}")
        if result.get('plan'):
            print(f"[MiniDrifter] enriched plan: {result['plan']}")
        if not args.dry_run and result.get('validation_errors'):
            print(f"[MiniDrifter] validation: {result['validation_errors'][:5]}")
    else:
        raise SystemExit(f"Unknown reasoning task: {args.task}. Choose: card_auditor, acquisition_advisor")


def cmd_verify_prepare(args: argparse.Namespace) -> None:
    """Run S1 audit + requirements + acquisition plan; optional LLM chain advisor + card auditor."""
    cmd_audit_pack(args)
    cmd_detect_requirements(args)
    plan_args = argparse.Namespace(
        input_dir=args.input_dir,
        output=getattr(args, 'output', None),
        with_llm=False,
        limit=getattr(args, 'advisor_limit', 25),
        dry_run=args.dry_run,
    )
    cmd_plan_acquisition(plan_args)
    if args.with_llm:
        advisor_args = argparse.Namespace(
            input_dir=args.input_dir,
            task='acquisition_advisor',
            tier=None,
            card_id=None,
            limit=getattr(args, 'advisor_limit', 25),
            dry_run=args.dry_run,
        )
        cmd_reason(advisor_args)
        auditor_args = argparse.Namespace(
            input_dir=args.input_dir,
            task='card_auditor',
            tier=args.tier,
            card_id=None,
            limit=args.limit,
            dry_run=args.dry_run,
        )
        cmd_reason(auditor_args)


def cmd_generate_baseline_template(args: argparse.Namespace) -> None:
    from minidrifter.reasoning.pack_loader import load_pack

    pack = load_pack(args.input_dir)
    out = Path(args.output or args.input_dir)
    erd = build_evidence_requirements(pack['cards'], pack['manifest'])
    erd_items = erd.get('items') or []
    write_json(out / 'evidence_requirements.json', erd)

    result = build_baseline_material_pipeline(
        pack['cards'],
        pack['manifest'],
        erd_items=erd_items,
        stage1_limit=args.stage1_limit,
    )
    paths = write_baseline_material_pipeline(out, result)

    tmpl = result['baseline_material_template']
    reqs = result['material_requirements']
    dom = result['business_domain_tree']
    graph = result['runtime_demand_graph_full']
    print(f"[MiniDrifter] baseline template: {tmpl.get('template_id')} -> {paths['baseline_material_template']}")
    print(
        f"[MiniDrifter] materials: required={len(tmpl.get('required_materials',[]))} "
        f"recommended={len(tmpl.get('recommended_materials',[]))} "
        f"deferred={len(tmpl.get('deferred_materials',[]))}"
    )
    print(
        f"[MiniDrifter] domain known={dom.get('known_domain_percent')}% "
        f"graph full: apis={graph.get('api_node_count')} edges={len(graph.get('edges',[]))} "
        f"produces={graph.get('produces_count')}"
    )
    print(f"[MiniDrifter] graph files: full={paths['runtime_demand_graph_full']} preview={paths['runtime_demand_graph_preview']}")
    print(f"[MiniDrifter] field stats={reqs.get('summary')}")


def cmd_intake_baseline(args: argparse.Namespace) -> None:
    from minidrifter.materials.intelligent_intake import run_intelligent_baseline_intake

    out = Path(args.output or args.input_dir)
    source_dir = Path(args.source_dir) if getattr(args, 'source_dir', None) else None
    if args.file:
        raw = Path(args.file).read_text(encoding='utf-8', errors='replace')
        source = str(args.file)
    else:
        raise SystemExit('Provide --file with raw HTTP capture(s)')

    if getattr(args, 'materialize_after', False):
        args.import_after = True

    result = run_intelligent_baseline_intake(
        out, raw,
        source_dir=source_dir,
        source_label=source,
        import_after=bool(getattr(args, 'import_after', False)),
        materialize_after=bool(getattr(args, 'materialize_after', False) or getattr(args, 'import_after', False)),
        materialize_limit=getattr(args, 'limit', 120),
    )

    if getattr(args, 'write_splits', False):
        from minidrifter.materials.baseline_intake import build_intake_report
        report_path = out / 'baseline_intake_report.json'
        if report_path.exists():
            import json
            report = json.loads(report_path.read_text(encoding='utf-8'))
            mat_dir = out / 'user_materials'
            mat_dir.mkdir(parents=True, exist_ok=True)
            splits = report.get('recommended_file_split') or {}
            from minidrifter.materials.baseline_intake import split_multi_raw_http
            chunks = split_multi_raw_http(raw)
            for mid, idx in splits.items():
                if idx and 1 <= idx <= len(chunks):
                    (mat_dir / f'{mid}.http').write_text(chunks[idx - 1], encoding='utf-8')

    strategy = result.get('intake_strategy') or {}
    baseline = result.get('baseline') or {}
    print(
        f"[MiniDrifter] intelligent intake: status={result.get('status')} "
        f"strategy={strategy.get('strategy')} replay_tier={strategy.get('replay_tier')} "
        f"captures={result.get('capture_count')}"
    )
    if baseline:
        print(
            f"  baseline: fields={baseline.get('field_count')} "
            f"crypto_replay={baseline.get('crypto_replay_ready')} "
            f"mode={baseline.get('replay_mode')} n1={baseline.get('n1_materialize_allowed')}"
        )
    if strategy.get('rationale'):
        print(f"  rationale: {strategy['rationale']}")
    crypto_prep = result.get('crypto_prep') or {}
    if crypto_prep.get('can_replay') is not None:
        print(f"  static_crypto: can_replay={crypto_prep.get('can_replay')} profile={(crypto_prep.get('capability') or {}).get('profile_id')}")
    if result.get('materialize'):
        print(f"  materialize: {result['materialize']}")
    report_path = out / 'baseline_intake_report.json'
    if report_path.exists():
        import json
        report = json.loads(report_path.read_text(encoding='utf-8'))
        for line in (report.get('user_guidance') or [])[:6]:
            print(f"  - {line}")


def cmd_run_flow(args: argparse.Namespace) -> None:
    from minidrifter.orchestration.unified_flow import run_unified_pack_flow

    pack_dir = Path(args.input_dir)
    result = run_unified_pack_flow(
        pack_dir=pack_dir,
        project_root=Path(args.project) if getattr(args, 'project', None) else None,
        capture_file=Path(args.capture_file) if getattr(args, 'capture_file', None) else None,
        source_dir=Path(args.source_dir) if getattr(args, 'source_dir', None) else None,
        skip_analyze=getattr(args, 'skip_analyze', False),
        mode=args.mode,
        max_http=getattr(args, 'max_http', 5),
        max_seeds=getattr(args, 'max_seeds', 2),
        materialize=not getattr(args, 'skip_materialize', False),
        verify=not getattr(args, 'skip_verify', False),
        with_llm=getattr(args, 'with_llm', False),
    )
    print(f"[MiniDrifter] run-flow: status={result.get('status')} loop_state={result.get('loop_state')} pack={pack_dir}")
    for st in result.get('stages') or []:
        print(f"  [{st.get('status')}] {st.get('stage')}: { {k: v for k, v in st.items() if k not in ('stage', 'status', 'at')} }")
    intake = result.get('intake') or {}
    if intake.get('verdict'):
        print(f"  intake_strategy={intake.get('verdict')} crypto_replay={(intake.get('baseline') or {}).get('crypto_replay_ready')}")
    if result.get('verdict'):
        print(f"  verify_verdict={result.get('verdict')} verify_mode={result.get('verify_mode')}")
    if result.get('next_action'):
        print(f"  next_action={result.get('next_action')}")
    print(f"  report: {pack_dir / 'closed_loop_report.json'}")


def cmd_run_closed_loop(args: argparse.Namespace) -> None:
    from minidrifter.orchestration.account_closed_loop import (
        resume_closed_loop_from_capture,
        run_account_closed_loop,
    )

    if args.mode == 'execute' and not getattr(args, 'i_know', False):
        raise SystemExit('[MiniDrifter] live execute requires --i-know (sends real HTTP to target host)')

    pack_dir = Path(args.input_dir)
    if getattr(args, 'resume_file', None):
        raw = Path(args.resume_file).read_text(encoding='utf-8', errors='replace')
        result = resume_closed_loop_from_capture(
            pack_dir, raw,
            source_label=str(args.resume_file),
            source_dir=Path(args.source_dir) if getattr(args, 'source_dir', None) else None,
            mode=args.mode,
            chain_id=getattr(args, 'chain_id', None),
        )
    else:
        result = run_account_closed_loop(
            pack_dir=pack_dir,
            project_root=Path(args.project) if getattr(args, 'project', None) else None,
            capture_file=Path(args.capture_file) if getattr(args, 'capture_file', None) else None,
            source_dir=Path(args.source_dir) if getattr(args, 'source_dir', None) else None,
            skip_analyze=getattr(args, 'skip_analyze', False),
            mode=args.mode,
            max_http=getattr(args, 'max_http', 250),
            max_chains=getattr(args, 'max_chains', 15),
            materialize=not getattr(args, 'skip_materialize', False),
            verify=not getattr(args, 'skip_verify', False),
            chain_id=getattr(args, 'chain_id', None),
            with_llm=getattr(args, 'with_llm', False),
            verify_mode=getattr(args, 'verify_mode', 'campaign'),
            beam_width=getattr(args, 'beam_width', 8),
            campaign_source=getattr(args, 'campaign_source', 'rank_plan'),
        )
    print(f"[MiniDrifter] closed-loop: status={result.get('status')} loop_state={result.get('loop_state')}")
    if result.get('verdict'):
        print(f"  verdict={result.get('verdict')} verify_mode={result.get('verify_mode')}")
    if result.get('coverage') and isinstance(result.get('coverage'), dict):
        cov = result['coverage']
        if cov.get('summary'):
            print(f"  coverage: {cov.get('summary')}")
    if result.get('binding_coverage_report'):
        print(f"  binding_coverage_report={result.get('binding_coverage_report')}")
    if result.get('next_action'):
        print(f"  next_action={result.get('next_action')}")
    if result.get('operator_prompt'):
        print(f"  operator_prompt={result.get('operator_prompt')}")
    print(f"  report: {pack_dir / 'closed_loop_report.json'}")


def cmd_import_baseline(args: argparse.Namespace) -> None:
    import json
    from minidrifter.materials.baseline_importer import import_baseline_from_directory

    out = Path(args.output or args.input_dir)
    tmpl_path = out / 'baseline_material_template.json'
    if not tmpl_path.exists():
        raise FileNotFoundError(
            f'Missing {tmpl_path}; run generate-baseline-template first'
        )
    template = json.loads(tmpl_path.read_text(encoding='utf-8'))

    intake_report = None
    ir_path = getattr(args, 'intake_report', None) or out / 'baseline_intake_report.json'
    if ir_path and Path(ir_path).exists():
        intake_report = json.loads(Path(ir_path).read_text(encoding='utf-8'))

    ctx = import_baseline_from_directory(
        Path(args.materials_dir),
        template,
        pack_id=template.get('pack_id'),
        intake_report=intake_report,
    )
    ctx_path = out / 'baseline_runtime_context.json'
    write_json(ctx_path, ctx)
    print(
        f"[MiniDrifter] baseline context: fields={ctx.get('field_count')} "
        f"crypto_replay={ctx.get('crypto_replay_ready')} "
        f"n1_allowed={ctx.get('n1_materialize_allowed')} -> {ctx_path}"
    )


def cmd_repair_baseline_version(args: argparse.Namespace) -> None:
    import json
    from minidrifter.materials.baseline_version_repair import repair_baseline_version

    out = Path(args.output or args.input_dir)
    ctx_path = out / 'baseline_runtime_context.json'
    if not ctx_path.exists():
        raise SystemExit(f'Missing {ctx_path}; run import-baseline first')

    ctx = json.loads(ctx_path.read_text(encoding='utf-8'))
    materials_dir = Path(args.materials_dir) if getattr(args, 'materials_dir', None) else out / 'user_materials'
    source_dir = Path(args.source_dir) if getattr(args, 'source_dir', None) else None

    if args.mode == 'execute' and not getattr(args, 'i_know', False):
        raise SystemExit('Live version probe requires --i-know with --mode execute')

    updated, report = repair_baseline_version(
        ctx,
        materials_dir=materials_dir if materials_dir.is_dir() else None,
        source_dir=source_dir,
        override_version=getattr(args, 'version', None),
        probe_live=args.mode == 'execute',
        pack_dir=out,
        base_url=getattr(args, 'base_url', None),
        probe_path=getattr(args, 'probe_path', None) or '/Wechat/mobile/CurrentTime',
    )
    write_json(ctx_path, updated)
    report_path = out / 'baseline_version_repair_report.json'
    write_json(report_path, report)
    print(
        f"[MiniDrifter] repair-baseline-version status={report.get('status')} "
        f"version={report.get('selected_version')} changed={report.get('changed')} -> {report_path}"
    )
    if report.get('recommendation'):
        print(f"  note: {report['recommendation']}")


def cmd_crypto_replay(args: argparse.Namespace) -> None:
    import json
    from minidrifter.runtime.crypto.common import parse_kv_string
    from minidrifter.runtime.crypto.aes_cfb_md5_wrapper import WrapperSessionContext
    from minidrifter.runtime.crypto.registry import load_crypto_capability
    from minidrifter.runtime.crypto_replay import build_replay_request

    out = Path(args.output or args.input_dir)
    ctx_path = out / 'baseline_runtime_context.json'
    if not ctx_path.exists():
        raise SystemExit(f'Missing {ctx_path}; run intake-baseline --import-after first')

    ctx = json.loads(ctx_path.read_text(encoding='utf-8'))
    pool = {k: v.get('value') for k, v in (ctx.get('resolved_fields') or {}).items()}
    capability = load_crypto_capability(out, source_dir=getattr(args, 'source_dir', None))

    session = WrapperSessionContext.from_baseline_pool(pool)
    if capability.md5_aeskey and not session.md5_aeskey:
        session.md5_aeskey = capability.md5_aeskey

    params = parse_kv_string(args.params) if args.params else {}
    if not params and pool.get('UserId'):
        params = {'userId': pool['UserId']}

    base_url = args.base_url or pool.get('Host') or ''
    if base_url and not base_url.startswith('http'):
        base_url = f'https://{base_url.lstrip("/")}'

    req = build_replay_request(
        args.path, params, session,
        base_url=base_url,
        capability=capability,
        output_dir=out,
        source_dir=Path(args.source_dir) if getattr(args, 'source_dir', None) else None,
    )
    replay_path = out / 'crypto_replay_preview.json'
    write_json(replay_path, req)
    print(f"[MiniDrifter] crypto-replay preview -> {replay_path}")
    print(f"  Authorization={req['headers'].get('Authorization')}")
    print(f"  query_plain={req.get('query_plain')}")


def cmd_materialize_templates(args: argparse.Namespace) -> None:
    import json
    from minidrifter.core.schema import SCHEMA_VERSION
    from minidrifter.reasoning.pack_loader import load_pack
    from minidrifter.materials.intake_param_hints import resolve_intake_capture_card_ids
    from minidrifter.materials.slot_binder import build_materialized_templates
    from minidrifter.materials.materialization_meta import check_materialization_stale
    from minidrifter.graph.produces_confirm import confirm_produces_from_baseline

    out = Path(args.output or args.input_dir)
    ctx_path = out / 'baseline_runtime_context.json'
    if not ctx_path.exists():
        raise SystemExit(f'Missing {ctx_path}; run import-baseline first')

    pack = load_pack(args.input_dir)
    ctx = json.loads(ctx_path.read_text(encoding='utf-8'))
    tpl_path = out / 'materialized_api_templates.json'

    existing = None
    if tpl_path.exists():
        existing = json.loads(tpl_path.read_text(encoding='utf-8'))
    stale = check_materialization_stale(out, existing_templates=existing, baseline_context=ctx)
    if stale.get('stale') and not getattr(args, 'force', False):
        print(f"[MiniDrifter] materialized templates STALE: {stale.get('reasons')}; re-run with --force or use intake --materialize-after")
        if not getattr(args, 'if_stale', True):
            return

    sk_path = out / 'runtime_skeletons.json'
    skeletons = json.loads(sk_path.read_text(encoding='utf-8')) if sk_path.exists() else {}
    by_id = skeletons.get('by_card_id') or {s['card_id']: s for s in skeletons.get('skeletons', [])}

    plan_path = out / 'acquisition_plan.json'
    target_ids = None
    if plan_path.exists():
        plan = json.loads(plan_path.read_text(encoding='utf-8'))
        safe_targets = [
            b['card_id'] for b in (plan.get('stage_1_target_apis') or [])
            if (b.get('replay_safe_rank') or b.get('stage1_score') or 0) > 0
        ]
        target_ids = safe_targets[: args.limit] + [
            b['card_id'] for b in (plan.get('auto_discovery_apis') or [])
            if (b.get('replay_safe_rank') or b.get('stage1_score') or 0) > 0
        ][: max(0, args.limit - len(safe_targets))]

    intake_report = None
    ir_path = out / 'baseline_intake_report.json'
    if ir_path.exists():
        intake_report = json.loads(ir_path.read_text(encoding='utf-8'))

    if intake_report:
        capture_ids = resolve_intake_capture_card_ids(intake_report, pack['cards_by_id'])
        if capture_ids:
            if target_ids is None:
                target_ids = capture_ids
            else:
                target_ids = list(dict.fromkeys(capture_ids + target_ids))

    from minidrifter.business_chain.chain_targets import (
        collect_chain_materialization_targets,
        merge_materialization_targets,
    )
    chain_ids = collect_chain_materialization_targets(out, max_ids=args.limit)
    if chain_ids:
        target_ids = merge_materialization_targets(chain_ids, target_ids, limit=args.limit)

    result = build_materialized_templates(
        pack['cards_by_id'],
        by_id,
        ctx,
        target_api_ids=target_ids,
        pack_dir=out,
        replay_safe_only=getattr(args, 'replay_safe_only', False),
        intake_report=intake_report,
    )
    result['staleness_check'] = stale

    graph_path = out / 'runtime_demand_graph.full.json'
    if graph_path.exists():
        graph = json.loads(graph_path.read_text(encoding='utf-8'))
        produces = [e for e in (graph.get('edges') or []) if e.get('type') == 'produces']
        confirmed = confirm_produces_from_baseline(
            produces, pack['cards_by_id'], ctx, intake_report=intake_report,
        )
        write_json(out / 'confirmed_produces.json', {
            'schema_version': '1.0.0',
            'generated_at': result.get('generated_at'),
            'confirmed_count': sum(1 for e in confirmed if e.get('evidence_level') == 'baseline_confirmed'),
            'edges': confirmed,
        })

    write_json(tpl_path, result)
    try:
        from minidrifter.materials.object_flow_anchor_materializer import inject_object_flow_anchors
        inject_object_flow_anchors(out, write=True)
    except Exception:
        pass
    try:
        from minidrifter.business_chain.export import refresh_business_chains_for_pack
        refresh_business_chains_for_pack(out)
    except Exception:
        pass
    report = {
        'schema_version': SCHEMA_VERSION,
        'generated_at': result.get('generated_at'),
        'summary': result.get('summary'),
        'ready_for_replay': result.get('ready_for_replay'),
        'baseline_field_count': result.get('baseline_field_count'),
        'baseline_context_generated_at': result.get('baseline_context_generated_at'),
        'dependencies': result.get('dependencies'),
        'template_count': result.get('template_count'),
        'staleness_check': stale,
    }
    report_path = out / 'materialization_report.json'
    write_json(report_path, report)
    print(f"[MiniDrifter] materialized: {result.get('summary')} baseline_fields={result.get('baseline_field_count')} -> {tpl_path}")
    print(f"[MiniDrifter] ready_for_replay={len(result.get('ready_for_replay',[]))} report={report_path}")


def cmd_plan_campaign(args: argparse.Namespace) -> None:
    from minidrifter.verification.campaign_runner import run_verification_campaign

    out = Path(args.output or args.input_dir)
    result = run_verification_campaign(
        out,
        mode='dry-run',
        only_safe=not getattr(args, 'include_unsafe', False),
        max_tests=args.max_tests,
        plan_only=True,
    )
    camp = result.get('campaign') or {}
    print(
        f"[MiniDrifter] verification plan: selected={camp.get('selected_count')} "
        f"candidates={camp.get('candidate_count')} blocked={camp.get('blocked_count')}"
    )
    for item in (camp.get('top_apis') or [])[:8]:
        print(f"  - {item.get('path')} score={item.get('score')}")
    print(f"[MiniDrifter] -> {out / 'verification_campaign.json'}, {out / 'test_cases.jsonl'}")


def cmd_run_campaign(args: argparse.Namespace) -> None:
    from minidrifter.verification.campaign_runner import run_verification_campaign

    out = Path(args.output or args.input_dir)
    mode = getattr(args, 'mode', 'dry-run')
    if mode == 'execute' and not getattr(args, 'i_know', False):
        print('[MiniDrifter] live execute requires --i-know (sends real HTTP to target host)')
        raise SystemExit(2)

    result = run_verification_campaign(
        out,
        mode=mode,
        only_safe=not getattr(args, 'include_unsafe', False),
        max_tests=args.max_tests,
        plan_only=False,
        source_dir=Path(args.source_dir) if getattr(args, 'source_dir', None) else None,
        base_url=getattr(args, 'base_url', None) or None,
        with_llm=getattr(args, 'with_llm', False),
        llm_dry_run=getattr(args, 'llm_dry_run', False),
    )
    cov = result.get('coverage') or {}
    print(
        f"[MiniDrifter] campaign mode={mode}: planned={cov.get('tests_planned')} "
        f"executed={cov.get('tests_executed')} dry_ok={cov.get('dry_run_ok')} "
        f"business_success={cov.get('business_success')} "
        f"app_version_blocked={cov.get('app_version_blocked')} findings={cov.get('findings_count')}"
    )
    if getattr(args, 'with_llm', False):
        print(
            f"[MiniDrifter] LLM: proposals={cov.get('llm_proposals')} "
            f"feedback={cov.get('llm_feedback_status')}"
        )
        fb = (result.get('llm_feedback') or {}).get('feedback') or {}
        if fb.get('diagnosis'):
            print(f"  diagnosis: {fb.get('diagnosis')[:120]}")
    nap = result.get('next_action_plan') or {}
    for act in (nap.get('recommended_actions') or [])[:3]:
        print(f"  next: [{act.get('priority')}] {act.get('action')} — {act.get('reason')}")
    print(f"[MiniDrifter] -> coverage_report.json, next_action_plan.json")


def cmd_replay_preflight(args: argparse.Namespace) -> None:
    import json
    from minidrifter.verification.replay_preflight import run_replay_preflight

    out = Path(args.output or args.input_dir)
    live = getattr(args, 'live_probe', False)
    if live and not getattr(args, 'i_know', False):
        print('[MiniDrifter] live preflight probe requires --i-know')
        raise SystemExit(2)

    report = run_replay_preflight(
        out,
        source_dir=Path(args.source_dir) if getattr(args, 'source_dir', None) else None,
        base_url=getattr(args, 'base_url', None) or None,
        live_probe=live,
    )
    path = out / 'replay_preflight_report.json'
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    print(
        f"[MiniDrifter] preflight ready={report.get('ready')} "
        f"blockers={report.get('summary', {}).get('blocker_count')} "
        f"warnings={report.get('summary', {}).get('warning_count')} "
        f"checks={report.get('summary', {}).get('checks_passed')}/"
        f"{report.get('summary', {}).get('checks_total')}"
    )
    for b in report.get('blockers') or []:
        print(f"  BLOCKER [{b.get('layer')}]: {b.get('message')}")
    for w in (report.get('warnings') or [])[:5]:
        print(f"  WARN [{w.get('layer')}]: {w.get('message')}")
    print(f"[MiniDrifter] -> {path}")


def cmd_plan_frontier_campaign(args: argparse.Namespace) -> None:
    from minidrifter.orchestration.frontier_scheduler import write_campaign_frontier_plan

    pack = Path(args.input_dir)
    path = write_campaign_frontier_plan(pack, max_chains=getattr(args, 'max_chains', 40))
    import json
    doc = json.loads(path.read_text(encoding='utf-8'))
    print(
        f"[MiniDrifter] frontier plan: candidates={doc.get('candidate_chains')} "
        f"selected={len(doc.get('selected_chains') or [])} round={doc.get('campaign_round')}"
    )
    for row in (doc.get('selected_chains') or [])[:10]:
        print(
            f"  [{row.get('priority')}] {row.get('chain_id')} "
            f"{row.get('producer_api')} -> {row.get('consumer_api')} "
            f"anchor={row.get('object_anchor')}"
        )
    print(f"[MiniDrifter] -> {path}")


def cmd_run_deep_verify(args: argparse.Namespace) -> None:
    from minidrifter.orchestration.pipeline_runner import run_deep_verify

    out = Path(args.output or args.input_dir)
    mode = getattr(args, 'mode', 'dry-run')
    if mode == 'execute' and not getattr(args, 'i_know', False):
        print('[MiniDrifter] live execute requires --i-know (sends real HTTP to target host)')
        raise SystemExit(2)

    result = run_deep_verify(
        out,
        source_dir=Path(args.source_dir) if getattr(args, 'source_dir', None) else None,
        base_url=getattr(args, 'base_url', None) or None,
        mode=mode,
        max_tests=args.max_tests,
        campaign_rounds=args.rounds,
        with_llm=getattr(args, 'with_llm', False),
        llm_dry_run=getattr(args, 'llm_dry_run', False),
        skip_materialize=getattr(args, 'skip_materialize', False),
        force_materialize=getattr(args, 'force_materialize', False),
        live_preflight=getattr(args, 'live_preflight', False),
        only_safe=not getattr(args, 'include_unsafe', False),
        use_search=not getattr(args, 'legacy_campaign', False),
        max_http=getattr(args, 'max_http', 250),
        max_seeds=getattr(args, 'max_seeds', 50),
        max_depth=getattr(args, 'max_depth', 5),
        max_llm=getattr(args, 'max_llm', 80),
        ig_threshold=getattr(args, 'ig_threshold', 0.25),
        ig_prune=not getattr(args, 'no_ig_prune', False),
        search_mode=getattr(args, 'search_mode', 'apex'),
        beam_width=getattr(args, 'beam_width', 5),
        anchor_api_id=getattr(args, 'anchor_api', None) or None,
        verbose=not getattr(args, 'no_progress', False),
        deep_think=getattr(args, 'deep_think', False),
        with_llm_chain=getattr(args, 'with_llm_chain', False),
        resume_mode=getattr(args, 'resume', False),
        force_resume=getattr(args, 'force_resume', False),
        verify_mode=getattr(args, 'verify_mode', 'campaign'),
        chain_id=getattr(args, 'chain_id', None) or None,
    )
    print(f"[MiniDrifter] deep-verify status={result.get('status')} verdict={result.get('verdict')}")
    print(f"[MiniDrifter] {result.get('executive_summary')}")
    for st in result.get('stages') or []:
        extra = ''
        if st.get('http_calls') is not None:
            extra = f" http={st.get('http_calls')} seeds={st.get('seeds_retired')} findings={st.get('findings_confirmed')}"
        print(f"  stage {st.get('stage')}: {st.get('status')}{extra}")
    ss = result.get('search_session') or {}
    if ss:
        cov = ss.get('coverage') or {}
        budget = ss.get('budget') or {}
        print(
            f"[MiniDrifter] {ss.get('search_mode', 'search')}: http={cov.get('http_calls')}/{budget.get('max_http')} "
            f"atomic={cov.get('atomic_passed') or cov.get('seeds_retired')} "
            f"beam={cov.get('beam_chains')} "
            f"findings={cov.get('findings_confirmed')}"
        )
    ar = result.get('analysis_report') or {}
    if ar.get('markdown'):
        print(f"[MiniDrifter] analysis report -> {ar.get('markdown')}")


def cmd_run_verify_search(args: argparse.Namespace) -> None:
    out = Path(args.output or args.input_dir)
    mode = getattr(args, 'mode', 'dry-run')
    if mode == 'execute' and not getattr(args, 'i_know', False):
        print('[MiniDrifter] live execute requires --i-know (sends real HTTP to target host)')
        raise SystemExit(2)

    with_llm = getattr(args, 'with_llm', False)
    search_mode = getattr(args, 'search_mode', 'apex')
    verify_mode = getattr(args, 'verify_mode', 'apex')

    if verify_mode == 'chain_strict':
        from minidrifter.verification.chain_strict_runner import run_chain_strict_verification

        result = run_chain_strict_verification(
            out,
            mode=mode,
            chain_id=getattr(args, 'chain_id', None) or None,
            source_dir=Path(args.source_dir) if getattr(args, 'source_dir', None) else None,
            base_url=getattr(args, 'base_url', None) or None,
            only_safe=not getattr(args, 'include_unsafe', False),
            skip_preflight=getattr(args, 'skip_preflight', False),
            verbose=not getattr(args, 'no_progress', False),
        )
    elif search_mode == 'apex':
        from minidrifter.verification.adaptive_poc_search import run_adaptive_poc_search
        from minidrifter.verification.apex_search_config import ApexSearchConfig

        apex_cfg = ApexSearchConfig.from_cli(
            mode=mode,
            only_safe=not getattr(args, 'include_unsafe', False),
            max_http=args.max_http,
            max_seeds=args.max_seeds,
            max_depth=args.max_depth,
            max_llm=getattr(args, 'max_llm', 50),
            beam_width=getattr(args, 'beam_width', 5),
            ig_threshold=getattr(args, 'ig_threshold', 0.25),
            ig_prune=not getattr(args, 'no_ig_prune', False),
            with_llm=with_llm,
            with_llm_policy=getattr(args, 'with_llm_policy', False),
            with_llm_chain=getattr(args, 'with_llm_chain', False),
            deep_think=getattr(args, 'deep_think', False),
            llm_dry_run=getattr(args, 'llm_dry_run', False),
            with_mutations=not getattr(args, 'no_mutations', False),
            skip_preflight=getattr(args, 'skip_preflight', False),
            anchor_api_id=getattr(args, 'anchor_api', None) or None,
            verbose=not getattr(args, 'no_progress', False),
            source_dir=Path(args.source_dir) if getattr(args, 'source_dir', None) else None,
            base_url=getattr(args, 'base_url', None) or None,
        )

        result = run_adaptive_poc_search(
            out,
            mode=apex_cfg.mode,
            only_safe=apex_cfg.only_safe,
            max_http=apex_cfg.max_http,
            max_seeds=apex_cfg.max_seeds,
            max_depth=apex_cfg.max_depth,
            beam_width=apex_cfg.beam_width,
            source_dir=apex_cfg.source_dir,
            base_url=apex_cfg.base_url,
            skip_preflight=apex_cfg.skip_preflight,
            with_mutations=apex_cfg.with_mutations,
            with_llm_policy=apex_cfg.with_llm_policy,
            with_llm_chain=apex_cfg.resolved_llm_chain(),
            deep_think=apex_cfg.deep_think,
            llm_dry_run=apex_cfg.llm_dry_run,
            max_llm=apex_cfg.max_llm,
            ig_threshold=apex_cfg.ig_threshold,
            ig_prune=apex_cfg.ig_prune,
            anchor_api_id=apex_cfg.anchor_api_id,
            policy_interval=apex_cfg.resolved_policy_interval(),
            verbose=apex_cfg.verbose,
        )
    else:
        common = dict(
            mode=mode,
            only_safe=not getattr(args, 'include_unsafe', False),
            max_http=args.max_http,
            max_seeds=args.max_seeds,
            max_depth=args.max_depth,
            source_dir=Path(args.source_dir) if getattr(args, 'source_dir', None) else None,
            base_url=getattr(args, 'base_url', None) or None,
            skip_preflight=getattr(args, 'skip_preflight', False),
            with_mutations=not getattr(args, 'no_mutations', False),
            llm_dry_run=getattr(args, 'llm_dry_run', False),
            max_llm=getattr(args, 'max_llm', 50),
            ig_threshold=getattr(args, 'ig_threshold', 0.25),
            ig_prune=not getattr(args, 'no_ig_prune', False),
        )
        from minidrifter.verification.search_controller import run_verification_search

        with_llm_strategy = getattr(args, 'with_llm_strategy', False) or with_llm
        with_llm_workflow = getattr(args, 'with_llm_workflow', False) or with_llm
        result = run_verification_search(
            out,
            **common,
            with_llm_strategy=with_llm_strategy,
            with_llm_workflow=with_llm_workflow,
        )
    if result.get('status') == 'preflight_blocked':
        print(f"[MiniDrifter] search blocked by preflight: {result.get('preflight', {}).get('blockers')}")
        raise SystemExit(1)

    cov = result.get('coverage') or {}
    budget = result.get('budget') or {}
    print(
        f"[MiniDrifter] {result.get('search_mode', search_mode)} mode={mode} verdict={result.get('verdict')}: "
        f"http={cov.get('http_calls')}/{budget.get('max_http')} "
        f"atomic={cov.get('atomic_passed') or cov.get('seeds_retired')} "
        f"beam={cov.get('beam_chains')} "
        f"business_success={cov.get('business_success')} "
        f"findings={cov.get('findings_confirmed')}"
    )
    ps = result.get('prune_summary') or {}
    if ps.get('total_pruned'):
        print(f"[MiniDrifter] prune: {ps.get('total_pruned')} by_reason={ps.get('by_reason')}")
    if budget.get('http_remaining') is not None:
        print(f"[MiniDrifter] budget: http_remaining={budget.get('http_remaining')} llm={budget.get('used_llm')}/{budget.get('max_llm')}")
    llm = result.get('llm') or {}
    if llm.get('with_strategy') or llm.get('with_workflow'):
        print(
            f"[MiniDrifter] LLM: strategy={llm.get('with_strategy')} workflow={llm.get('with_workflow')} "
            f"calls={llm.get('calls')} traces={llm.get('trace_count')} dry_run={llm.get('dry_run')}"
        )
    print(f"[MiniDrifter] -> search_session.json, attribution_records.jsonl, apex_beam_chains.json")
    if getattr(args, 'deep_think', False):
        print(f"[MiniDrifter] -> chain_reasoning_journals.json, chain_thoughts/*.json")
    if llm.get('trace_count'):
        print(f"[MiniDrifter] -> llm_trace.jsonl, llm_trace_session.json")
    if result.get('budget_panel_ref'):
        print(f"[MiniDrifter] -> budget_panel.json, runtime_demand_graph.workflow.json")
    if result.get('finding_chain_reports_ref') or result.get('finding_lifecycle'):
        fl = result.get('finding_lifecycle') or {}
        print(f"[MiniDrifter] -> finding_registry.json, finding_chain_reports.json (confirmed={fl.get('confirmed')})")


def cmd_refine_domain_unknown(args: argparse.Namespace) -> None:
    from minidrifter.refinement.domain_refinement import run_domain_refinement

    out = Path(args.output or args.input_dir)
    domain_ids = None
    if getattr(args, 'domain', None):
        domain_ids = [d.strip() for d in args.domain.split(',') if d.strip()]

    result = run_domain_refinement(out, domain_ids=domain_ids, dry_run=args.dry_run)
    for did, info in (result.get('per_domain') or {}).items():
        pr = info.get('patch_report') or {}
        print(
            f"[MiniDrifter] domain={did}: candidates={pr.get('total_unknown_candidates')} "
            f"resolved={pr.get('method_resolved')} still_unknown={pr.get('still_unknown')} "
            f"auto_replay_ok={pr.get('auto_replay_allowed')}"
        )
    print(
        f"[MiniDrifter] method UNKNOWN: {result.get('before_method_unknown')} -> "
        f"{result.get('after_method_unknown')}"
    )
    if not args.dry_run:
        domains = result.get('domains_run') or []
        print(f"[MiniDrifter] wrote domain_refinement_report.json + per-domain outputs for {domains}")


def cmd_pack_refinement_pipeline(args: argparse.Namespace) -> None:
    """P0–P2: analyze → freeze → domain refine → skeletons → plan → materialize."""
    from minidrifter.core.pack_meta import resolve_app_label, unknown_merge_report_name

    out = Path(args.output or args.input_dir)
    src = args.source or args.input
    app_label = resolve_app_label(out)

    if args.analyze:
        print('[MiniDrifter] P0: analyze + shadow UNKNOWN merge...')
        analyze_args = argparse.Namespace(input=src, output=str(out), platform='wechat')
        cmd_analyze(analyze_args)

    if not args.no_freeze_cards:
        print('[MiniDrifter] freeze-cards from optimized operations...')
        freeze_args = argparse.Namespace(
            input_dir=str(out), output=str(out), app_label=app_label,
            include_registered_only=False, top_k=200,
        )
        cmd_freeze_cards(freeze_args)

    domain_arg = getattr(args, 'domain', None) or None
    domains_label = domain_arg or 'all'
    print(f'[MiniDrifter] P1: domain UNKNOWN refinement (domains={domains_label})...')
    refine_args = argparse.Namespace(
        input_dir=str(out), output=str(out), dry_run=False, domain=domain_arg,
    )
    cmd_refine_domain_unknown(refine_args)

    if args.regenerate_downstream:
        print('[MiniDrifter] P2: regenerate skeletons + plan + materialize...')
        gen_args = argparse.Namespace(input_dir=str(out), output=str(out), stage1_limit=120)
        cmd_generate_baseline_template(gen_args)
        plan_args = argparse.Namespace(input_dir=str(out), output=str(out), with_llm=False)
        cmd_plan_acquisition(plan_args)
        mat_args = argparse.Namespace(
            input_dir=str(out), output=str(out), limit=120, force=True, replay_safe_only=False,
        )
        cmd_materialize_templates(mat_args)

    merge_path = out / unknown_merge_report_name(out)
    if merge_path.exists():
        import json
        mr = json.loads(merge_path.read_text(encoding='utf-8'))
        print(
            f"[MiniDrifter] shadow merge: ops {mr.get('before',{}).get('operation_cards')} -> "
            f"{mr.get('after',{}).get('operation_cards')}, "
            f"UNKNOWN {mr.get('before',{}).get('method_unknown')} -> {mr.get('after',{}).get('method_unknown')}"
        )


def cmd_freeze_cards(args: argparse.Namespace) -> None:
    freezer = APICardFreezer.from_output_dir(
        args.input_dir,
        app_label=args.app_label or None,
        include_registered_only=args.include_registered_only,
        top_k_evidence=args.top_k,
    )
    out = Path(args.output or args.input_dir)
    result = freezer.write(out)
    manifest = result['manifest']
    inv = manifest.get('card_inventory', {})
    down = manifest.get('downstream_inventory', {})
    errs = result.get('validation_errors') or []
    print(f"[MiniDrifter] frozen API cards: total={inv.get('total_cards')} fuzzing_eligible={down.get('fuzzing_eligible')} -> {out}")
    if errs:
        print(f"[MiniDrifter] manifest validation warnings: {errs}")


def cmd_optimize(args: argparse.Namespace) -> None:
    result = StaticResultOptimizer.load_output_dir(args.input_dir)
    opt = StaticResultOptimizer(result).run()
    out = Path(args.output or args.input_dir)
    out.mkdir(parents=True, exist_ok=True)
    # Preserve the old raw replay contracts before writing the optimized replay_contracts.json.
    src_raw = Path(args.input_dir) / 'replay_contracts.json'
    dst_raw = out / 'raw_replay_contracts.json'
    if src_raw.exists() and not dst_raw.exists():
        try:
            shutil.copy2(src_raw, dst_raw)
        except Exception:
            pass
    write_optimizer_outputs(out, opt)
    # also refresh summaries with optimizer-aware counts where possible
    result['optimizer_outputs'] = opt
    write_json(out / 'summary.json', build_summary_json(result))
    write_text(out / 'summary.md', build_summary_md(result))
    APICardFreezer.from_output_dir(out, app_label=out.name).write(out)
    print(f"[MiniDrifter] optimized existing outputs: {args.input_dir} -> {out}")
    print(f"[MiniDrifter] normalized_operations={len(opt.get('normalized_api_operations', []))} business_operations={len(opt.get('business_api_operations', []))} ranked={len(opt.get('ranked_api_candidates', []))}")


def cmd_console(args: argparse.Namespace) -> None:
    from minidrifter.orchestration.console.app import main as console_main
    from minidrifter.orchestration.console.workspace_layout import default_workspace
    ws = getattr(args, 'workspace', None) or str(default_workspace())
    argv = ['--workspace', ws]
    if getattr(args, 'menu', False):
        argv.append('--menu')
    if getattr(args, 'skip_verify', False):
        argv.append('--skip-verify')
    if getattr(args, 'input_dir', None):
        argv.extend(['--menu', '--pack', args.input_dir])
    if getattr(args, 'project', None):
        argv.extend(['--menu', '--project', args.project])
    console_main(argv)


def cmd_static_batch_eval(args: argparse.Namespace) -> None:
    import importlib.util
    path = Path(__file__).resolve().parents[1] / 'scripts' / 'run_static_workspace_eval.py'
    spec = importlib.util.spec_from_file_location('run_static_workspace_eval', path)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    report = mod.run_static_workspace_eval(
        args.workspace,
        skip_analyze=bool(getattr(args, 'skip_analyze', False)),
        only=getattr(args, 'only', None),
    )
    if not report.get('all_passed'):
        raise SystemExit(1)
    print(f"[MiniDrifter] static-batch-eval ALL PASSED ({report.get('passed_count')}/{report.get('project_count')})")


def cmd_prepare_trace_kit(args: argparse.Namespace) -> None:
    from minidrifter.runtime_trace.prepare_kit import prepare_trace_kit, prepare_workspace_trace_kits

    if getattr(args, 'project', None):
        m = prepare_trace_kit(
            args.project,
            pack_dir=getattr(args, 'input_dir', None),
            max_workflows=int(getattr(args, 'max_workflows', 12) or 12),
        )
        print(f"[MiniDrifter] trace kit -> {m.get('trace_dir')}")
        print(f"[MiniDrifter] guide -> {m.get('guide')}")
        return

    report = prepare_workspace_trace_kits(
        args.workspace,
        only=getattr(args, 'only', None),
        max_workflows=int(getattr(args, 'max_workflows', 12) or 12),
    )
    for p in report.get('projects') or []:
        status = 'OK' if p.get('ok') else 'FAIL'
        print(f"[MiniDrifter] [{status}] {p.get('project')} -> {p.get('trace_dir') or p.get('error')}")
    if report.get('ok_count') != report.get('project_count'):
        raise SystemExit(1)
    print(f"[MiniDrifter] prepare-trace-kit ALL OK ({report.get('ok_count')}/{report.get('project_count')})")


def cmd_crbd_probe(args: argparse.Namespace) -> None:
    from minidrifter.runtime_trace.crbd_probe import probe_project, probe_workspace

    mode = getattr(args, 'mode', 'dry-run')
    run_live = bool(getattr(args, 'live', False))
    if mode == 'execute' and run_live and not getattr(args, 'i_know', False):
        raise SystemExit('[MiniDrifter] live execute requires --i-know')

    if getattr(args, 'project', None):
        r = probe_project(
            Path(args.project),
            pack_dir=Path(args.input_dir) if getattr(args, 'input_dir', None) else None,
            max_workflows=int(getattr(args, 'max_workflows', 20) or 20),
            run_live=run_live,
            live_mode=mode,
            self_verify=bool(getattr(args, 'self_verify', False)),
        )
        s = r.get('summary') or {}
        print(f"[MiniDrifter] RR-Drift-probe status={r.get('status')} can_detect={s.get('can_detect_crbd_now')} self_verify={s.get('can_self_verify_now')}")
        print(f"  verdict_counts={r.get('verdict_counts')} blockers={s.get('blocking_factors')}")
        print(f"  report={Path(args.project) / 'CRBD_validation' / 'crbd_probe_report.json'}")
        return

    doc = probe_workspace(
        args.workspace,
        only=getattr(args, 'only', None),
        max_workflows=int(getattr(args, 'max_workflows', 20) or 20),
        run_live=run_live,
        live_mode=mode,
        self_verify=bool(getattr(args, 'self_verify', False)),
    )
    print(f"[MiniDrifter] RR-Drift-probe conclusion={doc.get('conclusion')}")
    print(f"  detectable={doc.get('crbd_detectable_count')}/{doc.get('project_count')}")
    print(f"  report={Path(args.workspace) / 'crbd_dynamic_probe_report.json'}")


def cmd_single_subject_probe(args: argparse.Namespace) -> None:
    from minidrifter.runtime_trace.single_subject_probe import (
        run_single_subject_project,
        run_single_subject_workspace,
    )

    mode = getattr(args, 'mode', 'execute')
    if mode == 'execute' and not getattr(args, 'i_know', False):
        raise SystemExit('[MiniDrifter] single-subject execute requires --i-know (real HTTP)')

    if getattr(args, 'project', None):
        r = run_single_subject_project(
            Path(args.project),
            mode=mode,
            max_targets=int(getattr(args, 'max_targets', 40) or 40),
            i_know=bool(getattr(args, 'i_know', False)),
            enum_radius=int(getattr(args, 'enum_radius', 0) or 0),
            enum_budget=int(getattr(args, 'enum_budget', 12) or 12),
        )
        print(
            f"[MiniDrifter] single-subject status={r.get('status')} "
            f"hit_rate={r.get('hit_rate')}% positives={r.get('positives')}/{r.get('m0_success')}"
        )
        print(f"  report={Path(args.project) / 'CRBD_validation' / 'single_subject_report.json'}")
        return

    doc = run_single_subject_workspace(
        args.workspace,
        only=getattr(args, 'only', None),
        mode=mode,
        max_targets=int(getattr(args, 'max_targets', 40) or 40),
        i_know=bool(getattr(args, 'i_know', False)),
    )
    print(f"[MiniDrifter] single-subject avg_hit_rate={doc.get('avg_hit_rate')}% gate={doc.get('gate_passed')}")
    print(f"  report={Path(args.workspace) / 'single_subject_batch_report.json'}")


# ── 新增命令实现 ──

def cmd_compose_chains(args: argparse.Namespace) -> None:
    from minidrifter.runtime_trace.chain_composer import compose_chains_for_pack
    pack = Path(args.input_dir)
    har = Path(args.har) if getattr(args, 'har', None) else None
    result = compose_chains_for_pack(
        pack,
        har,
        max_chains=args.max_chains,
        har_first=not bool(getattr(args, 'no_har_first', False)),
        align_crypto=not bool(getattr(args, 'no_align_crypto', False)),
    )
    print(f"[MiniDrifter] compose-chains: {result['chain_count']} chains -> {result['output']}")
    print(f"  critical={result['summary']['critical']} high={result['summary']['high']} "
          f"har_crbd={result['summary'].get('har_crbd')} json_rpc={result['summary'].get('json_rpc')}")
    align = result.get('crypto_align') or {}
    if align:
        print(f"  crypto_align ok={align.get('ok')} aes={align.get('aes_aligned')} "
              f"sm4={align.get('sm4_aligned')} app={align.get('picked_app_id')}")


def cmd_har_crbd_probe(args: argparse.Namespace) -> None:
    from minidrifter.runtime_trace.har_crbd_campaign import run_limited_har_crbd_probe
    pack = Path(args.input_dir)
    har = Path(args.har) if getattr(args, 'har', None) else None
    if har is None:
        # default subject_A full_session.har next to pack
        cand = pack.parent / 'CRBD_validation' / 'trace' / 'subject_A' / 'full_session.har'
        har = cand if cand.exists() else None
    if har is None or not har.exists():
        print('[MiniDrifter] har-RR-Drift-probe requires --har or CRBD_validation/trace/subject_A/full_session.har')
        return
    if args.mode == 'execute' and not getattr(args, 'i_know', False):
        print('[MiniDrifter] har-RR-Drift-probe --mode execute requires --i-know')
        return
    result = run_limited_har_crbd_probe(
        pack,
        har,
        max_targets=int(getattr(args, 'max_targets', 8) or 8),
        i_know=bool(getattr(args, 'i_know', False)) and args.mode == 'execute',
        align_crypto=not bool(getattr(args, 'no_align_crypto', False)),
        base_url=getattr(args, 'base_url', '') or '',
    )
    s = result.get('summary') or {}
    print(f"[MiniDrifter] har-RR-Drift-probe: targets={s.get('n_targets')} "
          f"Accept={s.get('n_accept')} SEffect={s.get('n_seffect')} decrypt={s.get('n_decrypt_ok')}")
    print(f"  output={result.get('output')}")
    align = result.get('align') or {}
    if align:
        print(f"  crypto_align ok={align.get('ok')} notes={align.get('notes')}")


def cmd_feedback_stats(args: argparse.Namespace) -> None:
    from minidrifter.runtime_trace.feedback_engine import create_feedback_engine
    engine = create_feedback_engine(Path(args.input_dir))
    stats = engine.get_stats()
    print(f"[MiniDrifter] feedback stats:")
    print(f"  total_probes={stats['total_probes']}")
    print(f"  categories={stats['category_distribution']}")
    print(f"  blocked={stats['blocked_endpoints']} valid={stats['valid_endpoints']}")
    print(f"  oracles={stats['oracle_count']}")


def cmd_active_probe(args: argparse.Namespace) -> None:
    from minidrifter.runtime_trace.active_probe import run_active_probe
    if not getattr(args, 'i_know', False):
        print("[MiniDrifter] active-probe requires --i-know for live HTTP probing")
        return
    pack = Path(args.input_dir)
    oracle_tests = None
    if args.oracle_endpoint and args.oracle_param and args.oracle_values:
        oracle_tests = [{
            'endpoint': args.oracle_endpoint,
            'param': args.oracle_param,
            'values': args.oracle_values,
        }]
    enum_tasks = None
    if getattr(args, 'enum_idcard', False) and args.enum_areas:
        enum_tasks = [{
            'type': 'idcard',
            'endpoint': args.oracle_endpoint or '/coupon/coupon/search',
            'param': args.oracle_param or 'cardno',
            'area_codes': args.enum_areas,
        }]
    result = run_active_probe(
        pack, args.base_url,
        scan_paths=args.scan_paths,
        oracle_tests=oracle_tests,
        enum_tasks=enum_tasks,
    )
    scan_info = result.get('scan') or {}
    print(f"[MiniDrifter] active-probe: scan={scan_info.get('accessible')} oracles={len(result.get('oracles',[]))} enum_hits={sum(e.get('hit_count',0) for e in result.get('enumerations',[]))}")
    print(f"  output={result.get('output')}")


def cmd_execute_chains(args: argparse.Namespace) -> None:
    from minidrifter.runtime_trace.chain_executor import execute_chains
    if args.mode == 'execute' and not getattr(args, 'i_know', False):
        print("[MiniDrifter] execute-chains --mode execute requires --i-know")
        return
    pack = Path(args.input_dir)
    chains_file = Path(args.chains_file) if args.chains_file else pack / 'exploit_chains.json'
    if not chains_file.exists():
        print(f"[MiniDrifter] chains file not found: {chains_file}")
        return
    import json
    doc = json.loads(chains_file.read_text(encoding='utf-8'))
    chains = doc.get('chains') or []
    result = execute_chains(
        pack, chains,
        base_url=args.base_url,
        mode=args.mode,
        max_chains=args.max_chains,
        feedback_mode=getattr(args, 'feedback_mode', 'full'),
    )
    print(f"[MiniDrifter] execute-chains: completed={result['summary']['completed']} failed={result['summary']['failed']}")
    print(f"  output={result.get('output')}")


def main() -> None:
    from minidrifter.verification.search_progress import ensure_unbuffered_stdout
    ensure_unbuffered_stdout()

    parser = argparse.ArgumentParser(
        description=(
            'MiniDrifter (paper): static drift-oriented taint analyzer '
            '(RCR -> RPGraph -> RR-Drift chains) + dynamic perturbation validator'
        )
    )
    sub = parser.add_subparsers(dest='command')

    p1 = sub.add_parser('analyze', help='static extract: RCR -> RPGraph -> RR-Drift chains')
    p1.add_argument('--input', '-i', required=True, help='unpacked mini-program directory, zip file, or supported archive')
    p1.add_argument('--output', '-o', required=True, help='output directory')
    p1.add_argument('--platform', default='wechat', choices=['wechat', 'alipay', 'baidu', 'tiktok'], help='mini-program platform')
    p1.set_defaults(func=cmd_analyze)

    p_paper = sub.add_parser(
        'paper-static',
        help='rebuild RCR/RPGraph/RR-Drift propagation chains + scores',
    )
    p_paper.add_argument('--input-dir', '-i', required=True, help='existing OUTPUT pack directory')
    p_paper.add_argument('--max-workflows', type=int, default=120)
    p_paper.set_defaults(func=cmd_paper_static)

    p2 = sub.add_parser('optimize', help='run only the normalization/cleaning/ranking layer over existing MiniDrifter JSON outputs')
    p2.add_argument('--input-dir', '-i', required=True, help='directory containing existing MiniDrifter raw JSON outputs')
    p2.add_argument('--output', '-o', default=None, help='output directory; default overwrites/adds files in input-dir')
    p2.set_defaults(func=cmd_optimize)

    p3 = sub.add_parser('freeze-cards', help='freeze optimized static outputs into unified API Cards')
    p3.add_argument('--input-dir', '-i', required=True, help='directory with ranked_api_candidates.json and related outputs')
    p3.add_argument('--output', '-o', default=None, help='output directory; default writes into input-dir')
    p3.add_argument('--app-label', default=None, help='app label for pack_id; default is input directory name')
    p3.add_argument('--top-k', type=int, default=100, help='number of evidence packs to emit')
    p3.add_argument(
        '--include-registered-only',
        default='auto',
        choices=['auto', 'yes', 'no'],
        help='whether to emit registered_only cards',
    )
    p3.set_defaults(func=cmd_freeze_cards)

    p4 = sub.add_parser('audit-pack', help='build verification_readiness_panel.json from API Cards')
    p4.add_argument('--input-dir', '-i', required=True)
    p4.add_argument('--output', '-o', default=None)
    p4.set_defaults(func=cmd_audit_pack)

    p5 = sub.add_parser('detect-requirements', help='rule-based evidence_requirements.json (S1 ERD)')
    p5.add_argument('--input-dir', '-i', required=True)
    p5.add_argument('--output', '-o', default=None)
    p5.set_defaults(func=cmd_detect_requirements)

    p5b = sub.add_parser('plan-acquisition', help='rule acquisition plan; optional --with-llm for chain advisor')
    p5b.add_argument('--input-dir', '-i', required=True)
    p5b.add_argument('--output', '-o', default=None)
    p5b.add_argument('--with-llm', action='store_true', help='run LLM acquisition chain advisor after rule plan')
    p5b.add_argument('--limit', type=int, default=25, help='max focus cards for LLM advisor')
    p5b.add_argument('--dry-run', action='store_true')
    p5b.set_defaults(func=cmd_plan_acquisition)

    p5c = sub.add_parser(
        'generate-baseline-template',
        help='Steps 1-7: skeletons, domain tree, produces graph, material template (no replay)',
    )
    p5c.add_argument('--input-dir', '-i', required=True)
    p5c.add_argument('--output', '-o', default=None)
    p5c.add_argument('--stage1-limit', type=int, default=120, help='max target APIs for material compression')
    p5c.set_defaults(func=cmd_generate_baseline_template)

    p5d = sub.add_parser('import-baseline', help='import user HTTP/JSON materials → baseline_runtime_context.json')
    p5d.add_argument('--input-dir', '-i', required=True, help='pack output directory with baseline_material_template.json')
    p5d.add_argument('--materials-dir', '-m', required=True, help='directory with {material_id}.har|.json|.http files')
    p5d.add_argument('--output', '-o', default=None)
    p5d.add_argument('--intake-report', default=None, help='baseline_intake_report.json (default: auto from pack dir)')
    p5d.set_defaults(func=cmd_import_baseline)

    p5d2 = sub.add_parser('intake-baseline', help='validate/classify pasted HTTP captures → baseline_intake_report.json')
    p5d2.add_argument('--input-dir', '-i', required=True, help='pack dir with baseline_material_template.json')
    p5d2.add_argument('--file', '-f', required=True, help='raw HTTP file (single or multi-request)')
    p5d2.add_argument('--output', '-o', default=None)
    p5d2.add_argument('--source-dir', default=None, help='decompiled mini-program root (for http.js key extraction)')
    p5d2.add_argument('--write-splits', action='store_true', help='write recommended captures to user_materials/*.http')
    p5d2.add_argument('--import-after', action='store_true', help='run import-baseline after intake')
    p5d2.add_argument('--materialize-after', action='store_true', help='run materialize-templates after import (implies --import-after)')
    p5d2.add_argument('--limit', type=int, default=120, help='max templates when --materialize-after')
    p5d2.set_defaults(func=cmd_intake_baseline)

    p5flow = sub.add_parser(
        'run-flow',
        help='universal end-to-end: static → crypto-extract → intelligent intake → materialize → verify',
    )
    p5flow.add_argument('--input-dir', '-i', required=True, help='pack output directory')
    p5flow.add_argument('--project', '-p', default=None, help='decompiled mini-program root (static analyze)')
    p5flow.add_argument('--capture-file', '-f', default=None, help='baseline HTTP capture file')
    p5flow.add_argument('--source-dir', default=None, help='decompiled root for crypto key extraction')
    p5flow.add_argument('--skip-analyze', action='store_true')
    p5flow.add_argument('--skip-materialize', action='store_true')
    p5flow.add_argument('--skip-verify', action='store_true')
    p5flow.add_argument('--mode', choices=['dry-run', 'execute'], default='dry-run')
    p5flow.add_argument('--max-http', type=int, default=5)
    p5flow.add_argument('--max-seeds', type=int, default=2)
    p5flow.add_argument('--with-llm', action='store_true')
    p5flow.set_defaults(func=cmd_run_flow)

    p5loop = sub.add_parser(
        'run-closed-loop',
        help='account closed-loop: static → batch intake → materialize → campaign verify',
    )
    p5loop.add_argument('--input-dir', '-i', required=True, help='pack output directory')
    p5loop.add_argument('--project', '-p', default=None, help='decompiled mini-program root (static analyze)')
    p5loop.add_argument('--capture-file', '-f', default=None, help='baseline HTTP capture file (merged with batch)')
    p5loop.add_argument('--resume-file', default=None, help='apply capture then re-run closed loop')
    p5loop.add_argument('--source-dir', default=None, help='decompiled root for crypto key extraction')
    p5loop.add_argument('--chain-id', default=None, help='target business chain id (forces chain_strict)')
    p5loop.add_argument('--verify-mode', choices=['campaign', 'apex', 'chain_strict'], default='campaign',
                        help='campaign=top-N chain batch (default); apex=beam search; chain_strict=single chain')
    p5loop.add_argument('--skip-analyze', action='store_true')
    p5loop.add_argument('--skip-materialize', action='store_true')
    p5loop.add_argument('--skip-verify', action='store_true')
    p5loop.add_argument('--mode', choices=['dry-run', 'execute'], default='dry-run')
    p5loop.add_argument('--max-http', type=int, default=250)
    p5loop.add_argument('--max-chains', type=int, default=15)
    p5loop.add_argument('--campaign-source', choices=['rank_plan', 'frontier'], default='rank_plan',
                        help='rank_plan=legacy rank batch; frontier=coverage_frontier unlocked chains')
    p5loop.add_argument('--beam-width', type=int, default=8)
    p5loop.add_argument('--with-llm', action='store_true')
    p5loop.add_argument('--i-know', action='store_true', help='required for --mode execute (live HTTP)')
    p5loop.set_defaults(func=cmd_run_closed_loop)

    p_frontier = sub.add_parser(
        'plan-frontier-campaign',
        help='build campaign_frontier_plan.json from coverage_frontier (no HTTP)',
    )
    p_frontier.add_argument('--input-dir', '-i', required=True)
    p_frontier.add_argument('--max-chains', type=int, default=40)
    p_frontier.set_defaults(func=cmd_plan_frontier_campaign)

    p5d2b = sub.add_parser(
        'repair-baseline-version',
        help='sync AppVersion/Version from captures + static source; optional live probe',
    )
    p5d2b.add_argument('--input-dir', '-i', required=True)
    p5d2b.add_argument('--output', '-o', default=None)
    p5d2b.add_argument('--materials-dir', '-m', default=None, help='user_materials dir (default: pack/user_materials)')
    p5d2b.add_argument('--source-dir', default=None, help='decompiled mini-program root for static Version')
    p5d2b.add_argument('--version', default=None, help='force AppVersion/Version override')
    p5d2b.add_argument('--mode', choices=['dry-run', 'execute'], default='dry-run',
                       help='execute = live probe candidate versions against probe-path')
    p5d2b.add_argument('--probe-path', default='/Wechat/mobile/CurrentTime')
    p5d2b.add_argument('--base-url', default=None)
    p5d2b.add_argument('--i-know', action='store_true', help='required for --mode execute (live HTTP probe)')
    p5d2b.set_defaults(func=cmd_repair_baseline_version)

    p5d3 = sub.add_parser('crypto-replay', help='build signed GET request from decrypted baseline context')
    p5d3.add_argument('--input-dir', '-i', required=True)
    p5d3.add_argument('--path', required=True, help='API path e.g. /Wechat/User/Base/CacheInfo')
    p5d3.add_argument('--params', default='', help='plain query params e.g. userId=123')
    p5d3.add_argument('--base-url', default='', help='API base URL (default: Host from baseline context)')
    p5d3.add_argument('--source-dir', default=None, help='decompiled mini-program root for crypto keys')
    p5d3.add_argument('--output', '-o', default=None)
    p5d3.set_defaults(func=cmd_crypto_replay)

    p5e = sub.add_parser('materialize-templates', help='bind baseline context to N1 skeletons → materialized_api_templates.json')
    p5e.add_argument('--input-dir', '-i', required=True)
    p5e.add_argument('--output', '-o', default=None)
    p5e.add_argument('--limit', type=int, default=120, help='max stage-1 targets to materialize')
    p5e.add_argument('--force', action='store_true', help='regenerate even if templates appear fresh')
    p5e.add_argument('--replay-safe-only', action='store_true', help='only S0/S1 APIs')
    p5e.set_defaults(func=cmd_materialize_templates)

    p5v = sub.add_parser('plan-campaign', help='build verification_campaign.json + test_cases.jsonl (no HTTP)')
    p5v.add_argument('--input-dir', '-i', required=True)
    p5v.add_argument('--output', '-o', default=None)
    p5v.add_argument('--max-tests', type=int, default=10)
    p5v.add_argument('--only-safe', action='store_true', default=True)
    p5v.add_argument('--include-unsafe', action='store_true', help='include S2+ APIs')
    p5v.set_defaults(func=cmd_plan_campaign)

    p_run_campaign = sub.add_parser('run-campaign', help='plan → execute → analyze → next_action')
    p_run_campaign.add_argument('--input-dir', '-i', required=True)
    p_run_campaign.add_argument('--output', '-o', default=None)
    p_run_campaign.add_argument('--mode', choices=['dry-run', 'execute'], default='dry-run')
    p_run_campaign.add_argument('--only-safe', action='store_true', default=True)
    p_run_campaign.add_argument('--include-unsafe', action='store_true')
    p_run_campaign.add_argument('--max-tests', type=int, default=10)
    p_run_campaign.add_argument('--source-dir', default=None, help='decompiled mini-program root for crypto keys')
    p_run_campaign.add_argument('--base-url', default=None, help='API base URL override')
    p_run_campaign.add_argument('--i-know', action='store_true', help='required for --mode execute')
    p_run_campaign.add_argument('--with-llm', action='store_true', help='LLM test proposals + feedback plan (validated, advisory)')
    p_run_campaign.add_argument('--llm-dry-run', action='store_true', help='skip LLM API calls (structure only)')
    p_run_campaign.set_defaults(func=cmd_run_campaign)

    p_replay_preflight = sub.add_parser('replay-preflight', help='preflight gates before live campaign (crypto, params, URL)')
    p_replay_preflight.add_argument('--input-dir', '-i', required=True)
    p_replay_preflight.add_argument('--output', '-o', default=None)
    p_replay_preflight.add_argument('--source-dir', default=None)
    p_replay_preflight.add_argument('--base-url', default=None)
    p_replay_preflight.add_argument('--live-probe', action='store_true', help='optional live HTTP smoke test')
    p_replay_preflight.add_argument('--i-know', action='store_true', help='required for --live-probe')
    p_replay_preflight.set_defaults(func=cmd_replay_preflight)

    p_deep_verify = sub.add_parser(
        'run-deep-verify',
        help='full pipeline: materialize → preflight → Apex-PoC search → analysis report',
    )
    p_deep_verify.add_argument('--input-dir', '-i', required=True)
    p_deep_verify.add_argument('--output', '-o', default=None)
    p_deep_verify.add_argument('--mode', choices=['dry-run', 'execute'], default='dry-run')
    p_deep_verify.add_argument('--source-dir', default=None, help='decompiled mini-program root for crypto keys')
    p_deep_verify.add_argument('--base-url', default=None)
    p_deep_verify.add_argument('--search-mode', choices=['apex', 'pbws'], default='apex', help='apex (default) or legacy pbws')
    p_deep_verify.add_argument('--beam-width', type=int, default=5, help='parallel beam chains (apex mode)')
    p_deep_verify.add_argument('--anchor-api', default=None, help='api_id to prioritize for atomic probe (apex mode)')
    p_deep_verify.add_argument('--no-progress', action='store_true', help='suppress step-by-step progress lines')
    p_deep_verify.add_argument('--max-http', type=int, default=250, help='HTTP budget (default 250)')
    p_deep_verify.add_argument('--max-seeds', type=int, default=50, help='atomic probe API budget (default 50)')
    p_deep_verify.add_argument('--max-depth', type=int, default=5)
    p_deep_verify.add_argument('--max-llm', type=int, default=80, help='LLM call budget when --with-llm')
    p_deep_verify.add_argument('--ig-threshold', type=float, default=0.25)
    p_deep_verify.add_argument('--no-ig-prune', action='store_true')
    p_deep_verify.add_argument('--verify-mode', choices=['campaign', 'apex', 'chain_strict'], default='campaign',
                               help='campaign=top-N chain batch (default); apex=beam search; chain_strict=single chain')
    p_deep_verify.add_argument('--chain-id', default=None, help='business chain id (chain_strict mode)')
    p_deep_verify.add_argument('--max-tests', type=int, default=8, help='legacy campaign only')
    p_deep_verify.add_argument('--rounds', type=int, default=2, help='legacy campaign rounds')
    p_deep_verify.add_argument('--with-llm', action='store_true')
    p_deep_verify.add_argument('--deep-think', action='store_true', help='chain-level S-TRACE reasoning (quality over speed)')
    p_deep_verify.add_argument('--with-llm-chain', action='store_true', help='LLM chain reasoner (default: on when --deep-think --with-llm)')
    p_deep_verify.add_argument('--llm-dry-run', action='store_true')
    p_deep_verify.add_argument('--skip-materialize', action='store_true')
    p_deep_verify.add_argument('--force-materialize', action='store_true')
    p_deep_verify.add_argument('--live-preflight', action='store_true')
    p_deep_verify.add_argument('--only-safe', action='store_true', default=True)
    p_deep_verify.add_argument('--include-unsafe', action='store_true')
    p_deep_verify.add_argument('--i-know', action='store_true', help='required for --mode execute')
    p_deep_verify.add_argument('--resume', action='store_true', help='dismiss chain tickets and continue search')
    p_deep_verify.add_argument('--force-resume', action='store_true', help='clear global auth ticket (dev only)')
    p_deep_verify.set_defaults(func=cmd_run_deep_verify)

    p_verify_search = sub.add_parser(
        'run-verify-search',
        help='Apex-PoC (default) or PBWS verification search',
    )
    p_verify_search.add_argument('--input-dir', '-i', required=True)
    p_verify_search.add_argument('--output', '-o', default=None)
    p_verify_search.add_argument('--search-mode', choices=['apex', 'pbws'], default='apex')
    p_verify_search.add_argument('--beam-width', type=int, default=5)
    p_verify_search.add_argument('--anchor-api', default=None, help='api_id to prioritize for atomic probe')
    p_verify_search.add_argument('--no-progress', action='store_true', help='suppress step-by-step progress lines')
    p_verify_search.add_argument('--mode', choices=['dry-run', 'execute'], default='dry-run')
    p_verify_search.add_argument('--max-http', type=int, default=50)
    p_verify_search.add_argument('--max-seeds', type=int, default=8)
    p_verify_search.add_argument('--max-depth', type=int, default=5)
    p_verify_search.add_argument('--source-dir', default=None, help='decompiled mini-program root for crypto keys')
    p_verify_search.add_argument('--base-url', default=None)
    p_verify_search.add_argument('--skip-preflight', action='store_true')
    p_verify_search.add_argument('--no-mutations', action='store_true')
    p_verify_search.add_argument('--with-llm-strategy', action='store_true', help='A1 LLM seed strategy (S-TRACE)')
    p_verify_search.add_argument('--with-llm-workflow', action='store_true', help='A2 LLM workflow linker (S-TRACE)')
    p_verify_search.add_argument('--with-llm', action='store_true', help='apex: policy replanner; pbws: strategy+workflow')
    p_verify_search.add_argument('--with-llm-policy', action='store_true', help='apex mode LLM policy replanner')
    p_verify_search.add_argument('--with-llm-chain', action='store_true', help='LLM chain reasoner (default: on when --deep-think --with-llm)')
    p_verify_search.add_argument('--deep-think', action='store_true', help='chain-level S-TRACE reasoning per hop/block')
    p_verify_search.add_argument('--llm-dry-run', action='store_true', help='skip LLM API calls (trace structure only)')
    p_verify_search.add_argument('--max-llm', type=int, default=50, help='LLM call budget per search session')
    p_verify_search.add_argument('--ig-threshold', type=float, default=0.25, help='IG prune threshold (0-1)')
    p_verify_search.add_argument('--no-ig-prune', action='store_true', help='disable information-gain pruning')
    p_verify_search.add_argument('--only-safe', action='store_true', default=True)
    p_verify_search.add_argument('--include-unsafe', action='store_true')
    p_verify_search.add_argument('--verify-mode', choices=['apex', 'chain_strict'], default='apex')
    p_verify_search.add_argument('--chain-id', default=None)
    p_verify_search.add_argument('--i-know', action='store_true', dest='i_know', help='required for --mode execute')
    p_verify_search.set_defaults(func=cmd_run_verify_search)

    p5f = sub.add_parser(
        'refine-domain-unknown',
        help='patch domain UNKNOWN ops: method, side_effect, workflow plan (config-driven domain packs)',
    )
    p5f.add_argument('--input-dir', '-i', required=True)
    p5f.add_argument('--output', '-o', default=None)
    p5f.add_argument('--domain', default=None, help='comma-separated domain pack ids (default: all registered)')
    p5f.add_argument('--dry-run', action='store_true')
    p5f.set_defaults(func=cmd_refine_domain_unknown)

    p5g = sub.add_parser(
        'pack-refinement-pipeline',
        help='P0 analyze+merge → freeze → domain refine → optional downstream regen',
    )
    p5g.add_argument('--input', required=True, help='decompiled mini-program root')
    p5g.add_argument('--output', '-o', default=None, help='pack output directory')
    p5g.add_argument('--source', default=None, help='alias for --input')
    p5g.add_argument('--domain', default=None, help='domain pack(s) for refinement, comma-separated (default: all)')
    p5g.add_argument('--analyze', action='store_true', help='P0: re-run static analyze')
    p5g.add_argument('--no-freeze-cards', action='store_true', help='skip freeze-cards after analyze')
    p5g.add_argument('--regenerate-downstream', action='store_true', help='P2: skeletons + plan + materialize')
    p5g.set_defaults(func=cmd_pack_refinement_pipeline)

    p6 = sub.add_parser('reason', help='run evidence-constrained LLM reasoning tasks')
    p6.add_argument('--input-dir', '-i', required=True)
    p6.add_argument('--task', required=True, choices=['card_auditor', 'acquisition_advisor'])
    p6.add_argument('--tier', default=None, help='priority tier filter, e.g. P1')
    p6.add_argument('--card-id', default=None, help='audit a single card')
    p6.add_argument('--limit', type=int, default=50)
    p6.add_argument('--dry-run', action='store_true', help='select cards without calling LLM')
    p6.set_defaults(func=cmd_reason)

    p7 = sub.add_parser('verify-prepare', help='audit + ERD + plan + optional LLM advisor & card auditor')
    p7.add_argument('--input-dir', '-i', required=True)
    p7.add_argument('--output', '-o', default=None)
    p7.add_argument('--with-llm', action='store_true')
    p7.add_argument('--tier', default='P1')
    p7.add_argument('--limit', type=int, default=5, help='card_auditor limit')
    p7.add_argument('--advisor-limit', type=int, default=25, help='acquisition_advisor focus cards')
    p7.add_argument('--dry-run', action='store_true')
    p7.set_defaults(func=cmd_verify_prepare)

    wb = sub.add_parser('workbench', help='MiniDrifter Workbench — multi-project scan, gates, user intake')
    wb_sub = wb.add_subparsers(dest='workbench_cmd', required=True)

    p_wb_scan = wb_sub.add_parser('scan', help='scan folder for all mini-program projects')
    p_wb_scan.add_argument('workspace', help='folder containing one or more mini-program projects')
    p_wb_scan.set_defaults(func=cmd_workbench_scan)

    p_wb_gate = wb_sub.add_parser('gate', help='decompile or pack readiness gate')
    p_wb_gate.add_argument('--project', '-p', default=None, help='decompiled project root')
    p_wb_gate.add_argument('--pack-dir', '-i', default=None, help='MiniDrifter pack output dir')
    p_wb_gate.set_defaults(func=cmd_workbench_gate)

    p_wb_intake = wb_sub.add_parser('intake-prompt', help='generate ordered user capture checklist')
    p_wb_intake.add_argument('--input-dir', '-i', required=True, help='pack output dir')
    p_wb_intake.set_defaults(func=cmd_workbench_intake_prompt)

    p_wb_roadmap = wb_sub.add_parser('roadmap', help='show pipeline stage and next user action')
    p_wb_roadmap.add_argument('--workspace', '-w', default=None)
    p_wb_roadmap.add_argument('--project', '-p', default=None)
    p_wb_roadmap.add_argument('--input-dir', '-i', default=None, help='pack dir')
    p_wb_roadmap.set_defaults(func=cmd_workbench_roadmap)

    p_wb_resume = wb_sub.add_parser('resume', help='apply user pasted HTTP capture after operator pause')
    p_wb_resume.add_argument('--input-dir', '-i', required=True)
    p_wb_resume.add_argument('--file', '-f', required=True, help='raw HTTP or HAR capture file')
    p_wb_resume.add_argument('--ticket-id', default=None, help='resolve blocking_tickets.json entry')
    p_wb_resume.add_argument('--import-after', action='store_true', help='merge intake into baseline_runtime_context')
    p_wb_resume.add_argument('--bootstrap-after', action='store_true', help='rebuild runtime index, pools, templates, replay context')
    p_wb_resume.set_defaults(func=cmd_workbench_resume)

    p_bootstrap = sub.add_parser('baseline-bootstrap', help='rebuild baseline-adjacent artifacts (index, pools, templates, replay context)')
    p_bootstrap.add_argument('--input-dir', '-i', required=True)
    p_bootstrap.add_argument('--baseline-dir', default=None, help='rescan baseline/*.http directory')
    p_bootstrap.add_argument('--source-dir', default=None)
    p_bootstrap.add_argument('--rescan', action='store_true', help='re-import baseline directory before bootstrap')
    p_bootstrap.add_argument('--skip-materialize', action='store_true')
    p_bootstrap.add_argument('--skip-rebuild-context', action='store_true')
    p_bootstrap.add_argument('--limit', type=int, default=120)
    p_bootstrap.set_defaults(func=cmd_baseline_bootstrap)

    p_wb_run = wb_sub.add_parser(
        'run',
        help='full pipeline: prepare → dashboard → intake → deep-verify (P2)',
    )
    p_wb_run.add_argument('--input-dir', '-i', required=True, help='pack output dir')
    p_wb_run.add_argument('--project', '-p', default=None, help='decompiled mini-program root (static analyze)')
    p_wb_run.add_argument('--workspace', '-w', default=None, help='scan workspace and pick project')
    p_wb_run.add_argument('--source-dir', default=None, help='source for crypto/replay preflight')
    p_wb_run.add_argument('--base-url', default=None)
    p_wb_run.add_argument('--skip-analyze', action='store_true', help='use existing static pack')
    p_wb_run.add_argument('--skip-verify', action='store_true', help='stop after intake/dashboard')
    p_wb_run.add_argument('--skip-materialize', action='store_true')
    p_wb_run.add_argument('--with-llm', action='store_true')
    p_wb_run.add_argument('--deep-think', action='store_true')
    p_wb_run.add_argument('--mode', default='dry-run', choices=['dry-run', 'execute'])
    p_wb_run.add_argument('--i-know', action='store_true', dest='i_know')
    p_wb_run.add_argument('--max-http', type=int, default=250)
    p_wb_run.add_argument('--max-seeds', type=int, default=50)
    p_wb_run.add_argument('--max-depth', type=int, default=5)
    p_wb_run.add_argument('--max-llm', type=int, default=80)
    p_wb_run.add_argument('--beam-width', type=int, default=5)
    p_wb_run.add_argument('--anchor-api', default=None)
    p_wb_run.add_argument('--resume', action='store_true', help='continue after ticket; dismiss chain tickets')
    p_wb_run.add_argument('--resume-file', default=None, help='apply capture then resume verify')
    p_wb_run.add_argument('--verify-mode', choices=['apex', 'chain_strict'], default='apex')
    p_wb_run.add_argument('--chain-id', default=None)
    p_wb_run.set_defaults(func=cmd_workbench_run)

    # Alias: scan-workspace
    p_scan_ws = sub.add_parser('scan-workspace', help='alias for workbench scan')
    p_scan_ws.add_argument('workspace', help='folder containing mini-program projects')
    p_scan_ws.set_defaults(func=cmd_workbench_scan)

    from minidrifter.orchestration.console.workspace_layout import default_workspace as _default_ws
    p_console = sub.add_parser('console', help='wizard workbench (same as run_minidrifter.py)')
    p_console.add_argument('--workspace', '-w', default=str(_default_ws()))
    p_console.add_argument('--menu', action='store_true', help='legacy menu mode')
    p_console.add_argument('--skip-verify', action='store_true')
    p_console.add_argument('--input-dir', '-i', default=None, help='(menu mode) pack dir')
    p_console.add_argument('--project', '-p', default=None, help='(menu mode) project root')
    p_console.set_defaults(func=cmd_console)

    p_batch = sub.add_parser('static-batch-eval', help='analyze all Workspace projects + static acceptance gates')
    p_batch.add_argument('--workspace', '-w', default=str(_default_ws()))
    p_batch.add_argument('--skip-analyze', action='store_true', help='reuse existing OUTPUT packs')
    p_batch.add_argument('--only', default=None, help='substring filter on project name')
    p_batch.set_defaults(func=cmd_static_batch_eval)

    p_trace = sub.add_parser(
        'prepare-trace-kit',
        help='create CRBD_validation/trace + 抓包指引.md for Workspace projects (§3 prelude)',
    )
    p_trace.add_argument('--workspace', '-w', default=str(_default_ws()), help='Workspace root (batch mode)')
    p_trace.add_argument('--project', '-p', default=None, help='single project directory')
    p_trace.add_argument('--input-dir', '-i', default=None, help='OUTPUT pack dir (optional with --project)')
    p_trace.add_argument('--only', default=None, help='substring filter on project name (batch)')
    p_trace.add_argument('--max-workflows', type=int, default=12, help='workflows listed in the guide')
    p_trace.set_defaults(func=cmd_prepare_trace_kit)

    p_crbd = sub.add_parser(
        'RR-Drift-probe',
        help='approach §3 RR-Drift dynamic probe over τ_A/τ_B + workflows/drift_plans',
    )
    p_crbd.add_argument('--workspace', '-w', default=str(_default_ws()))
    p_crbd.add_argument('--project', '-p', default=None)
    p_crbd.add_argument('--input-dir', '-i', default=None)
    p_crbd.add_argument('--only', default=None)
    p_crbd.add_argument('--max-workflows', type=int, default=20)
    p_crbd.add_argument('--live', action='store_true', help='also run legacy closed-loop verify')
    p_crbd.add_argument('--mode', choices=['dry-run', 'execute'], default='dry-run')
    p_crbd.add_argument('--i-know', action='store_true', help='required with --live --mode execute')
    p_crbd.add_argument(
        '--self-verify',
        action='store_true',
        help='same-subject self-verification using τ_A only (no τ_B; not paper ConfirmRRDrift)',
    )
    p_crbd.set_defaults(func=cmd_crbd_probe)

    p_ss = sub.add_parser(
        'single-subject-probe',
        help='single-account RR-Drift probe: drift from own τ_A baseline with real HTTP',
    )
    p_ss.add_argument('--workspace', '-w', default=str(_default_ws()))
    p_ss.add_argument('--project', '-p', default=None)
    p_ss.add_argument('--only', default=None)
    p_ss.add_argument('--mode', choices=['dry-run', 'execute'], default='execute')
    p_ss.add_argument('--max-targets', type=int, default=40)
    p_ss.add_argument('--enum-radius', type=int, default=0, help='±N numeric donor enum on positive subject/object ids')
    p_ss.add_argument('--enum-budget', type=int, default=12, help='max enum donors per positive target')
    p_ss.add_argument('--i-know', action='store_true', help='required for --mode execute')
    p_ss.set_defaults(func=cmd_single_subject_probe)

    p_ir = sub.add_parser('ir-export', help='export Universal IR bundle from pack')
    p_ir.add_argument('--input-dir', '-i', required=True)

    # ── 新增：Chain Composer / Feedback / Active Probe / Chain Executor ──
    p_cc = sub.add_parser('compose-chains', help='auto-compose exploit chains from BCG + HAR')
    p_cc.add_argument('--input-dir', '-i', required=True, help='pack directory')
    p_cc.add_argument('--har', '-f', default=None, help='HAR file for dynamic trace')
    p_cc.add_argument('--max-chains', type=int, default=50)
    p_cc.add_argument('--no-har-first', action='store_true', help='do not prefer/filter HAR business APIs')
    p_cc.add_argument('--no-align-crypto', action='store_true', help='skip HAR key alignment before compose')
    p_cc.set_defaults(func=cmd_compose_chains)

    p_hcp = sub.add_parser(
        'har-RR-Drift-probe',
        help='limited live RR-Drift probe on high-value HAR business APIs (account/card/invoice/…)',
    )
    p_hcp.add_argument('--input-dir', '-i', required=True, help='pack directory')
    p_hcp.add_argument('--har', '-f', default=None, help='HAR file (default: ../CRBD_validation/.../full_session.har)')
    p_hcp.add_argument('--base-url', '-u', default='', help='optional base URL override')
    p_hcp.add_argument('--max-targets', type=int, default=8)
    p_hcp.add_argument('--mode', choices=['dry-run', 'execute'], default='dry-run')
    p_hcp.add_argument('--no-align-crypto', action='store_true')
    p_hcp.add_argument('--i-know', action='store_true', help='required for live HTTP')
    p_hcp.set_defaults(func=cmd_har_crbd_probe)

    p_fb = sub.add_parser('feedback-stats', help='show feedback engine statistics')
    p_fb.add_argument('--input-dir', '-i', required=True)
    p_fb.set_defaults(func=cmd_feedback_stats)

    p_ap = sub.add_parser('active-probe', help='active probing: scan + oracle + enumerate')
    p_ap.add_argument('--input-dir', '-i', required=True, help='pack directory')
    p_ap.add_argument('--base-url', '-u', required=True, help='target base URL')
    p_ap.add_argument('--scan-paths', nargs='*', default=None, help='paths to scan')
    p_ap.add_argument('--oracle-endpoint', default=None)
    p_ap.add_argument('--oracle-param', default=None)
    p_ap.add_argument('--oracle-values', nargs='*', default=None)
    p_ap.add_argument('--enum-idcard', action='store_true')
    p_ap.add_argument('--enum-areas', nargs='*', default=None)
    p_ap.add_argument('--i-know', action='store_true', help='required for live probing')
    p_ap.set_defaults(func=cmd_active_probe)

    p_ce = sub.add_parser('execute-chains', help='execute composed chains with feedback')
    p_ce.add_argument('--input-dir', '-i', required=True, help='pack directory')
    p_ce.add_argument('--base-url', '-u', required=True)
    p_ce.add_argument('--chains-file', default=None, help='exploit_chains.json path')
    p_ce.add_argument('--mode', choices=['dry-run', 'execute'], default='dry-run')
    p_ce.add_argument('--max-chains', type=int, default=20)
    p_ce.add_argument(
        '--feedback-mode',
        choices=['full', 'one-shot', 'no-node', 'no-workflow'],
        default='full',
        help='Fig.4 ablation: full | one-shot | no-node | no-workflow',
    )
    p_ce.add_argument('--i-know', action='store_true')
    p_ce.set_defaults(func=cmd_execute_chains)
    p_ir.add_argument('--profile', default=None, help='profile id from packs/profiles/')
    p_ir.set_defaults(func=cmd_ir_export)

    p_prof = sub.add_parser('profile-resolve', help='detect adapter profile for a pack directory')
    p_prof.add_argument('--input-dir', '-i', required=True)
    p_prof.add_argument('--profile', default=None, help='force profile id override')
    p_prof.set_defaults(func=cmd_profile_resolve)

    p_crypto = sub.add_parser('crypto-extract', help='extract crypto keys from decompiled JS → crypto_static_profile.json')
    p_crypto.add_argument('--input-dir', '-i', required=True, help='pack output directory')
    p_crypto.add_argument('--source-dir', default=None, help='decompiled mini-program root')
    p_crypto.add_argument('--profile', default=None, help='force crypto profile id')
    p_crypto.set_defaults(func=cmd_crypto_extract)

    p_sig = sub.add_parser(
        'mine-signature-profile',
        help='P5: mine static signature logic and verify against baseline captures',
    )
    p_sig.add_argument('--input-dir', '-i', required=True, help='pack output directory')
    p_sig.add_argument('--source-dir', default=None, help='decompiled mini-program root')
    p_sig.set_defaults(func=cmd_mine_signature_profile)

    p_bench = sub.add_parser('benchmark', help='collect cross-app benchmark metrics')
    p_bench.add_argument('--pack', '-p', default=None, help='single pack dir to score')
    p_bench.add_argument('--profile', default=None)
    p_bench.set_defaults(func=cmd_benchmark)

    p_mine_sw = sub.add_parser(
        'mine-subject-wire-candidates',
        help='P4-fix-5.1: mine sensitive APIs with subject fields on request wire',
    )
    p_mine_sw.add_argument('--input-dir', '-i', required=True)
    p_mine_sw.add_argument('--verbose', action='store_true')
    p_mine_sw.set_defaults(func=cmd_mine_subject_wire_candidates)

    p_sac = sub.add_parser(
        'write-sensitive-binding-coverage',
        help='aggregate sensitive API replay/testability/conclusion from existing OUTPUT artifacts',
    )
    p_sac.add_argument('--input-dir', '-i', required=True)
    p_sac.set_defaults(func=cmd_write_sensitive_binding_coverage)

    p_gap_sw = sub.add_parser(
        'plan-subject-wire-gap',
        help='P4-fix-5.2: plan subject-wire capture gaps from static schema vs baseline',
    )
    p_gap_sw.add_argument('--input-dir', '-i', required=True)
    p_gap_sw.add_argument('--max-gaps', type=int, default=24)
    p_gap_sw.add_argument('--verbose', action='store_true')
    p_gap_sw.set_defaults(func=cmd_plan_subject_wire_gap)

    p_run_so = sub.add_parser(
        'run-sensitive-subject-override',
        help='P4-fix-5: mine wire candidates then run M0/M7-subject override batch',
    )
    p_run_so.add_argument('--input-dir', '-i', required=True)
    p_run_so.add_argument('--source-dir', default=None, help='decompiled mini-program root for crypto')
    p_run_so.add_argument('--base-url', default=None)
    p_run_so.add_argument('--mode', choices=['dry-run', 'execute'], default='dry-run')
    p_run_so.add_argument('--max-targets', type=int, default=10)
    p_run_so.add_argument('--max-http', type=int, default=30)
    p_run_so.add_argument('--verbose', action='store_true')
    p_run_so.add_argument('--i-know', action='store_true', help='required for --mode execute')
    p_run_so.set_defaults(func=cmd_run_sensitive_subject_override)

    p_bind = sub.add_parser(
        'run-binding-campaign',
        help='unified binding campaign: eligibility matrix + final_binding_report',
    )
    p_bind.add_argument('--input-dir', '-i', required=True)
    p_bind.add_argument('--source-dir', default=None)
    p_bind.add_argument('--mode', choices=['safe', 'dry-run', 'execute'], default='safe')
    p_bind.add_argument('--max-targets', type=int, default=10)
    p_bind.add_argument('--max-http', type=int, default=30)
    p_bind.add_argument('--base-url', default=None)
    p_bind.add_argument('--i-know', action='store_true', help='required for --mode execute')
    p_bind.set_defaults(func=cmd_run_binding_campaign)

    p_replay_ctx = sub.add_parser(
        'build-sensitive-replay-context',
        help='rebuild sensitive_replay_context + wire miners before campaign',
    )
    p_replay_ctx.add_argument('--input-dir', '-i', required=True)
    p_replay_ctx.set_defaults(func=cmd_build_sensitive_replay_context)

    # Backward compatible mode: `python -m minidrifter.cli --input ... --output ...`
    parser.add_argument('--input', help=argparse.SUPPRESS)
    parser.add_argument('--output', help=argparse.SUPPRESS)
    parser.add_argument('--platform', default='wechat', choices=['wechat', 'alipay', 'baidu', 'tiktok'], help=argparse.SUPPRESS)
    args = parser.parse_args()
    if hasattr(args, 'func'):
        args.func(args)
    elif args.input and args.output:
        cmd_analyze(args)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
