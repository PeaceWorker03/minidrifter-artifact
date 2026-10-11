# -*- coding: utf-8 -*-
"""Baseline bootstrap — rebuild runtime index, pools, templates, replay context."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional

from minidrifter.materials.baseline_capture_requirements import write_baseline_capture_requirements
from minidrifter.materials.capture_sequence import write_capture_sequence
from minidrifter.materials.runtime_capture_index import write_runtime_capture_index
from minidrifter.materials.runtime_pools import write_runtime_pools
from minidrifter.orchestration.baseline_readiness import write_baseline_readiness_report


def run_baseline_bootstrap(
    pack_dir: Path,
    *,
    source_dir: Optional[Path] = None,
    rescan_baseline_dir: Optional[Path] = None,
    materialize: bool = True,
    rebuild_sensitive_context: bool = True,
    limit: int = 120,
) -> Dict[str, Any]:
    """Rebuild baseline-adjacent artifacts up to campaign-ready state (no M7 execute)."""
    pack_dir = Path(pack_dir)
    from minidrifter.orchestration.console.workspace_layout import ensure_baseline_for_pack

    layout = ensure_baseline_for_pack(pack_dir)
    steps: list[str] = ['ensure_baseline_dir']
    errors: Dict[str, str] = {}

    try:
        from minidrifter.classification.api_plane_classifier import write_api_plane_index
        write_api_plane_index(pack_dir)
        steps.append('api_plane_index')
    except Exception as exc:
        errors['api_plane_index'] = str(exc)

    try:
        from minidrifter.orchestration.project_dashboard import write_project_dashboard
        write_project_dashboard(pack_dir, project_name=pack_dir.name)
        steps.append('project_dashboard')
    except Exception as exc:
        errors['project_dashboard'] = str(exc)

    if source_dir:
        try:
            from minidrifter.runtime.crypto.static_emit import emit_crypto_static_profile
            emit_crypto_static_profile(pack_dir, source_dir=source_dir)
            steps.append('crypto_static_profile')
        except Exception as exc:
            errors['crypto_static_profile'] = str(exc)

    if rescan_baseline_dir and rescan_baseline_dir.is_dir():
        try:
            import json
            from minidrifter.materials.baseline_importer import import_baseline_from_directory
            from minidrifter.core.utils import write_json as wj

            tmpl_path = pack_dir / 'baseline_material_template.json'
            if tmpl_path.exists():
                template = json.loads(tmpl_path.read_text(encoding='utf-8'))
                intake_report = None
                ir_path = pack_dir / 'baseline_intake_report.json'
                if ir_path.exists():
                    intake_report = json.loads(ir_path.read_text(encoding='utf-8'))
                ctx = import_baseline_from_directory(
                    rescan_baseline_dir, template, intake_report=intake_report,
                )
                wj(pack_dir / 'baseline_runtime_context.json', ctx)
                steps.append('import_baseline_directory')
        except Exception as exc:
            errors['rescan'] = str(exc)

    from minidrifter.classification.subject_wire_gap_planner import build_subject_wire_gap_plan
    build_subject_wire_gap_plan(pack_dir, write=True)
    steps.append('subject_wire_gap_plan')

    rci_path = write_runtime_capture_index(pack_dir)
    steps.append('runtime_capture_index')

    pool_paths = write_runtime_pools(pack_dir)
    steps.append('runtime_pools')

    try:
        intake_report = None
        ir_path = pack_dir / 'baseline_intake_report.json'
        if ir_path.exists():
            import json
            intake_report = json.loads(ir_path.read_text(encoding='utf-8'))
            write_capture_sequence(pack_dir, intake_report)
        steps.append('capture_sequence')
    except Exception as exc:
        errors['capture_sequence'] = str(exc)

    try:
        from minidrifter.quality.runtime_reachability.capture_anchor_planner import write_dual_plane_artifacts
        write_dual_plane_artifacts(pack_dir)
        steps.append('runtime_alias_map')
    except Exception as exc:
        errors['runtime_alias_map'] = str(exc)

    req_paths = write_baseline_capture_requirements(pack_dir)
    steps.append('baseline_capture_requirements')

    if materialize:
        try:
            import json
            from minidrifter.reasoning.pack_loader import load_pack
            from minidrifter.materials.slot_binder import build_materialized_templates
            from minidrifter.materials.intake_param_hints import resolve_intake_capture_card_ids
            from minidrifter.business_chain.chain_targets import (
                collect_chain_materialization_targets,
                merge_materialization_targets,
            )

            ctx_path = pack_dir / 'baseline_runtime_context.json'
            ctx = json.loads(ctx_path.read_text(encoding='utf-8'))
            pack = load_pack(str(pack_dir))
            sk_path = pack_dir / 'runtime_skeletons.json'
            skeletons = json.loads(sk_path.read_text(encoding='utf-8')) if sk_path.exists() else {}
            by_id = skeletons.get('by_card_id') or {
                s['card_id']: s for s in skeletons.get('skeletons', [])
            }
            intake_report = json.loads((pack_dir / 'baseline_intake_report.json').read_text(encoding='utf-8'))
            target_ids = resolve_intake_capture_card_ids(intake_report, pack['cards_by_id'])
            chain_ids = collect_chain_materialization_targets(pack_dir, max_ids=limit)
            target_ids = merge_materialization_targets(chain_ids, target_ids, limit=limit)
            result = build_materialized_templates(
                pack['cards_by_id'], by_id, ctx,
                target_api_ids=target_ids,
                pack_dir=pack_dir,
                intake_report=intake_report,
            )
            from minidrifter.core.utils import write_json as wj
            wj(pack_dir / 'materialized_api_templates.json', result)
            steps.append('materialized_api_templates')
        except Exception as exc:
            errors['materialize'] = str(exc)

    if rebuild_sensitive_context:
        try:
            from minidrifter.verification.binding_campaign_runner import rebuild_binding_campaign_artifacts
            rebuild_binding_campaign_artifacts(pack_dir)
            steps.append('sensitive_replay_context_and_wire_candidates')
        except Exception as exc:
            errors['rebuild_sensitive_context'] = str(exc)

    readiness_path = write_baseline_readiness_report(pack_dir)
    steps.append('baseline_readiness_report')

    from minidrifter.orchestration.baseline_readiness import build_baseline_readiness_report
    readiness = build_baseline_readiness_report(pack_dir)

    return {
        'pack_dir': str(pack_dir),
        'steps_completed': steps,
        'errors': errors,
        'artifacts': {
            'runtime_capture_index': str(rci_path),
            'pools': {k: str(v) for k, v in pool_paths.items()},
            'baseline_capture_requirements_md': str(req_paths.get('md')),
            'baseline_readiness_report': str(readiness_path),
        },
        'readiness': readiness,
    }
