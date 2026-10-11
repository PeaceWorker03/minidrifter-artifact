# -*- coding: utf-8
"""Print static analysis summary after step 3."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from minidrifter.core.utils import write_json
from minidrifter.orchestration.console.display import artifact, panel, status, table


def _load(path: Path) -> Any:
    if path.exists():
        return json.loads(path.read_text(encoding='utf-8'))
    return None


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def build_static_report(pack_dir: Path) -> Dict[str, Any]:
    pack_dir = Path(pack_dir)
    dash = _load(pack_dir / 'project_dashboard.json') or {}
    panel_doc = _load(pack_dir / 'verification_readiness_panel.json') or {}
    erd = _load(pack_dir / 'evidence_requirements.json') or {}
    plan = _load(pack_dir / 'acquisition_plan.json') or {}
    manifest = _load(pack_dir / 'api_card_pack_manifest.json') or {}
    profile = _load(pack_dir / 'project_profile.json') or {}
    adapter = _load(pack_dir / 'adapter_profile.json') or {}

    funnel = panel_doc.get('funnel') or {}
    inv = erd.get('erd_inventory') or {}
    plan_sum = plan.get('plan_summary') or {}
    inv_cards = manifest.get('card_inventory') or {}

    n1_dist = panel_doc.get('runtime_requirement_distribution') or {}
    n0 = n1_dist.get('N0_STATIC_TEMPLATE', 0)
    n1 = n1_dist.get('N1_BASELINE_RUNTIME_TEMPLATE', 0)

    top_n1 = (panel_doc.get('n1_runtime_template_candidates') or {}).get('top_cards') or []
    binding_doc = _load(pack_dir / 'binding_risk_candidates.json') or {}
    top_binding = (binding_doc.get('candidates') or [])[:12]
    chain_plan = _load(pack_dir / 'chain_rank_plan.json') or {}
    chain_mat = _load(pack_dir / 'chain_material_request_plan.json') or {}
    chains_doc = _load(pack_dir / 'business_chains.json') or {}

    report = {
        'schema_version': '1.0.0',
        'generated_at': _utc_now(),
        'pack_dir': str(pack_dir),
        'project_profile': {
            'shape': profile.get('shape') or dash.get('shape'),
            'platform': profile.get('platform_guess'),
            'obfuscation': (profile.get('obfuscation') or {}).get('level'),
        },
        'adapter_profile': adapter,
        'api_surface': {
            'total_api_cards': funnel.get('total_cards') or dash.get('api_card_count') or inv_cards.get('total'),
            'operation_cards': funnel.get('operation_cards'),
            'replay_ready': funnel.get('replay_ready'),
            'priority_p0': funnel.get('priority_p0'),
            'priority_p1': funnel.get('priority_p1'),
            'fuzzing_gate_pass': funnel.get('fuzzing_gate_pass'),
        },
        'n0_n1': {
            'n0_static_template': n0,
            'n1_baseline_runtime': n1 or dash.get('n1_count'),
            'operation_with_binding_check': inv.get('operation_with_binding_check'),
            'blocking_histogram': inv.get('blocking_missing_histogram'),
        },
        'verification_plan': {
            'stage_1_targets': plan_sum.get('stage_1_target_count') or dash.get('stage_1_targets'),
            'material_packages': plan_sum.get('material_package_count') or dash.get('material_packages'),
            'auto_discovery': plan_sum.get('auto_discovery_count'),
            'deferred': plan_sum.get('deferred_count'),
        },
        'top_verify_candidates': [
            {
                'path': c.get('path'),
                'method': c.get('method'),
                'tier': c.get('priority_tier'),
                'replay': c.get('replay_readiness'),
                'kind': 'replay_ready_sort',
            }
            for c in top_n1[:8]
        ],
        'top_binding_risk_candidates': [
            {
                'api_id': c.get('api_id'),
                'path': c.get('path'),
                'method': c.get('method'),
                'combined_score': c.get('combined_score'),
                'probe_eligible': c.get('probe_eligible'),
                'intake_anchor': c.get('intake_anchor'),
                'signals': (c.get('risk_signals') or [])[:4],
            }
            for c in top_binding
        ],
        'binding_risk_summary': binding_doc.get('summary'),
        'business_chain_summary': {
            'verification_scope': chain_plan.get('verification_scope', 'single_account'),
            'chains_recovered': chains_doc.get('chain_count'),
            'top_chains_ranked': len(chain_plan.get('top_chains') or []),
            'material_requests': chain_mat.get('request_count'),
        },
        'top_business_chains': [
            {
                'rank': c.get('rank'),
                'chain_id': c.get('chain_id'),
                'chain_type': c.get('chain_type'),
                'entry_path': c.get('entry_path'),
                'target_path': c.get('target_path'),
                'score': c.get('score'),
                'binding_fields': (c.get('binding_fields') or [])[:4],
            }
            for c in (chain_plan.get('top_chains') or [])[:8]
        ],
        'chain_capture_requests': [
            {
                'priority': r.get('priority'),
                'action': r.get('recommended_user_action'),
                'example_paths': r.get('example_paths'),
                'unlocks_chains': len((r.get('unlocks') or {}).get('chains') or []),
            }
            for r in (chain_mat.get('requests') or [])[:5]
        ],
        'artifacts': {
            'api_cards': str(pack_dir / 'api_cards.json'),
            'evidence_requirements': str(pack_dir / 'evidence_requirements.json'),
            'acquisition_plan': str(pack_dir / 'acquisition_plan.json'),
            'runtime_demand_graph': str(pack_dir / 'runtime_demand_graph_preview.json'),
        },
    }
    write_json(pack_dir / 'static_analysis_report.json', report)
    return report


def print_static_report(pack_dir: Path) -> Dict[str, Any]:
    pack_dir = Path(pack_dir)
    try:
        from minidrifter.ir.export import export_universal_ir
        export_universal_ir(pack_dir)
    except Exception:
        pass

    report = build_static_report(pack_dir)
    surf = report.get('api_surface') or {}
    n01 = report.get('n0_n1') or {}
    plan = report.get('verification_plan') or {}
    prof = report.get('project_profile') or {}
    adapter = report.get('adapter_profile') or {}

    panel('静态分析结果摘要', [
        f'项目形态: {prof.get("shape")}  |  平台: {prof.get("platform")}  |  混淆: {prof.get("obfuscation") or "-"}',
        f'Adapter Profile: {adapter.get("profile_id") or "-"}  |  Request: {adapter.get("request_adapter") or "-"}',
        f'API Cards 总数: {surf.get("total_api_cards")}',
        f'业务 Operation: {surf.get("operation_cards")}  |  Replay就绪: {surf.get("replay_ready")}',
        f'优先级 P0: {surf.get("priority_p0")}  |  P1: {surf.get("priority_p1")}  |  Fuzz门通过: {surf.get("fuzzing_gate_pass")}',
        f'N0 静态可试: {n01.get("n0_static_template")}  |  N1 需Baseline: {n01.get("n1_baseline_runtime")}',
        f'绑定检测接口: {n01.get("operation_with_binding_check")}',
        f'阶段1验证目标: {plan.get("stage_1_targets")}  |  材料包: {plan.get("material_packages")}',
    ])

    rows = [
        (c.get('path', '?'), c.get('method', '?'), c.get('tier', '?'), c.get('replay', '?'))
        for c in (report.get('top_verify_candidates') or [])
    ]
    if rows:
        print(status('Replay-ready 候选 (Top 8, 按 materialize 就绪排序)', 'INFO'))
        table(['Path', 'Method', 'Tier', 'Replay'], rows, col_widths=[36, 8, 6, 10])

    br_rows = [
        (
            c.get('path', '?')[:36],
            c.get('method', '?'),
            str(c.get('combined_score', '?')),
            'Y' if c.get('probe_eligible') else '-',
            'Y' if c.get('intake_anchor') else '-',
        )
        for c in (report.get('top_binding_risk_candidates') or [])
    ]
    if br_rows:
        print(status('绑定风险优先 (Top 12, 规则+可选LLM — 用于链式探测)', 'INFO'))
        table(['Path', 'Method', 'Risk', 'Probe', 'Capture'], br_rows, col_widths=[36, 8, 6, 6, 8])
        br_sum = report.get('binding_risk_summary') or {}
        if br_sum.get('external_excluded'):
            print(status(
                f"已排除 {br_sum.get('external_excluded')} 个第三方 SDK 路径; "
                f"可探测 {br_sum.get('probe_eligible_count')} 个",
                'INFO',
            ))

    ir_export = _load(pack_dir / 'universal_ir' / 'universal_n_tier_summary.json') or {}
    n_tier_dist = ir_export.get('distribution') or {}
    if n_tier_dist:
        print(status(f'Universal N-tier 分布: {n_tier_dist}', 'INFO'))
    hist = n01.get('blocking_histogram') or {}
    if hist:
        print(status(f'N1 阻塞字段分布: {hist}', 'INFO'))

    md_lines = [
        '# Static Analysis Report',
        '',
        f'- Shape: {prof.get("shape")}',
        f'- API cards: {surf.get("total_api_cards")}',
        f'- N0 / N1: {n01.get("n0_static_template")} / {n01.get("n1_baseline_runtime")}',
        f'- Stage-1 targets: {plan.get("stage_1_targets")}',
        '',
        '## Top candidates (replay-ready sort)',
        '',
    ]
    for c in report.get('top_verify_candidates') or []:
        md_lines.append(f'- `{c.get("method")} {c.get("path")}` ({c.get("tier")})')
    md_lines.extend([
        '',
        '## Binding-risk priority (for chain probing)',
        '',
    ])
    for c in report.get('top_binding_risk_candidates') or []:
        md_lines.append(
            f'- `{c.get("method")} {c.get("path")}` score={c.get("combined_score")} '
            f'probe={c.get("probe_eligible")}'
        )
    (Path(pack_dir) / 'static_analysis_report.md').write_text('\n'.join(md_lines), encoding='utf-8')

    artifact(Path(pack_dir) / 'static_analysis_report.json')
    artifact(Path(pack_dir) / 'static_analysis_report.md')
    br_path = pack_dir / 'binding_risk_candidates.json'
    if br_path.exists():
        artifact(br_path)
    for name in (
        'business_chains.json', 'chain_rank_plan.json', 'chain_material_request_plan.json',
    ):
        p = pack_dir / name
        if p.exists():
            artifact(p)
    ir_bundle = pack_dir / 'universal_ir' / 'universal_ir_bundle.json'
    if ir_bundle.exists():
        artifact(ir_bundle)
    return report
