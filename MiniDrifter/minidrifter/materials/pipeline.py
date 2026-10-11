# -*- coding: utf-8 -*-
"""Orchestrate Steps 1-7: domain tree, produces, materials, baseline template."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from minidrifter.core.utils import write_json
from minidrifter.graph.business_domain_tree import build_business_domain_tree
from minidrifter.graph.produces_infer import build_enhanced_produces
from minidrifter.graph.runtime_demand_graph import (
    assemble_demand_graph,
    build_requires_edges,
    truncate_graph_preview,
)
from minidrifter.materials.baseline_template_generator import generate_baseline_material_template
from minidrifter.materials.material_compressor import compress_material_requirements
from minidrifter.reasoning.acquisition_planner import build_acquisition_plan
from minidrifter.reasoning.erd import build_evidence_requirements
from minidrifter.reasoning.runtime_skeleton import build_runtime_requirement_skeleton
from minidrifter.graph.runtime_demand_graph import extract_workflow_graph

SCHEMA_VERSION = '1.0.0'


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def export_runtime_skeletons(
    cards: List[Dict[str, Any]],
    erd_items: List[Dict[str, Any]],
) -> Dict[str, Any]:
    erd_by_id = {i['card_id']: i for i in erd_items}
    skeletons = []
    for card in cards:
        if (card.get('provenance') or {}).get('card_kind') != 'operation':
            continue
        item = erd_by_id.get(card['card_id'], {})
        level = (item.get('runtime_requirement') or {}).get('level', 'N1_BASELINE_RUNTIME_TEMPLATE')
        sk = item.get('runtime_requirement_skeleton') or build_runtime_requirement_skeleton(card, level)
        skeletons.append({'card_id': card['card_id'], **sk})
    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': _utc_now(),
        'count': len(skeletons),
        'skeletons': skeletons,
        'by_card_id': {s['card_id']: s for s in skeletons},
    }


def build_demand_graphs(
    cards: List[Dict[str, Any]],
    erd_items: List[Dict[str, Any]],
    domain_tree: Dict[str, Any],
) -> Dict[str, Any]:
    erd_by_id = {i['card_id']: i for i in erd_items}
    required_by_api: Dict[str, Set[str]] = {}
    for card in cards:
        if (card.get('provenance') or {}).get('card_kind') != 'operation':
            continue
        cid = card['card_id']
        sk = (erd_by_id.get(cid) or {}).get('runtime_requirement_skeleton') or {}
        required_by_api[cid] = {f['name'] for f in sk.get('required_fields') or [] if f.get('name')}

    produces_edges = build_enhanced_produces(
        cards,
        classifications=domain_tree.get('by_card_id'),
        required_by_api=required_by_api,
    )
    api_nodes, requires_edges, field_nodes = build_requires_edges(cards, erd_by_id)
    full = assemble_demand_graph(api_nodes, requires_edges, produces_edges, field_nodes)
    full['variant'] = 'full'
    full['note'] = 'produces edges merged from path, snippet, and list/detail pairing heuristics'
    preview = truncate_graph_preview(full)
    return {'full': full, 'preview': preview}


def build_baseline_material_pipeline(
    cards: List[Dict[str, Any]],
    manifest: Dict[str, Any],
    erd_items: Optional[List[Dict[str, Any]]] = None,
    acquisition_plan: Optional[Dict[str, Any]] = None,
    *,
    stage1_limit: int = 120,
) -> Dict[str, Any]:
    if erd_items is None:
        erd = build_evidence_requirements(cards, manifest)
        erd_items = erd.get('items') or []
    else:
        erd = {'items': erd_items}

    if acquisition_plan is None:
        acquisition_plan = build_acquisition_plan(cards, manifest, erd_items)

    domain_tree = build_business_domain_tree(cards, manifest)
    skeleton_export = export_runtime_skeletons(cards, erd_items)
    graphs = build_demand_graphs(cards, erd_items, domain_tree)

    cards_by_id = {c['card_id']: c for c in cards}
    material_requirements = compress_material_requirements(
        cards_by_id,
        erd_items,
        acquisition_plan,
        domain_tree,
        stage1_limit=stage1_limit,
    )

    baseline_template = generate_baseline_material_template(
        material_requirements,
        acquisition_plan,
        domain_tree=domain_tree,
        demand_graph=graphs['full'],
        erd_items=erd_items,
        manifest=manifest,
    )

    business_chain_result: Dict[str, Any] = {}
    try:
        from minidrifter.business_chain.export import build_business_chain_pipeline
        wf = extract_workflow_graph(graphs['full'])
        business_chain_result = build_business_chain_pipeline(
            cards=cards,
            manifest=manifest,
            runtime_graph_full=graphs['full'],
            workflow_graph=wf,
            domain_tree=domain_tree,
            material_requirements=material_requirements,
            templates_by_id={},
            pack_dir=output_dir,
        )
    except Exception as exc:
        business_chain_result = {'error': str(exc)}

    return {
        'runtime_skeleton_export': skeleton_export,
        'business_domain_tree': domain_tree,
        'runtime_demand_graph_full': graphs['full'],
        'runtime_demand_graph_preview': graphs['preview'],
        'material_requirements': material_requirements,
        'baseline_material_template': baseline_template,
        'acquisition_plan': acquisition_plan,
        'business_chain_pipeline': business_chain_result,
    }


def write_baseline_material_pipeline(output_dir: Path, result: Dict[str, Any]) -> Dict[str, str]:
    output_dir = Path(output_dir)
    paths = {
        'runtime_skeletons': output_dir / 'runtime_skeletons.json',
        'business_domain_tree': output_dir / 'business_domain_tree.json',
        'runtime_demand_graph': output_dir / 'runtime_demand_graph.json',
        'runtime_demand_graph_full': output_dir / 'runtime_demand_graph.full.json',
        'runtime_demand_graph_preview': output_dir / 'runtime_demand_graph.preview.json',
        'material_requirements': output_dir / 'material_requirements.json',
        'baseline_material_template': output_dir / 'baseline_material_template.json',
    }
    write_json(paths['runtime_skeletons'], result['runtime_skeleton_export'])
    write_json(paths['business_domain_tree'], result['business_domain_tree'])
    write_json(paths['runtime_demand_graph_full'], result['runtime_demand_graph_full'])
    write_json(paths['runtime_demand_graph_preview'], result['runtime_demand_graph_preview'])
    from minidrifter.graph.runtime_demand_graph import extract_workflow_graph
    write_json(
        output_dir / 'runtime_demand_graph.workflow.json',
        extract_workflow_graph(result['runtime_demand_graph_full']),
    )
    write_json(
        output_dir / 'runtime_demand_graph.workflow_stats.json',
        (result['runtime_demand_graph_full'].get('workflow_stats') or {}),
    )
    # Default pointer file → preview for lightweight consumers
    write_json(paths['runtime_demand_graph'], {
        'variant': 'index',
        'full': 'runtime_demand_graph.full.json',
        'preview': 'runtime_demand_graph.preview.json',
        'full_api_node_count': result['runtime_demand_graph_full'].get('api_node_count'),
        'full_edge_counts': result['runtime_demand_graph_full'].get('edge_counts'),
    })
    write_json(paths['material_requirements'], result['material_requirements'])
    write_json(paths['baseline_material_template'], result['baseline_material_template'])
    bc = result.get('business_chain_pipeline') or {}
    if bc and bc.get('business_chains'):
        from minidrifter.business_chain.export import write_business_chain_artifacts
        bc_paths = write_business_chain_artifacts(output_dir, bc)
        paths.update({f'bc_{k}': v for k, v in bc_paths.items()})
    plan = result['acquisition_plan']
    plan['runtime_demand_graph'] = result['runtime_demand_graph_preview']
    plan['runtime_demand_graph_ref'] = {
        'full': 'runtime_demand_graph.full.json',
        'preview': 'runtime_demand_graph.preview.json',
    }
    write_json(output_dir / 'acquisition_plan.json', plan)
    return {k: str(v) for k, v in paths.items()}
