# -*- coding: utf-8
"""Business chain pipeline orchestration and pack export."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from minidrifter.business_chain.chain_extractor import extract_business_chains
from minidrifter.business_chain.chain_ranker import rank_business_chains
from minidrifter.business_chain.graph_builder import build_business_chain_graph
from minidrifter.business_chain.material_planner import build_chain_material_request_plan
from minidrifter.business_chain.producer_consumer import build_api_transitions
from minidrifter.business_chain.chain_run_context import (
    make_run_id,
    stamp_run_context,
)
from minidrifter.core.utils import write_json
from minidrifter.graph.runtime_demand_graph import extract_workflow_graph


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def build_business_chain_pipeline(
    *,
    cards: List[Dict[str, Any]],
    manifest: Dict[str, Any],
    runtime_graph_full: Dict[str, Any],
    workflow_graph: Optional[Dict[str, Any]] = None,
    domain_tree: Optional[Dict[str, Any]] = None,
    material_requirements: Optional[Dict[str, Any]] = None,
    templates_by_id: Optional[Dict[str, Dict[str, Any]]] = None,
    pack_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    """Run full business chain recovery layer (rule-based, single-account)."""
    cards_by_id = {c['card_id']: c for c in cards if c.get('card_id')}
    wf = workflow_graph or extract_workflow_graph(runtime_graph_full)

    business_graph = build_business_chain_graph(
        wf, cards_by_id=cards_by_id, domain_tree=domain_tree,
    )
    transitions = build_api_transitions(
        business_graph, templates_by_id or {}, cards_by_id,
    )
    chains_doc = extract_business_chains(
        transitions, business_graph, templates_by_id or {},
        cards_by_id=cards_by_id,
        pack_dir=pack_dir,
    )
    rank_plan = rank_business_chains(
        chains_doc, templates_by_id or {}, pack_dir=pack_dir,
        cards_by_id=cards_by_id,
    )

    if pack_dir:
        audit_doc = {'llm_status': 'skipped', 'adjustments': []}
        try:
            from minidrifter.reasoning.chain_plausibility_auditor import (
                apply_plausibility_to_rank_plan,
                audit_chain_plausibility,
            )
            audit_doc = audit_chain_plausibility(
                pack_dir, chains_doc.get('chains') or [], limit=15, use_llm=True,
            )
            rank_plan = apply_plausibility_to_rank_plan(rank_plan, audit_doc)
        except Exception as exc:
            from minidrifter.core.utils import write_json
            audit_doc['error'] = str(exc)[:200]
            write_json(pack_dir / 'chain_plausibility_audit.json', audit_doc)

    material_plan = build_chain_material_request_plan(
        rank_plan, chains_doc, domain_tree=domain_tree, pack_dir=pack_dir,
        cards_by_id=cards_by_id,
    )

    pack_label = Path(pack_dir).name if pack_dir else 'pack'
    run_id = make_run_id(pack_label)
    chains_doc = stamp_run_context(chains_doc, run_id=run_id, artifact_name='business_chains', pack_dir=pack_dir)
    rank_plan = stamp_run_context(rank_plan, run_id=run_id, artifact_name='chain_rank_plan', pack_dir=pack_dir)
    material_plan = stamp_run_context(
        material_plan, run_id=run_id, artifact_name='chain_material_request_plan', pack_dir=pack_dir,
    )
    business_graph = stamp_run_context(
        business_graph, run_id=run_id, artifact_name='business_chain_graph', pack_dir=pack_dir,
    )
    transitions = stamp_run_context(
        transitions, run_id=run_id, artifact_name='business_api_transitions', pack_dir=pack_dir,
    )

    return {
        'generated_at': _utc_now(),
        'run_id': run_id,
        'verification_scope': 'single_account',
        'business_chain_graph': business_graph,
        'business_api_transitions': transitions,
        'business_chains': chains_doc,
        'chain_rank_plan': rank_plan,
        'chain_material_request_plan': material_plan,
        'summary': {
            'api_nodes': business_graph.get('stats', {}).get('api_count'),
            'transitions': transitions.get('transition_count'),
            'chains': chains_doc.get('chain_count'),
            'top_chains': len(rank_plan.get('top_chains') or []),
            'material_requests': material_plan.get('request_count'),
        },
    }


def write_business_chain_artifacts(output_dir: Path, result: Dict[str, Any]) -> Dict[str, str]:
    output_dir = Path(output_dir)
    paths = {
        'business_chain_graph': output_dir / 'business_chain_graph.json',
        'business_api_transitions': output_dir / 'business_api_transitions.json',
        'business_chains': output_dir / 'business_chains.json',
        'chain_rank_plan': output_dir / 'chain_rank_plan.json',
        'chain_material_request_plan': output_dir / 'chain_material_request_plan.json',
    }
    write_json(paths['business_chain_graph'], result['business_chain_graph'])
    write_json(paths['business_api_transitions'], result['business_api_transitions'])
    write_json(paths['business_chains'], result['business_chains'])
    write_json(paths['chain_rank_plan'], result['chain_rank_plan'])
    write_json(paths['chain_material_request_plan'], result['chain_material_request_plan'])
    try:
        from minidrifter.quality.runtime_reachability.capture_anchor_planner import (
            build_dual_plane_plans,
            write_dual_plane_artifacts,
        )
        dual = build_dual_plane_plans(output_dir)
        write_dual_plane_artifacts(output_dir, dual)
    except Exception:
        pass
    try:
        from minidrifter.business_chain.ui_capture_surface import write_capture_surface_plan
        write_capture_surface_plan(output_dir, plan=result['chain_material_request_plan'])
    except Exception:
        pass
    try:
        from minidrifter.business_chain.baseline_capture_strategy import write_baseline_capture_strategy
        write_baseline_capture_strategy(output_dir)
    except Exception:
        pass
    return {k: str(v) for k, v in paths.items()}


def load_business_chains(pack_dir: Path) -> Dict[str, Any]:
    import json
    path = Path(pack_dir) / 'business_chains.json'
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding='utf-8'))


def refresh_business_chains_for_pack(pack_dir: Path) -> Optional[Dict[str, Any]]:
    """Rebuild chain artifacts when materialized templates are available."""
    import json
    pack_dir = Path(pack_dir)
    full_path = pack_dir / 'runtime_demand_graph.full.json'
    if not full_path.exists():
        return None
    try:
        from minidrifter.reasoning.pack_loader import load_pack
        pack = load_pack(pack_dir)
        full = json.loads(full_path.read_text(encoding='utf-8'))
        domain_path = pack_dir / 'business_domain_tree.json'
        domain = json.loads(domain_path.read_text(encoding='utf-8')) if domain_path.exists() else {}
        tpl_path = pack_dir / 'materialized_api_templates.json'
        tpl_doc = json.loads(tpl_path.read_text(encoding='utf-8')) if tpl_path.exists() else {}
        templates_by_id = {t['api_id']: t for t in (tpl_doc.get('templates') or []) if t.get('api_id')}
        result = build_business_chain_pipeline(
            cards=pack['cards'],
            manifest=pack['manifest'],
            runtime_graph_full=full,
            domain_tree=domain,
            templates_by_id=templates_by_id,
            pack_dir=pack_dir,
        )
        write_business_chain_artifacts(pack_dir, result)
        try:
            from minidrifter.quality.runner import write_static_quality_report
            write_static_quality_report(
                pack_dir,
                phase='post_chain',
                resolutions_applied=['transition_edge_prune', 'chain_semantic_gates'],
                merge_existing=True,
            )
        except Exception:
            pass
        return result
    except Exception as exc:
        import logging
        logging.getLogger('MiniDrifter').warning('refresh_business_chains failed: %s', exc)
        return None


def find_chain_for_entry(pack_dir: Path, entry_api_id: str) -> Optional[Dict[str, Any]]:
    """Best ranked chain starting at entry_api_id."""
    import json
    rank_path = Path(pack_dir) / 'chain_rank_plan.json'
    chains_path = Path(pack_dir) / 'business_chains.json'
    if not rank_path.exists() or not chains_path.exists():
        return None
    rank = json.loads(rank_path.read_text(encoding='utf-8'))
    chains = {c['chain_id']: c for c in (json.loads(chains_path.read_text(encoding='utf-8')).get('chains') or [])}
    for item in rank.get('top_chains') or []:
        if item.get('entry_api') == entry_api_id:
            return chains.get(item.get('chain_id')) or item
    return None
