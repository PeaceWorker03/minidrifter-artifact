# -*- coding: utf-8 -*-
"""Export RPGraph / Cross-API Business Credential Dependency Graph, workflows, and drift plans."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from minidrifter.rpgraph.graph_builder import build_rpgraph
from minidrifter.rpgraph.workflow_recovery import plan_drifts, recover_workflows
from minidrifter.core.utils import write_json


def _load_ccrs(pack_dir: Path) -> List[Dict[str, Any]]:
    """Load RCR nodes (paper: Reference Contract Representation)."""
    for name in ('rcr_pack.json', 'ccr_pack.json'):
        path = pack_dir / name
        if not path.exists():
            continue
        doc = json.loads(path.read_text(encoding='utf-8'))
        return list(doc.get('rcrs') or doc.get('ccrs') or [])
    return []


def _enrich_ccrs_from_facts(ccrs: List[Dict[str, Any]], pack_dir: Path) -> List[Dict[str, Any]]:
    """Merge business-like params from request_facts when RCR bind set is sparse."""
    from minidrifter.runtime_trace.chain_composer import infer_binding_fields_from_path
    from minidrifter.rpgraph.schema import is_business_bind_field

    rf_path = pack_dir / 'request_facts.json'
    facts: Dict[str, Any] = {}
    if rf_path.exists():
        facts = {
            f.get('operation_id'): f
            for f in (json.loads(rf_path.read_text(encoding='utf-8')).get('request_facts') or [])
            if f.get('operation_id')
        }
    out = []
    for RCR in ccrs:
        c = dict(RCR)
        fact = facts.get(c.get('operation_id')) or {}
        params = fact.get('params') or []
        names: List[str] = []
        if isinstance(params, list):
            for p in params:
                if isinstance(p, dict):
                    n = p.get('name') or p.get('key') or p.get('field')
                    if n:
                        names.append(str(n))
                else:
                    names.append(str(p))
        elif isinstance(params, dict):
            names = [str(k) for k in params.keys()]
        # Path-inferred binds (ByTitle→title, Title/Detail→titleId, ByUserId→userId)
        path = ((c.get('endpoint') or {}).get('path') or '')
        for n in infer_binding_fields_from_path(path):
            if n not in names:
                names.append(n)
        # ByUserId / serId style aliases → userId
        low = {n.lower() for n in names}
        if 'byuserid' in low and 'userid' not in low and 'userId' not in names:
            names.append('userId')
        # Merge into request_semantics.credentials for credential_set fallback
        rs = dict(c.get('request_semantics') or {})
        creds = list(rs.get('credentials') or [])
        for n in names:
            if n not in creds:
                creds.append(n)
        rs['credentials'] = creds
        c['request_semantics'] = rs
        # If binding empty, promote business-like names + path-inferred binds
        if not c.get('binding_credentials'):
            promoted = [n for n in names if is_business_bind_field(n)]
            path_inferred = infer_binding_fields_from_path(path)
            for n in path_inferred:
                if n not in promoted:
                    promoted.append(n)
            if promoted:
                c['binding_credentials'] = sorted(set(promoted))
        out.append(c)
    return out


def write_rpgraph_pack(pack_dir: Path | str, *, max_workflows: int = 120) -> Dict[str, Any]:
    """Emit paper artifacts: RPGraph, RR-Drift propagation chains, perturbation plans."""
    pack_dir = Path(pack_dir)
    ccrs = _enrich_ccrs_from_facts(_load_ccrs(pack_dir), pack_dir)
    # Persist enriched RCRs so gates/scores see promoted φ_i binds.
    try:
        from minidrifter.rcr.io import load_rcr_pack
        doc = load_rcr_pack(pack_dir) or {'schema_version': '1.0.0'}
        doc['representation'] = 'Reference Contract Representation (RCR)'
        doc['rcrs'] = ccrs
        doc['ccrs'] = ccrs
        doc['rcr_count'] = len(ccrs)
        doc['with_binding_credentials'] = sum(1 for c in ccrs if c.get('binding_credentials'))
        write_json(pack_dir / 'rcr_pack.json', doc)
    except Exception:
        pass
    graph = build_rpgraph(ccrs)
    workflows = recover_workflows(graph, ccrs, max_workflows=max_workflows)
    drifts = plan_drifts(workflows, graph)

    # Paper: Reference Propagation Graph (RPGraph) = (N, E)
    write_json(pack_dir / 'rpgraph.json', graph)
    # Candidate risky RR-Drift propagation chains (source→sink)
    write_json(pack_dir / 'workflows.json', workflows)
    write_json(pack_dir / 'rrdrift_propagation_chains.json', workflows)
    write_json(pack_dir / 'drift_plans.json', drifts)

    summary = {
        'schema_version': graph.get('schema_version'),
        'paper': {
            'tool': 'MiniDrifter',
            'threat': 'RR-Drift',
            'rcr': 'Reference Contract Representation',
            'rpgraph': 'Reference Propagation Graph',
            'static': 'static drift-oriented taint analyzer',
            'dynamic': 'dynamic perturbation validator',
            'chains': 'risky RR-Drift propagation chains',
        },
        'graph_summary': graph.get('summary'),
        'workflow_count': workflows.get('workflow_count'),
        'drift_plan_count': drifts.get('drift_plan_count'),
        'artifacts': [
            'rpgraph.json',
            'rrdrift_propagation_chains.json',
            'workflows.json',
            'drift_plans.json',
        ],
    }
    write_json(pack_dir / 'rpgraph_summary.json', summary)
    return summary
