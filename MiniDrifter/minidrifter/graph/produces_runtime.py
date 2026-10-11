# -*- coding: utf-8 -*-
"""Runtime produces confirmation — promote harvest fields into demand graph."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Set

from minidrifter.core.utils import write_json
from minidrifter.graph.runtime_demand_graph import (
    LEGACY_PRODUCES,
    PRODUCES_BUSINESS_OBJECT,
    PRODUCES_CAPABILITY,
    enrich_graph_dual_layer,
    extract_workflow_graph,
)
from minidrifter.verification.object_pool import GLOBAL_CONTEXT_FIELDS


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


_PRODUCE_TYPES = {PRODUCES_BUSINESS_OBJECT, PRODUCES_CAPABILITY, LEGACY_PRODUCES, 'produces'}


def apply_verification_produces(
    pack_dir: Path,
    *,
    api_id: str,
    path: str,
    produced_fields: List[str],
) -> Dict[str, Any]:
    """Confirm or add produces edges from live verification harvest; refresh workflow sidecar."""
    from minidrifter.verification.graph_loader import load_full_graph

    pack_dir = Path(pack_dir)
    if not api_id or not produced_fields:
        return {'status': 'skipped', 'confirmed': [], 'added': []}

    full = load_full_graph(pack_dir, write_upgraded=False)
    edges: List[Dict[str, Any]] = list(full.get('edges') or [])
    confirmed: List[str] = []
    added: List[str] = []

    for field in produced_fields:
        if not field or field in GLOBAL_CONTEXT_FIELDS:
            continue
        matched = False
        for edge in edges:
            etype = edge.get('type') or ''
            if etype not in _PRODUCE_TYPES:
                continue
            src = edge.get('from') or edge.get('from_api')
            tgt = edge.get('to_field') or edge.get('to')
            if src != api_id:
                continue
            if tgt != field and tgt.lower() != field.lower():
                continue
            edge['evidence_level'] = 'runtime_confirmed'
            edge['confidence'] = max(float(edge.get('confidence') or 0.5), 0.95)
            edge['phase'] = 'runtime_confirmed'
            edge['source_material'] = edge.get('source_material') or 'verification_harvest'
            confirmed.append(field)
            matched = True
            break
        if not matched:
            edges.append({
                'type': PRODUCES_BUSINESS_OBJECT,
                'from': api_id,
                'from_api': api_id,
                'to_field': field,
                'to': field,
                'confidence': 0.95,
                'evidence_level': 'runtime_confirmed',
                'phase': 'runtime_confirmed',
                'source_material': 'verification_harvest',
                'path_hint': path,
                'confirmed_at': _utc_now(),
            })
            added.append(field)

    if not confirmed and not added:
        return {'status': 'no_op', 'confirmed': [], 'added': []}

    full['edges'] = edges
    full['runtime_produces_updated_at'] = _utc_now()
    full = enrich_graph_dual_layer(full)
    write_json(pack_dir / 'runtime_demand_graph.full.json', full)

    workflow = extract_workflow_graph(full)
    write_json(pack_dir / 'runtime_demand_graph.workflow.json', workflow)
    write_json(
        pack_dir / 'runtime_demand_graph.workflow_stats.json',
        workflow.get('workflow_stats') or {},
    )
    return {
        'status': 'ok',
        'confirmed': sorted(set(confirmed)),
        'added': sorted(set(added)),
        'workflow_stats': workflow.get('workflow_stats') or {},
    }


def merge_runtime_graph_stats(existing: Dict[str, Any], update: Dict[str, Any]) -> Dict[str, Any]:
    """Merge writeback counters into session metadata."""
    out = dict(existing or {})
    rb = dict(out.get('runtime_produces_writeback') or {})
    rb['total_events'] = int(rb.get('total_events') or 0) + 1
    rb['fields_confirmed'] = sorted(set(rb.get('fields_confirmed') or []) | set(update.get('confirmed') or []))
    rb['fields_added'] = sorted(set(rb.get('fields_added') or []) | set(update.get('added') or []))
    rb['last_at'] = _utc_now()
    out['runtime_produces_writeback'] = rb
    return out
