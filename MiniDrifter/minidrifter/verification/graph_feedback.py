# -*- coding: utf-8
"""Runtime graph negative feedback — downgrade requires/produces on hop failures."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from minidrifter.core.utils import write_json


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


_REQUIRES_TYPES = {'requires', 'requires_business_object', 'requires_capability', 'requires_field'}
_PRODUCES_TYPES = {'produces', 'produces_business_object', 'produces_capability'}


def apply_hop_graph_feedback(
    pack_dir: Path,
    *,
    api_id: str,
    path: str,
    failure_class: Optional[str],
    missing_fields: Optional[List[str]] = None,
    binding_drift: bool = False,
    confidence: Any = None,
) -> Dict[str, Any]:
    """Downgrade graph edges when consumer blocked or binding hypothesis fails."""
    from minidrifter.verification.graph_loader import load_full_graph

    pack_dir = Path(pack_dir)
    if not api_id:
        return {'status': 'skipped'}

    full = load_full_graph(pack_dir, write_upgraded=False)
    edges: List[Dict[str, Any]] = list(full.get('edges') or [])
    downgraded: List[str] = []
    missing = {str(f).lower() for f in (missing_fields or []) if f}

    for edge in edges:
        etype = edge.get('type') or ''
        tgt_api = edge.get('to') or edge.get('to_api')
        field = edge.get('from_field') or edge.get('from') or edge.get('field')

        if etype in _REQUIRES_TYPES and tgt_api == api_id:
            fld = str(field or '').lower()
            if failure_class == 'business_state_blocked' and fld in missing:
                old = float(edge.get('confidence') or 0.7)
                edge['confidence'] = max(0.15, old - 0.25)
                edge['runtime_feedback'] = 'consumer_blocked_missing_field'
                edge['feedback_at'] = _utc_now()
                downgraded.append(f'requires:{field}->{api_id}')
                if confidence and field:
                    confidence.downgrade_field_mapping(field, delta=0.15)

        if binding_drift and etype in _PRODUCES_TYPES:
            src = edge.get('from') or edge.get('from_api')
            if src == api_id:
                old = float(edge.get('confidence') or 0.7)
                edge['confidence'] = max(0.2, old - 0.1)
                edge['runtime_feedback'] = 'binding_drift_observed'
                edge['feedback_at'] = _utc_now()
                downgraded.append(f'produces:{api_id}->{edge.get("to_field")}')

    if not downgraded:
        return {'status': 'no_op', 'downgraded': []}

    full['edges'] = edges
    full['runtime_feedback_updated_at'] = _utc_now()
    write_json(pack_dir / 'runtime_demand_graph.full.json', full)

    from minidrifter.graph.runtime_demand_graph import enrich_graph_dual_layer, extract_workflow_graph
    full = enrich_graph_dual_layer(full)
    workflow = extract_workflow_graph(full)
    write_json(pack_dir / 'runtime_demand_graph.workflow.json', workflow)

    return {'status': 'ok', 'downgraded': downgraded, 'path': path}
