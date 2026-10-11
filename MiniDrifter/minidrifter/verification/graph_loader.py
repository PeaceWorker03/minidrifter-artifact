# -*- coding: utf-8 -*-
"""Load P5 dual-layer workflow graph for verification consumers."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional

from minidrifter.core.utils import write_json
from minidrifter.graph.runtime_demand_graph import (
    enrich_graph_dual_layer,
    extract_workflow_graph,
)


def _load_json(path: Path) -> Any:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding='utf-8'))


def load_workflow_graph(
    pack_dir: Path,
    *,
    write_sidecar: bool = True,
    force_upgrade: bool = False,
) -> Dict[str, Any]:
    """Return workflow graph (business edges only); auto-upgrade legacy full graph."""
    pack_dir = Path(pack_dir)
    workflow_path = pack_dir / 'runtime_demand_graph.workflow.json'
    full_path = pack_dir / 'runtime_demand_graph.full.json'

    if workflow_path.exists() and not force_upgrade:
        doc = _load_json(workflow_path)
        if doc and doc.get('dual_layer'):
            return doc

    full = _load_json(full_path) or {}
    if not full.get('edges'):
        return full

    if not full.get('dual_layer') or force_upgrade:
        full = enrich_graph_dual_layer(full)
        if write_sidecar:
            write_json(full_path, full)

    workflow = extract_workflow_graph(full)
    if write_sidecar:
        write_json(workflow_path, workflow)
        write_json(pack_dir / 'runtime_demand_graph.workflow_stats.json', workflow.get('workflow_stats') or {})

    return workflow


def load_full_graph(pack_dir: Path, *, write_upgraded: bool = True) -> Dict[str, Any]:
    pack_dir = Path(pack_dir)
    full_path = pack_dir / 'runtime_demand_graph.full.json'
    full = _load_json(full_path) or {}
    if full.get('edges') and not full.get('dual_layer'):
        full = enrich_graph_dual_layer(full)
        if write_upgraded:
            write_json(full_path, full)
    return full
