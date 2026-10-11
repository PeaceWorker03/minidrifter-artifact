# -*- coding: utf-8 -*-
"""Load/save RPGraph artifacts (paper: Reference Propagation Graph)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional

RPGRAPH_FILENAME = 'rpgraph.json'
LEGACY_GRAPH_FILENAMES = (
    'cpeg.json',
    'binding_continuity_graph.json',
)


def rpgraph_path(pack_dir: Path | str) -> Path:
    pack = Path(pack_dir)
    primary = pack / RPGRAPH_FILENAME
    if primary.exists():
        return primary
    for name in LEGACY_GRAPH_FILENAMES:
        p = pack / name
        if p.exists():
            return p
    return primary


def load_rpgraph(pack_dir: Path | str) -> Dict[str, Any]:
    path = rpgraph_path(pack_dir)
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding='utf-8'))


def resolve_rpgraph_path(pack_dir: Path | str) -> Optional[Path]:
    path = rpgraph_path(pack_dir)
    return path if path.exists() else None
