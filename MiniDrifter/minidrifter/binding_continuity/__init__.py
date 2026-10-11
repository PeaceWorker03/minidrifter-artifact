# -*- coding: utf-8 -*-
"""Deprecated alias — use ``minidrifter.rpgraph`` (paper: RPGraph / Ĝ)."""
from minidrifter.rpgraph import *  # noqa: F403
from minidrifter.rpgraph import SCHEMA_VERSION, write_rpgraph_pack, load_rpgraph, rpgraph_path

# Legacy names
write_binding_continuity_pack = write_rpgraph_pack

__all__ = [
    'SCHEMA_VERSION',
    'write_rpgraph_pack',
    'write_binding_continuity_pack',
    'load_rpgraph',
    'rpgraph_path',
]
