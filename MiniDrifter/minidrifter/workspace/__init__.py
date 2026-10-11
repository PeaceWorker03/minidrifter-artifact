# -*- coding: utf-8
"""Workspace-level mini-program project discovery (wedecode-like)."""
from __future__ import annotations

from minidrifter.orchestration.workspace_scanner import (
    discover_projects,
    scan_workspace,
    write_workspace_manifest,
)

__all__ = ['discover_projects', 'scan_workspace', 'write_workspace_manifest', 'index_workspace']


def index_workspace(workspace, *, max_depth: int = 3):
    """Alias for scan_workspace — produces MiniDrifter_workspace.json."""
    return scan_workspace(workspace, max_depth=max_depth)
