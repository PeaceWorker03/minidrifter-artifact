# -*- coding: utf-8 -*-
"""Console session defaults — Workspace-first, not app-specific."""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from minidrifter.orchestration.console.session import ConsoleSession
from minidrifter.runtime.workspace_paths import (
    default_pack_dir_for_project,
    find_workspace_root,
    list_workspace_projects,
    resolve_workspace_project,
)


def apply_session_defaults(session: ConsoleSession, project_root: Path) -> None:
    """Set source_dir from project; optional anchor from profile later."""
    if not session.get('source_dir'):
        session.set('source_dir', str(project_root.resolve()))


def suggest_pack_and_project(
    *,
    project_root: Optional[Path] = None,
    MiniDrifter_root: Optional[Path] = None,
) -> tuple[str, str]:
    """Return (pack_dir, project_dir) strings for console/CLI hints."""
    root = MiniDrifter_root or Path(__file__).resolve().parents[2]
    ws = find_workspace_root(root)
    proj = project_root or resolve_workspace_project(workspace=ws)
    if proj:
        pack = default_pack_dir_for_project(proj, project_root=root)
        return str(pack.resolve()), str(proj.resolve())
    projects = list_workspace_projects(ws)
    if projects:
        _, proj = projects[0]
        pack = default_pack_dir_for_project(proj, project_root=root)
        return str(pack.resolve()), str(proj.resolve())
    return str((root / 'sample_outputs' / 'pack').resolve()), ''


# Backward-compatible aliases (deprecated names)
def apply_ehai_defaults(session: ConsoleSession, project_root: Path) -> None:
    apply_session_defaults(session, project_root)
