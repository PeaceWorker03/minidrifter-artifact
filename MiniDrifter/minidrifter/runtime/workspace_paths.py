# -*- coding: utf-8 -*-
"""Resolve Workspace/ project roots — not tied to any single mini-program."""
from __future__ import annotations

from pathlib import Path
from typing import List, Optional, Tuple


from minidrifter.adapters.pack_resolver import default_output_slug


def find_workspace_root(start: Optional[Path] = None) -> Optional[Path]:
    cursor = (start or Path.cwd()).resolve()
    for _ in range(12):
        for name in ('Workspace', 'workspace'):
            candidate = cursor / name
            if candidate.is_dir():
                return candidate
        if cursor.parent == cursor:
            break
        cursor = cursor.parent
    return None


def list_workspace_projects(workspace: Optional[Path] = None) -> List[Tuple[str, Path]]:
    """Return (folder_name, project_root) for decompiled mini-program dirs under Workspace."""
    ws = workspace or find_workspace_root()
    if not ws or not ws.is_dir():
        return []
    out: List[Tuple[str, Path]] = []
    skip = {'captures', 'runs', 'decompiled', 'projects', '.git'}
    for child in sorted(ws.iterdir()):
        if not child.is_dir() or child.name.lower() in skip:
            continue
        if (child / 'app.json').exists() or (child / 'app.js').exists() or (child / 'common.js').exists():
            out.append((child.name, child))
    return out


def default_pack_dir_for_project(project_dir: Path, *, project_root: Optional[Path] = None) -> Path:
    """Convention: Workspace/<name>/OUTPUT/ or sample_outputs/{slug} for legacy."""
    proj = Path(project_dir).resolve()
    ws = find_workspace_root(proj)
    if ws:
        try:
            rel = proj.relative_to(ws)
            if len(rel.parts) == 1:
                return proj / 'OUTPUT'
        except ValueError:
            pass
    root = project_root or Path(__file__).resolve().parents[2]
    slug = default_output_slug(project_dir.name, str(project_dir))
    return root / 'sample_outputs' / slug


def resolve_workspace_project(name_hint: str = '', *, workspace: Optional[Path] = None) -> Optional[Path]:
    projects = list_workspace_projects(workspace)
    if not projects:
        return None
    hint = (name_hint or '').strip().lower()
    if hint:
        for label, path in projects:
            if hint in label.lower() or hint in str(path).lower():
                return path
    return projects[0][1] if len(projects) == 1 else None
