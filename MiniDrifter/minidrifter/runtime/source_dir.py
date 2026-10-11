# -*- coding: utf-8 -*-
"""Resolve decompiled mini-program source directory (profile-driven, no app hardcoding)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional


def resolve_decompile_source_dir(
    pack_dir: Path,
    source_dir: Optional[Path] = None,
) -> Optional[Path]:
    if source_dir:
        p = Path(source_dir)
        if p.exists():
            return p

    pack_dir = Path(pack_dir)
    prof_path = pack_dir / 'project_profile.json'
    if not prof_path.exists():
        return None

    prof = json.loads(prof_path.read_text(encoding='utf-8'))
    root = prof.get('project_root')
    if not root:
        return None

    rp = Path(root)
    if rp.exists():
        return rp

    name = rp.name
    cursor = pack_dir.resolve()
    for _ in range(10):
        for sub in ('Workspace', 'workspace', 'runs', 'decompiled', 'projects'):
            candidate = cursor / sub / name
            if candidate.is_dir():
                return candidate
        if cursor.parent == cursor:
            break
        cursor = cursor.parent

    return None
