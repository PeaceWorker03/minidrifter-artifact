# -*- coding: utf-8 -*-
"""Scan a workspace folder for WeChat mini-program projects (wedecode-like discovery)."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from minidrifter.core.profile import ProjectProfileDetector

MINIPROGRAM_MARKERS = (
    'app.json',
    'app-config.json',
    'project.config.json',
    'app-service.js',
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _score_candidate(root: Path) -> int:
    score = 0
    for name in MINIPROGRAM_MARKERS:
        if (root / name).exists():
            score += 2
    if (root / 'pages').is_dir():
        score += 2
    if (root / 'services').is_dir() or (root / 'utils').is_dir():
        score += 1
    return score


def discover_projects(workspace: Path, *, max_depth: int = 3) -> List[Path]:
    """Find mini-program project roots under workspace (direct children + shallow nested)."""
    workspace = Path(workspace).resolve()
    if not workspace.is_dir():
        return []

    candidates: Dict[str, int] = {}

    def _consider(path: Path) -> None:
        s = _score_candidate(path)
        if s >= 2:
            key = str(path.resolve())
            candidates[key] = max(candidates.get(key, 0), s)

    _consider(workspace)
    for child in workspace.iterdir():
        if not child.is_dir() or child.name.startswith('.'):
            continue
        _consider(child)
        if max_depth >= 2:
            for sub in child.iterdir():
                if sub.is_dir() and not sub.name.startswith('.'):
                    _consider(sub)

    ranked = sorted(candidates.items(), key=lambda kv: (-kv[1], kv[0]))
    return [Path(p) for p, _ in ranked]


def scan_workspace(workspace: Path, *, max_depth: int = 3) -> Dict[str, Any]:
    """Return wedecode-style project list with profile hints."""
    workspace = Path(workspace).resolve()
    projects: List[Dict[str, Any]] = []

    for root in discover_projects(workspace, max_depth=max_depth):
        profile = ProjectProfileDetector(root).run()
        projects.append({
            'project_id': root.name,
            'project_root': str(root),
            'platform_guess': profile.get('platform_guess'),
            'shape': profile.get('shape'),
            'decompile_candidate': profile.get('shape') in {
                'decompiled_config_based', 'app_service_bundle', 'source_like', 'framework_compiled',
            },
            'has_app_json': profile.get('has_app_json'),
            'has_app_config_json': profile.get('has_app_config_json'),
            'has_app_service_js': profile.get('has_app_service_js'),
            'obfuscation': profile.get('obfuscation'),
            'file_count': profile.get('file_count'),
        })

    return {
        'schema_version': '1.0.0',
        'generated_at': _utc_now(),
        'workspace': str(workspace),
        'project_count': len(projects),
        'projects': projects,
    }


def write_workspace_manifest(workspace: Path, doc: Dict[str, Any]) -> Path:
    out = Path(workspace) / 'MiniDrifter_workspace.json'
    out.write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding='utf-8')
    return out
