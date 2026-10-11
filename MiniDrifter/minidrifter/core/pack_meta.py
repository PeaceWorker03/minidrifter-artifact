# -*- coding: utf-8 -*-
"""Resolve pack identifiers from static output directories."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional


def resolve_pack_id(output_dir: Path) -> str:
    output_dir = Path(output_dir)
    for name in ('api_card_pack_manifest.json', 'acquisition_plan.json', 'baseline_runtime_context.json'):
        path = output_dir / name
        if not path.exists():
            continue
        try:
            data = json.loads(path.read_text(encoding='utf-8'))
            pid = data.get('pack_id')
            if pid:
                return str(pid)
        except (json.JSONDecodeError, OSError):
            continue
    return output_dir.name


def resolve_app_label(output_dir: Path) -> str:
    output_dir = Path(output_dir)
    manifest = output_dir / 'api_card_pack_manifest.json'
    if manifest.exists():
        try:
            data = json.loads(manifest.read_text(encoding='utf-8'))
            label = (data.get('project_context') or {}).get('app_label')
            if label:
                return str(label)
            label = data.get('app_label')
            if label:
                return str(label)
        except (json.JSONDecodeError, OSError):
            pass
    return output_dir.name


def unknown_merge_report_name(output_dir: Path) -> str:
    label = resolve_app_label(output_dir)
    return f'{label}_unknown_merge_report.json'
