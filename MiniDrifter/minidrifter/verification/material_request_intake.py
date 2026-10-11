# -*- coding: utf-8
"""Sync material_requests → intake checklist + resume commands."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from minidrifter.core.utils import write_json


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def enrich_material_request(
    req: Dict[str, Any],
    *,
    pack_dir: Path,
) -> Dict[str, Any]:
    """Add CLI/workbench commands for one material request."""
    pack_dir = Path(pack_dir)
    pack_str = str(pack_dir)
    fields = req.get('missing_fields') or []
    paths = req.get('suggested_capture_paths') or []

    intake_items = []
    for mat in req.get('missing_materials') or []:
        field = mat.get('field') or '?'
        intake_items.append({
            'field': field,
            'why': mat.get('why_needed') or mat.get('capture_hint'),
            'suggested_paths': mat.get('suggested_capture_paths') or paths[:3],
            'priority': mat.get('priority') or 'medium',
            'cli_import': (
                f'python -m minidrifter.cli intake-baseline -i "{pack_str}" '
                f'--raw-file <capture_with_{field}.txt> --import-after'
            ),
            'workbench_resume': (
                f'python -m minidrifter.cli workbench resume -i "{pack_str}" -f <capture.txt>'
            ),
        })

    out = dict(req)
    out['intake'] = {
        'items': intake_items,
        'resume_verify': (
            f'python -m minidrifter.cli run-deep-verify -i "{pack_str}" '
            f'--mode execute --resume --skip-materialize'
        ),
        'fields_summary': ', '.join(fields),
    }
    return out


def sync_material_requests_to_intake(
    pack_dir: Path,
    requests: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Merge material_requests into user_intake_checklist.json for GUI/workbench."""
    pack_dir = Path(pack_dir)
    if not requests:
        return {'status': 'skipped', 'merged': 0}

    enriched = [enrich_material_request(r, pack_dir=pack_dir) for r in requests]
    checklist_path = pack_dir / 'user_intake_checklist.json'
    existing: Dict[str, Any] = {}
    if checklist_path.exists():
        existing = json.loads(checklist_path.read_text(encoding='utf-8'))

    items = list(existing.get('items') or [])
    seen_keys: set = set()
    for it in items:
        key = (it.get('field') or it.get('title') or '', it.get('path') or '')
        seen_keys.add(key)

    merged = 0
    for req in enriched:
        for mat in req.get('intake', {}).get('items') or []:
            field = mat.get('field') or '?'
            for p in mat.get('suggested_paths') or ['']:
                key = (field, p)
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                items.append({
                    'source': 'hop_adjudication',
                    'field': field,
                    'path': p,
                    'title': f'补充 {field} 抓包',
                    'why': mat.get('why'),
                    'priority': mat.get('priority'),
                    'paste_to': 'intake-baseline',
                    'cli_command': mat.get('cli_import'),
                    'resume_command': mat.get('workbench_resume'),
                })
                merged += 1

    doc = {
        **existing,
        'schema_version': existing.get('schema_version') or '1.0.0',
        'updated_at': _utc_now(),
        'material_request_count': len(enriched),
        'items': items,
        'verify_resume': enriched[0].get('intake', {}).get('resume_verify') if enriched else None,
    }
    write_json(checklist_path, doc)
    write_json(pack_dir / 'material_requests.json', {
        'schema_version': '1.0.0',
        'count': len(enriched),
        'items': enriched,
    })
    return {'status': 'ok', 'merged': merged, 'total_requests': len(enriched)}
