# -*- coding: utf-8 -*-
"""Versioned run manifest — single source of truth for one verification run."""
from __future__ import annotations

import hashlib
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from minidrifter.core.utils import write_json
from minidrifter.orchestration.run_metrics import collect_run_metrics


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _file_hash(path: Path) -> Optional[str]:
    if not path.exists():
        return None
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()[:16]


def _next_run_id(runs_dir: Path) -> str:
    runs_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%d')
    existing = sorted(runs_dir.glob(f'run_{stamp}_*'))
    seq = len(existing) + 1
    return f'run_{stamp}_{seq:03d}'


def build_run_manifest(
    pack_dir: Path,
    *,
    project_name: Optional[str] = None,
    baseline_dir: Optional[Path] = None,
    phase: str = 'verification_complete',
) -> Dict[str, Any]:
    pack_dir = Path(pack_dir)
    static_manifest = {}
    sm_path = pack_dir / 'api_card_pack_manifest.json'
    if sm_path.exists():
        static_manifest = json.loads(sm_path.read_text(encoding='utf-8'))

    baseline_hash = None
    if baseline_dir and Path(baseline_dir).exists():
        parts = sorted(Path(baseline_dir).rglob('*.http'))
        if parts:
            h = hashlib.sha256()
            for p in parts:
                h.update(p.name.encode())
                h.update(p.read_bytes())
            baseline_hash = h.hexdigest()[:16]

    ctx_path = pack_dir / 'baseline_runtime_context.json'
    ctx = {}
    if ctx_path.exists():
        ctx = json.loads(ctx_path.read_text(encoding='utf-8'))

    cp = ctx.get('crypto_profile')
    if isinstance(cp, dict):
        crypto_profile = cp.get('profile_id') or ctx.get('profile_id')
    else:
        crypto_profile = cp or ctx.get('profile_id')

    return {
        'schema_version': '1.0.0',
        'run_id': None,
        'phase': phase,
        'generated_at': _utc_now(),
        'project_name': project_name or pack_dir.name,
        'pack_dir': str(pack_dir),
        'pack_id': static_manifest.get('pack_id'),
        'source_hash': _file_hash(pack_dir / 'all_api_cards.json'),
        'baseline_hash': baseline_hash,
        'baseline_dir': str(baseline_dir) if baseline_dir else None,
        'crypto_profile': crypto_profile,
        'static_generated_at': static_manifest.get('generated_at'),
        'materialization_generated_at': _mtime_iso(pack_dir / 'materialization_report.json'),
        'verification_generated_at': _mtime_iso(pack_dir / 'search_session.json'),
        'artifacts': {
            'static': 'api_card_pack_manifest.json',
            'materialization': 'materialization_report.json',
            'verification': 'search_session.json',
            'findings': 'finding_registry.json',
            'metrics': 'run_metrics.json',
        },
    }


def _mtime_iso(path: Path) -> Optional[str]:
    if not path.exists():
        return None
    ts = path.stat().st_mtime
    return datetime.fromtimestamp(ts, tz=timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def finalize_run(
    pack_dir: Path,
    *,
    project_name: Optional[str] = None,
    baseline_dir: Optional[Path] = None,
    snapshot: bool = True,
) -> Dict[str, Any]:
    """Write run_metrics.json, run_manifest.json, optional versioned snapshot under runs/."""
    pack_dir = Path(pack_dir)
    manifest = build_run_manifest(pack_dir, project_name=project_name, baseline_dir=baseline_dir)
    metrics = collect_run_metrics(pack_dir)
    manifest['metrics'] = metrics.get('metrics')

    runs_dir = pack_dir / 'runs'
    run_id = _next_run_id(runs_dir)
    manifest['run_id'] = run_id

    write_json(pack_dir / 'run_metrics.json', metrics)
    write_json(pack_dir / 'run_manifest.json', manifest)

    if snapshot:
        run_root = runs_dir / run_id
        for sub, files in (
            ('static', ['api_card_pack_manifest.json', 'all_api_cards.json']),
            ('materialization', ['materialization_report.json', 'request_templates.json']),
            ('verification', ['search_session.json', 'replay_preflight_report.json']),
            ('findings', ['finding_registry.json', 'finding_chain_reports.json']),
            ('llm', ['llm_trace_session.json']),
        ):
            dest = run_root / sub
            dest.mkdir(parents=True, exist_ok=True)
            for fname in files:
                src = pack_dir / fname
                if src.exists():
                    shutil.copy2(src, dest / fname)
        write_json(run_root / 'manifest.json', manifest)
        write_json(run_root / 'run_metrics.json', metrics)
        latest = runs_dir / 'latest'
        if latest.exists() or latest.is_symlink():
            try:
                latest.unlink()
            except OSError:
                pass
        try:
            latest.symlink_to(run_id, target_is_directory=True)
        except OSError:
            write_json(latest / 'pointer.json', {'run_id': run_id, 'path': str(run_root)})

    return manifest
