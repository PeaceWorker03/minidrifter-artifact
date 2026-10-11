# -*- coding: utf-8
"""LLM call health — persist failures and session stats for debugging."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from minidrifter.core.utils import write_json


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def record_llm_event(
    pack_dir: Path,
    *,
    agent: str,
    status: str,
    error: Optional[str] = None,
    used_llm: bool = False,
    extra: Optional[Dict[str, Any]] = None,
) -> None:
    pack_dir = Path(pack_dir)
    path = pack_dir / 'llm_health.jsonl'
    rec = {
        'at': _utc_now(),
        'agent': agent,
        'status': status,
        'used_llm': used_llm,
        'error': error,
        **(extra or {}),
    }
    existing = path.read_text(encoding='utf-8') if path.exists() else ''
    path.write_text(existing + json.dumps(rec, ensure_ascii=False) + '\n', encoding='utf-8')


def summarize_llm_health(pack_dir: Path, traces: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    pack_dir = Path(pack_dir)
    path = pack_dir / 'llm_health.jsonl'
    events: List[Dict[str, Any]] = []
    if path.exists():
        for line in path.read_text(encoding='utf-8').splitlines():
            if line.strip():
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    pass

    ok = sum(1 for e in events if e.get('status') == 'ok' or e.get('used_llm'))
    err = sum(1 for e in events if e.get('error') or 'error' in str(e.get('status', '')))
    fallback = sum(1 for e in events if 'fallback' in str(e.get('status', '')))

    trace_stats = {'total': 0, 'ok': 0, 'llm_error_fallback': 0, 'dry_run': 0}
    for t in traces or []:
        trace_stats['total'] += 1
        st = t.get('status') or 'ok'
        if st == 'ok':
            trace_stats['ok'] += 1
        elif 'fallback' in st:
            trace_stats['llm_error_fallback'] += 1
        elif 'dry_run' in st:
            trace_stats['dry_run'] += 1

    summary = {
        'schema_version': '1.0.0',
        'generated_at': _utc_now(),
        'event_count': len(events),
        'llm_ok': ok,
        'llm_errors': err,
        'llm_fallbacks': fallback,
        'trace_stats': trace_stats,
        'recent_errors': [e for e in events if e.get('error')][-5:],
    }
    write_json(pack_dir / 'llm_health_summary.json', summary)
    return summary
