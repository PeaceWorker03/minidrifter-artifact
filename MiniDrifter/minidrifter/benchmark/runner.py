# -*- coding: utf-8
"""Benchmark metrics collector — compare packs without overfitting to one app."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from minidrifter.core.utils import write_json
from minidrifter.ir.export import export_universal_ir


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _load(path: Path) -> Any:
    if path.exists():
        return json.loads(path.read_text(encoding='utf-8'))
    return None


def collect_pack_metrics(pack_dir: Path, *, profile_id: Optional[str] = None) -> Dict[str, Any]:
    pack_dir = Path(pack_dir)
    ir = export_universal_ir(pack_dir, profile_id=profile_id)
    summary = ir.get('summary') or {}

    cards_doc = _load(pack_dir / 'api_cards.json') or {}
    cards = cards_doc if isinstance(cards_doc, list) else cards_doc.get('cards') or []
    if not cards and (pack_dir / 'api_cards.json').exists():
        raw = _load(pack_dir / 'api_cards.json')
        cards = raw if isinstance(raw, list) else (raw or {}).get('items') or []

    methods_known = sum(
        1 for c in cards
        if ((c.get('static') or {}).get('http') or {}).get('method') not in (None, '', 'UNKNOWN')
    )
    replay_ready = sum(1 for c in cards if (c.get('replay') or {}).get('readiness') == 'ready')

    session = _load(pack_dir / 'search_session.json') or {}
    cov = session.get('coverage') or {}
    budget = session.get('budget') or {}

    total = len(cards) or summary.get('api_card_count') or 1
    http_used = budget.get('used_http') or cov.get('http_calls') or 0
    http_ok = cov.get('business_success') or 0

    return {
        'schema_version': '1.0.0',
        'generated_at': _utc_now(),
        'pack_dir': str(pack_dir),
        'profile_id': ir.get('profile_id'),
        'metrics': {
            'api_recovery_count': total,
            'method_resolved_rate': round(methods_known / total, 4),
            'replay_ready_rate': round(replay_ready / total, 4),
            'n_tier_distribution': summary.get('n_tier_distribution') or {},
            'object_field_count': summary.get('baseline_field_count') or 0,
            'chain_hypothesis_count': summary.get('chain_hypotheses') or 0,
            'http_execution_count': http_used,
            'http_execution_success_rate': round(http_ok / http_used, 4) if http_used else None,
            'confirmed_finding_count': summary.get('confirmed_findings') or 0,
            'open_ticket_count': summary.get('open_tickets') or 0,
            'crypto_replay_ready': summary.get('crypto_replay_ready'),
            'manual_effort_estimate': _estimate_manual_effort(summary),
        },
        'universal_ir_bundle': ir.get('artifacts', {}).get('universal_ir_bundle'),
    }


def _estimate_manual_effort(summary: Dict[str, Any]) -> str:
    tickets = summary.get('open_tickets') or 0
    fields = summary.get('baseline_field_count') or 0
    if fields >= 10 and tickets == 0:
        return 'low'
    if fields >= 5 and tickets <= 3:
        return 'medium'
    return 'high'


def run_benchmark(manifest_path: Optional[Path] = None, *, pack_dirs: Optional[List[Path]] = None) -> Dict[str, Any]:
    root = Path(__file__).resolve().parents[2] / 'packs' / 'benchmark'
    manifest_path = manifest_path or root / 'manifest.json'
    manifest = _load(manifest_path) or {'benchmarks': []}

    results: List[Dict[str, Any]] = []
    if pack_dirs:
        for p in pack_dirs:
            results.append(collect_pack_metrics(p))
    else:
        for bench in manifest.get('benchmarks') or []:
            for rel in bench.get('example_packs') or []:
                pack = Path(__file__).resolve().parents[2] / rel
                if pack.is_dir():
                    m = collect_pack_metrics(pack)
                    m['benchmark_id'] = bench.get('id')
                    m['benchmark_profile'] = bench.get('profile_id')
                    results.append(m)

    report = {
        'schema_version': '1.0.0',
        'generated_at': _utc_now(),
        'manifest': str(manifest_path),
        'results': results,
    }
    out = root / 'last_benchmark_report.json'
    write_json(out, report)
    return report
