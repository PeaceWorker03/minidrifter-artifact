# -*- coding: utf-8
"""Aggregate hop adjudication log into actionable summary."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from minidrifter.core.utils import write_json


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def build_hop_adjudication_summary(hops: List[Dict[str, Any]]) -> Dict[str, Any]:
    health = Counter(h.get('node_health') or 'unknown' for h in hops)
    layers = Counter((h.get('attribution') or {}).get('layer') or '?' for h in hops)
    auto_actions = Counter()
    missing_fields = Counter()
    drift_hops: List[Dict[str, Any]] = []
    blocked_families = Counter()

    for h in hops:
        for a in (h.get('resolution_plan') or {}).get('auto_actions') or []:
            auto_actions[a.get('action') or '?'] += 1
        for m in h.get('missing_materials') or []:
            if m.get('field'):
                missing_fields[m['field']] += 1
        pair = h.get('m0_m7_pair')
        if pair and pair.get('binding_drift_score', 0) >= 0.5:
            drift_hops.append({
                'path': h.get('path'),
                'score': pair.get('binding_drift_score'),
                'signals': pair.get('drift_signals'),
            })
        fam = h.get('path_family') or (h.get('transport_context') or {}).get('family')
        if fam and h.get('node_health') == 'blocked':
            blocked_families[fam] += 1

    top_missing = [
        {'field': f, 'count': c}
        for f, c in missing_fields.most_common(8)
    ]
    return {
        'schema_version': '1.0.0',
        'generated_at': _utc_now(),
        'total_hops': len(hops),
        'node_health': dict(health),
        'layers': dict(layers),
        'auto_actions_applied_plan': dict(auto_actions),
        'top_missing_fields': top_missing,
        'binding_drift_hops': drift_hops[:12],
        'blocked_path_families': dict(blocked_families),
        'llm_enriched': sum(1 for h in hops if h.get('llm_root_cause')),
        'material_request_hops': sum(1 for h in hops if h.get('material_request')),
    }


def write_hop_summary(pack_dir: Path, hops: List[Dict[str, Any]]) -> None:
    if not hops:
        return
    write_json(Path(pack_dir) / 'hop_adjudication_summary.json', build_hop_adjudication_summary(hops))
