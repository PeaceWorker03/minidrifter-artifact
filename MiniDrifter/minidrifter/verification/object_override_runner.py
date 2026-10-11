# -*- coding: utf-8 -*-
"""Object identifier override runner — reuses subject override machinery for object anchors."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from minidrifter.business_chain.chain_run_context import load_json
from minidrifter.classification.object_wire_candidate_miner import load_object_wire_candidates
from minidrifter.core.utils import write_json
from minidrifter.materials.intake_param_hints import normalize_api_path
from minidrifter.verification.subject_override_oracle import summarize_subject_override_batch
from minidrifter.verification.subject_override_runner import run_subject_override_one


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def select_object_override_targets(
    pack_dir: Path,
    *,
    templates_by_id: Dict[str, Dict[str, Any]],
    max_targets: int = 3,
) -> List[Dict[str, Any]]:
    """Pick object-wire candidates with mutation-eligible object fields."""
    mined = load_object_wire_candidates(pack_dir)
    out: List[Dict[str, Any]] = []
    seen: set[str] = set()
    for cand in mined.get('candidates') or []:
        path = cand.get('path') or cand.get('api') or ''
        norm = normalize_api_path(path)
        if not path or norm in seen:
            continue
        wire_fields = cand.get('wire_object_fields') or []
        if not wire_fields:
            continue
        api_id = cand.get('api_id') or ''
        if not api_id:
            for tid, tpl in templates_by_id.items():
                if normalize_api_path(tpl.get('path') or '') == norm:
                    api_id = tid
                    break
        if not api_id or not templates_by_id.get(api_id):
            continue
        best = wire_fields[0]
        seen.add(norm)
        out.append({
            'api': path,
            'api_id': api_id,
            'plane': cand.get('plane'),
            'campaign_role': cand.get('campaign_role'),
            'selected_field': best.get('field'),
            'selected_value': None,
            'source': best.get('location'),
            'field_source': 'object_wire_candidate_miner',
            'allowed': True,
            'reason': ['object_identifier_on_wire'],
            'mutation_kind': 'object_override',
            'priority': cand.get('priority'),
        })
        if len(out) >= max_targets:
            break
    return out


def run_object_override_batch(
    pack_dir: Path,
    *,
    templates_by_id: Dict[str, Dict[str, Any]],
    mode: str = 'execute',
    max_targets: int = 3,
    max_http: int = 30,
    source_dir: Optional[Path] = None,
    base_url: Optional[str] = None,
) -> Dict[str, Any]:
    """Execute M0 + M7-object for APIs with wire-level object identifiers."""
    pack_dir = Path(pack_dir)
    targets = select_object_override_targets(
        pack_dir, templates_by_id=templates_by_id, max_targets=max_targets,
    )
    baseline = load_json(pack_dir / 'baseline_runtime_context.json') or {}
    replay_doc = load_json(pack_dir / 'sensitive_replay_context.json') or {}
    results: List[Dict[str, Any]] = []
    http_calls = 0

    for target in targets:
        if http_calls >= max_http:
            break
        row = run_subject_override_one(
            target,
            pack_dir=pack_dir,
            baseline_context=baseline,
            templates_by_id=templates_by_id,
            mode=mode,
            source_dir=source_dir,
            base_url=base_url,
            replay_context_doc=replay_doc,
        )
        row['mutation_kind'] = 'object_override'
        st = str(row.get('subject_override_status') or '')
        if st.startswith('subject_override_'):
            row['object_override_status'] = st.replace('subject_override_', 'object_override_', 1)
        http_calls += int(row.get('http_calls') or 0)
        results.append(row)

    summary = summarize_subject_override_batch(results)
    doc = {
        'schema_version': '1.0.0',
        'generated_at': _utc_now(),
        'pack_dir': str(pack_dir),
        'mode': mode,
        'summary': summary,
        'results': results,
    }
    write_json(pack_dir / 'object_override_report.json', doc)
    return doc
