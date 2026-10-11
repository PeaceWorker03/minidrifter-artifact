# -*- coding: utf-8 -*-
"""Run static quality gates and emit unified report."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from minidrifter.core.utils import write_json
from minidrifter.quality.gates.chain_graph import gate_chain_artifacts
from minidrifter.quality.gates.host_resolution import gate_host_resolution, gate_url_inventory
from minidrifter.quality.gates.static_acceptance import gate_static_acceptance
from minidrifter.quality.models import QualityReport, StaticIssue


def _load_cards(pack_dir: Path) -> List[Dict[str, Any]]:
    path = pack_dir / 'api_cards.json'
    if not path.exists():
        return []
    return json.loads(path.read_text(encoding='utf-8'))


def run_static_quality_gates(
    pack_dir: Path,
    *,
    phase: str = 'post_analyze',
    resolutions_applied: Optional[List[str]] = None,
) -> Dict[str, Any]:
    pack_dir = Path(pack_dir)
    report = QualityReport(phase=phase, resolutions_applied=list(resolutions_applied or []))

    gate_host_resolution(pack_dir, report)
    gate_url_inventory(_load_cards(pack_dir), report)
    acceptance = gate_static_acceptance(pack_dir, report)
    write_json(pack_dir / 'static_acceptance.json', acceptance)
    report.summary['static_acceptance_passed'] = acceptance.get('passed')
    report.summary['static_acceptance_hard_fails'] = acceptance.get('hard_fail_count')

    if phase in {'post_chain', 'full'}:
        gate_chain_artifacts(pack_dir, report)

    adapter = pack_dir / 'adapter_profile.json'
    if adapter.exists():
        report.add(StaticIssue(
            code='EXEC_ADAPTER_PROFILE_WRITTEN',
            message='adapter_profile.json 存在',
            artifact='adapter_profile.json',
            severity='info',
        ))
    else:
        report.add(StaticIssue(
            code='EXEC_ADAPTER_PROFILE_MISSING',
            message='缺少 adapter_profile.json',
            artifact=str(pack_dir),
            severity='error',
        ))

    return report.to_dict()


def write_static_quality_report(
    pack_dir: Path,
    *,
    phase: str = 'post_analyze',
    resolutions_applied: Optional[List[str]] = None,
    merge_existing: bool = True,
) -> Dict[str, Any]:
    pack_dir = Path(pack_dir)
    doc = run_static_quality_gates(
        pack_dir, phase=phase, resolutions_applied=resolutions_applied,
    )
    out = pack_dir / 'static_quality_report.json'
    if merge_existing and out.exists():
        prev = json.loads(out.read_text(encoding='utf-8'))
        prev_issues = {i['code'] + '|' + (i.get('artifact') or '') for i in (prev.get('issues') or [])}
        for issue in doc.get('issues') or []:
            key = issue['code'] + '|' + (issue.get('artifact') or '')
            if key not in prev_issues:
                prev.setdefault('issues', []).append(issue)
        prev['phase'] = phase
        prev['issue_count'] = len(prev.get('issues') or [])
        doc = prev
    write_json(out, doc)
    return doc
