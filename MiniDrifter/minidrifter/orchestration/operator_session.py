# -*- coding: utf-8
"""Operator session — pause verify on blocker, emit user request, resume after intake."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from minidrifter.core.utils import write_json
from minidrifter.orchestration.intake_prompts import build_operator_request, format_request_for_console

PAUSABLE_FAILURES = frozenset({
    'auth_expired',
    'app_version_blocked',
    'business_state_blocked',
    'build_failed',
    'transport_url_routing',
})


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


class OperatorSession:
    """Tracks pending user actions during live verification."""

    def __init__(self, pack_dir: Path) -> None:
        self.pack_dir = Path(pack_dir)
        self.pending: List[Dict[str, Any]] = []
        self.resolved: List[Dict[str, Any]] = []
        self.pause_reason: Optional[str] = None

    def should_pause(self, attribution: Dict[str, Any]) -> bool:
        fc = attribution.get('failure_class') or ''
        action = attribution.get('primary_action') or ''
        if fc in PAUSABLE_FAILURES:
            return True
        if action in ('refresh_baseline', 'acquire_object', 'intake_baseline'):
            return True
        return False

    def emit_request(
        self,
        *,
        trigger: str,
        attribution: Optional[Dict[str, Any]] = None,
        policy: Optional[Dict[str, Any]] = None,
        test_case: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        req = build_operator_request(
            trigger=trigger,
            attribution=attribution,
            policy=policy,
            test_case=test_case,
        )
        self.pending.append(req)
        self.pause_reason = req.get('failure_class')
        self._persist()
        return req

    def resolve(self, request_id: str, *, note: str = '') -> None:
        for i, req in enumerate(self.pending):
            if req.get('request_id') == request_id:
                resolved = {**req, 'resolved_at': _utc_now(), 'note': note}
                self.resolved.append(resolved)
                self.pending.pop(i)
                break
        if not self.pending:
            self.pause_reason = None
        self._persist()

    def to_document(self) -> Dict[str, Any]:
        return {
            'schema_version': '1.0.0',
            'generated_at': _utc_now(),
            'pack_dir': str(self.pack_dir),
            'paused': bool(self.pending),
            'pause_reason': self.pause_reason,
            'pending_count': len(self.pending),
            'pending': self.pending,
            'resolved': self.resolved,
        }

    def _persist(self) -> None:
        write_json(self.pack_dir / 'operator_session.json', self.to_document())
        if self.pending:
            latest = self.pending[-1]
            (self.pack_dir / 'operator_request.txt').write_text(
                format_request_for_console(latest), encoding='utf-8',
            )


def apply_user_capture(
    pack_dir: Path,
    raw_http: str,
    *,
    source_label: str = 'operator_resume',
    source_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """After user pastes capture — run intake report; caller should import-after."""
    from minidrifter.materials.baseline_intake import build_intake_report
    from minidrifter.materials.har_sequence import looks_like_har

    pack_dir = Path(pack_dir)
    report = build_intake_report(
        raw_http, pack_dir,
        source_label=source_label,
        source_path=source_path,
    )
    write_json(pack_dir / 'baseline_intake_report.json', report)
    session_path = pack_dir / 'operator_session.json'
    if session_path.exists():
        session = OperatorSession(pack_dir)
        data = json.loads(session_path.read_text(encoding='utf-8'))
        session.pending = data.get('pending') or []
        session.resolved = data.get('resolved') or []
        if session.pending:
            session.resolve(session.pending[-1].get('request_id', ''), note='user_capture_intake_done')
    return {
        'intake': report,
        'capture_sequence': str(pack_dir / 'capture_sequence.json') if (pack_dir / 'capture_sequence.json').exists() else None,
        'next_step': (
            'intake-baseline --import-after or workbench resume with --import-after '
            'to merge into baseline_runtime_context.json'
        ),
        'har_sequence': report.get('har_sequence_meta'),
        'is_har': bool(report.get('har_sequence_meta') or looks_like_har(raw_http)),
    }
