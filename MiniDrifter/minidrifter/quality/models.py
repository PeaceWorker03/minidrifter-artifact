# -*- coding: utf-8 -*-
"""Static quality issue models."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from minidrifter.quality.taxonomy import ISSUE_REGISTRY, ISSUE_CLASSES


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


@dataclass
class StaticIssue:
    code: str
    message: str
    artifact: Optional[str] = None
    evidence: Optional[Dict[str, Any]] = None
    severity: Optional[str] = None
    issue_class: Optional[str] = None
    remediation: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        meta = ISSUE_REGISTRY.get(self.code) or {}
        return {
            'code': self.code,
            'issue_class': self.issue_class or meta.get('class'),
            'issue_class_label': ISSUE_CLASSES.get(self.issue_class or meta.get('class') or '', ''),
            'severity': self.severity or meta.get('severity') or 'info',
            'message': self.message,
            'artifact': self.artifact,
            'evidence': self.evidence or {},
            'remediation': self.remediation or meta.get('hint'),
        }


@dataclass
class QualityReport:
    schema_version: str = '1.0.0'
    phase: str = 'post_analyze'
    generated_at: str = field(default_factory=_utc_now)
    issues: List[StaticIssue] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)
    resolutions_applied: List[str] = field(default_factory=list)

    def add(self, issue: StaticIssue) -> None:
        self.issues.append(issue)

    def to_dict(self) -> Dict[str, Any]:
        by_class: Dict[str, int] = {}
        by_severity: Dict[str, int] = {}
        for i in self.issues:
            d = i.to_dict()
            cls = d.get('issue_class') or 'unknown'
            sev = d.get('severity') or 'info'
            by_class[cls] = by_class.get(cls, 0) + 1
            by_severity[sev] = by_severity.get(sev, 0) + 1
        return {
            'schema_version': self.schema_version,
            'phase': self.phase,
            'generated_at': self.generated_at,
            'issue_count': len(self.issues),
            'by_class': by_class,
            'by_severity': by_severity,
            'resolutions_applied': self.resolutions_applied,
            'summary': self.summary,
            'issues': [i.to_dict() for i in self.issues],
        }
