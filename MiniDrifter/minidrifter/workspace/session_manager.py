# -*- coding: utf-8
"""Workspace session — tracks selected project, pack dir, tickets, resume state."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from minidrifter.core.utils import write_json

SCHEMA = '1.0.0'


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


class WorkspaceSession:
    def __init__(self, workspace: Path) -> None:
        self.workspace = Path(workspace)
        self.path = self.workspace / 'MiniDrifter_session.json'
        self.data: Dict[str, Any] = self._load()

    def _load(self) -> Dict[str, Any]:
        if self.path.exists():
            return json.loads(self.path.read_text(encoding='utf-8'))
        return {
            'schema_version': SCHEMA,
            'workspace': str(self.workspace),
            'selected_project': None,
            'pack_dir': None,
            'phase': 'scan',
            'pending_tickets': [],
        }

    def select_project(self, project_id: str, *, project_root: str, pack_dir: str) -> None:
        self.data['selected_project'] = project_id
        self.data['project_root'] = project_root
        self.data['pack_dir'] = pack_dir
        self.data['phase'] = 'selected'
        self.data['updated_at'] = _utc_now()
        self.save()

    def set_phase(self, phase: str) -> None:
        self.data['phase'] = phase
        self.data['updated_at'] = _utc_now()
        self.save()

    def save(self) -> None:
        write_json(self.path, self.data)

    @property
    def pack_dir(self) -> Optional[Path]:
        p = self.data.get('pack_dir')
        return Path(p) if p else None
