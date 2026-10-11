# -*- coding: utf-8
"""Console session — persisted workspace / pack / verify defaults."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from minidrifter.core.utils import write_json

DEFAULT_SESSION: Dict[str, Any] = {
    'schema_version': '1.1.0',
    'workspace': 'Workspace',
    'MiniDrifter_root': '',
    'project_root': '',
    'pack_dir': '',
    'source_dir': '',
    'baseline_dir': '',
    'mode': 'dry-run',
    'with_llm': True,
    'deep_think': True,
    'max_http': 250,
    'max_llm': 80,
    'max_depth': 5,
    'beam_width': 5,
    'anchor_api': '',
    'i_know_acknowledged': False,
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


class ConsoleSession:
    """Persisted console state — stored next to pack_dir or in project root."""

    def __init__(self, path: Optional[Path] = None) -> None:
        self.path = Path(path) if path else Path.cwd() / 'MiniDrifter_console_session.json'
        self.data: Dict[str, Any] = self._load()

    def _load(self) -> Dict[str, Any]:
        if self.path.exists():
            try:
                doc = json.loads(self.path.read_text(encoding='utf-8'))
                merged = {**DEFAULT_SESSION, **doc}
                return merged
            except (json.JSONDecodeError, OSError):
                pass
        return dict(DEFAULT_SESSION)

    def save(self) -> None:
        self.data['updated_at'] = _utc_now()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        write_json(self.path, self.data)

    def get(self, key: str, default: Any = None) -> Any:
        return self.data.get(key, default)

    def set(self, key: str, value: Any) -> None:
        self.data[key] = value
        self.save()

    def pack_path(self) -> Optional[Path]:
        p = self.data.get('pack_dir') or ''
        return Path(p) if p else None

    def project_path(self) -> Optional[Path]:
        p = self.data.get('project_root') or ''
        return Path(p) if p else None

    def require_pack(self) -> Path:
        p = self.pack_path()
        if not p or not p.is_dir():
            raise ValueError('Pack dir not set. Use menu [2] or [8] to configure.')
        return p

    def relocate_session_to_pack(self) -> None:
        """When pack_dir is set, store session inside pack for portability."""
        pack = self.pack_path()
        if pack:
            new_path = pack / 'MiniDrifter_console_session.json'
            if new_path != self.path:
                self.path = new_path
                self.save()
