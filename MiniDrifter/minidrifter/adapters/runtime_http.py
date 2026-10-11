# -*- coding: utf-8
"""Runtime adapter for raw HTTP capture intake."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional

from minidrifter.adapters.base import RuntimeAdapter
from minidrifter.materials.baseline_intake import build_intake_report


class HttpRuntimeAdapter(RuntimeAdapter):
    def __init__(self, profile: Dict[str, Any] | None = None) -> None:
        self._profile = profile or {}

    def parse_user_input(
        self,
        raw: str,
        *,
        source_dir: Optional[Path] = None,
        pack_dir: Optional[Path] = None,
    ) -> Dict[str, Any]:
        if not pack_dir:
            return {'error': 'pack_dir_required'}
        return build_intake_report(raw, Path(pack_dir), source_dir=source_dir)

    def update_object_pool(self, parsed: Dict[str, Any], pool: Dict[str, Any]) -> Dict[str, Any]:
        agg = parsed.get('decrypted_fields_aggregate') or {}
        fields = agg.get('fields') or {}
        pool = dict(pool or {})
        for k, v in fields.items():
            pool[k] = v
        return pool
