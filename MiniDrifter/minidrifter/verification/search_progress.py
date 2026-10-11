# -*- coding: utf-8 -*-
"""Structured stdout + file progress for verification search engines."""
from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


class SearchProgress:
    """Line-buffered progress reporter — safe for Tee-Object / CI logs."""

    def __init__(
        self,
        pack_dir: Optional[Path] = None,
        *,
        engine: str = 'apex',
        enabled: bool = True,
        log_filename: str = 'search_progress.log',
    ) -> None:
        self.engine = engine
        self.enabled = enabled
        self._log_path = Path(pack_dir) / log_filename if pack_dir else None
        self._step = 0

    def emit(self, phase: str, message: str, **fields: Any) -> None:
        if not self.enabled:
            return
        self._step += 1
        ts = _utc_now()
        extras = ' '.join(f'{k}={v}' for k, v in fields.items() if v is not None and v != '')
        line = f'[{ts}] [MiniDrifter:{self.engine}] [{phase}] {message}'
        if extras:
            line = f'{line} | {extras}'
        print(line, flush=True)
        if self._log_path:
            self._log_path.parent.mkdir(parents=True, exist_ok=True)
            existing = self._log_path.read_text(encoding='utf-8') if self._log_path.exists() else ''
            self._log_path.write_text(existing + line + '\n', encoding='utf-8')

    def banner(self, title: str, **fields: Any) -> None:
        self.emit('INIT', f'--- {title} ---', **fields)

    def http_execute(
        self,
        *,
        n: int,
        max_n: int,
        path: str,
        stage: str,
        mutation: Optional[str] = None,
        chain_id: Optional[str] = None,
    ) -> None:
        mut = mutation or 'M0'
        self.emit(
            'HTTP',
            f'[{n}/{max_n}] {stage} {path}',
            mutation=mut,
            chain=(chain_id[:16] if chain_id else None),
        )

    def http_result(
        self,
        *,
        path: str,
        outcome: str,
        failure_class: Optional[str] = None,
        harvested: Optional[str] = None,
        suspicious: bool = False,
    ) -> None:
        fc = failure_class or outcome
        self.emit(
            'RESULT',
            path,
            outcome=outcome,
            failure_class=fc if fc != outcome else None,
            harvest=harvested,
            finding='yes' if suspicious else None,
        )

    def diagnose(self, *, path: str, layer: str, action: str, diagnosis: str) -> None:
        self.emit('DIAGNOSE', path, layer=layer, action=action, diagnosis=diagnosis)

    def hop_adjudicate(
        self,
        *,
        path: str,
        health: str,
        root_cause: str,
        missing: Optional[str] = None,
        retry: bool = False,
        used_llm: bool = False,
    ) -> None:
        self.emit(
            'HOP',
            root_cause[:140],
            path=path,
            health=health,
            missing=missing[:80] if missing else None,
            retry='yes' if retry else None,
            llm='yes' if used_llm else 'rule',
        )

    def circuit(self, *, failure_class: str, open_now: bool, pause: bool = False) -> None:
        self.emit(
            'CIRCUIT',
            f'breaker {"OPEN" if open_now else "count"}',
            failure_class=failure_class,
            pause_execute='yes' if pause else None,
        )

    def policy(self, *, action: str, reason: str, used_llm: bool = False) -> None:
        self.emit('POLICY', action, reason=reason[:120], llm='yes' if used_llm else 'rule')

    def llm_wait(self, *, stage: str, detail: str = '') -> None:
        self.emit('LLM', f'calling {stage}...', detail=detail[:80] or None)

    def beam(self, *, event: str, chain_id: str, domain: str = '', detail: str = '') -> None:
        self.emit('BEAM', event, chain=chain_id[:20], domain=domain or None, detail=detail[:80] or None)

    def chain_think(
        self,
        *,
        chain_id: str,
        trigger: str,
        verdict: str,
        summary: str,
        layer: Optional[str] = None,
        actions: Optional[str] = None,
        used_llm: bool = False,
    ) -> None:
        self.emit(
            'THINK',
            summary[:160],
            chain=chain_id[:20],
            trigger=trigger,
            verdict=verdict,
            layer=layer,
            actions=actions[:100] if actions else None,
            llm='yes' if used_llm else 'rule',
        )

    def acquire(self, *, target_field: str, producer_path: str, score: float) -> None:
        self.emit('ACQUIRE', f'plan {target_field}', producer=producer_path, score=score)

    def summary(self, **fields: Any) -> None:
        self.emit('DONE', 'search completed', **fields)


def ensure_unbuffered_stdout() -> None:
    """Best-effort line buffering so progress appears under pipes."""
    try:
        sys.stdout.reconfigure(line_buffering=True)  # type: ignore[attr-defined]
    except (AttributeError, OSError, ValueError):
        pass
