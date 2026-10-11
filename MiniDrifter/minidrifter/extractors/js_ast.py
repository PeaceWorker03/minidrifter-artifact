# -*- coding: utf-8 -*-
"""Parse recovered mini-program JavaScript with Acorn (Node.js)."""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional

_SCAN = Path(__file__).resolve().parents[2] / 'tools' / 'jsparser' / 'scan_calls.js'
_PARSER_DIR = _SCAN.parent


def acorn_available() -> bool:
    return shutil.which('node') is not None and (_PARSER_DIR / 'node_modules' / 'acorn').exists() and _SCAN.exists()


def scan_platform_calls(root: Path, *, timeout: float = 120) -> Optional[Dict[str, Any]]:
    """Return Acorn call sites keyed by relative path, or None if the parser cannot run."""
    if not acorn_available():
        return None
    node = shutil.which('node')
    try:
        proc = subprocess.run(
            [node, str(_SCAN), str(root)],
            cwd=str(_PARSER_DIR),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0 or not proc.stdout:
        return None
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    return data
