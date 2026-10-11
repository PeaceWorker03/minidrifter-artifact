# -*- coding: utf-8 -*-
"""Load LLM settings from config/llm.json + optional overrides + environment."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict


def _project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def load_llm_config(overrides: Dict[str, Any] | None = None) -> Dict[str, Any]:
    root = _project_root()
    cfg: Dict[str, Any] = {}
    base_path = root / 'config' / 'llm.json'
    if base_path.exists():
        cfg.update(json.loads(base_path.read_text(encoding='utf-8')))
    local_path = root / 'config' / 'llm.local.json'
    if local_path.exists():
        cfg.update(json.loads(local_path.read_text(encoding='utf-8')))
    _load_dotenv(root / '.env')
    if overrides:
        cfg.update(overrides)
    key_env = cfg.get('api_key_env') or 'MiniDrifter_LLM_API_KEY'
    # env overrides config file; config file allows keyless .env for local testing
    cfg['api_key'] = os.environ.get(key_env) or cfg.get('api_key')
    base = (cfg.get('base_url') or '').rstrip('/')
    path = cfg.get('chat_completions_path') or '/chat/completions'
    if not path.startswith('/'):
        path = '/' + path
    cfg['chat_completions_url'] = f"{base}{path}"
    return cfg


def _load_dotenv(path: Path) -> None:
    if not path.exists():
        return
    for line in path.read_text(encoding='utf-8').splitlines():
        line = line.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        key, _, value = line.partition('=')
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)
