# -*- coding: utf-8 -*-
"""Export request_facts.json from pack OUTPUT / in-memory analyze result."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional

from minidrifter.core.utils import write_json
from minidrifter.request_facts.builder import build_request_facts_pack


def write_request_facts(
    pack_dir: Path | str,
    *,
    result: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    pack_dir = Path(pack_dir)
    business_ops: list = []
    crypto_cards: list = []
    wrappers: list = []
    events: list = []

    if result:
        opt = result.get('optimizer_outputs') or {}
        business_ops = opt.get('business_api_operations') or opt.get('ranked_api_candidates') or []
        crypto_cards = result.get('crypto_cards') or []
        wrappers = result.get('request_wrappers') or []
        events = result.get('events') or []
    else:
        for name in ('business_api_operations.json', 'ranked_api_candidates.json'):
            p = pack_dir / name
            if p.exists():
                business_ops = json.loads(p.read_text(encoding='utf-8'))
                break
        for name, target in (
            ('crypto_cards.json', 'crypto'),
            ('request_wrappers.json', 'wrappers'),
            ('events.json', 'events'),
        ):
            p = pack_dir / name
            if p.exists():
                data = json.loads(p.read_text(encoding='utf-8'))
                if target == 'crypto':
                    crypto_cards = data if isinstance(data, list) else data.get('cards') or []
                elif target == 'wrappers':
                    wrappers = data if isinstance(data, list) else []
                else:
                    events = data if isinstance(data, list) else data.get('events') or []

    doc = build_request_facts_pack(
        business_ops,
        crypto_cards=crypto_cards if isinstance(crypto_cards, list) else [],
        wrappers=wrappers if isinstance(wrappers, list) else [],
        events=events if isinstance(events, list) else [],
    )
    write_json(pack_dir / 'request_facts.json', doc)
    return doc
