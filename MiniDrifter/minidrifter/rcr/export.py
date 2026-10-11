# -*- coding: utf-8 -*-
"""Export rcr_pack.json and enrich api card semantic stubs."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional

from minidrifter.rcr.construct import construct_rcr_pack
from minidrifter.core.utils import write_json


def write_rcr_pack(pack_dir: Path | str, *, request_facts: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    pack_dir = Path(pack_dir)
    if request_facts is None:
        rf_path = pack_dir / 'request_facts.json'
        if not rf_path.exists():
            from minidrifter.request_facts.export import write_request_facts
            request_facts = write_request_facts(pack_dir)
        else:
            request_facts = json.loads(rf_path.read_text(encoding='utf-8'))

    doc = construct_rcr_pack(request_facts)
    write_json(pack_dir / 'rcr_pack.json', doc)

    # Enrich api_cards.json semantic block when present (backward compatible).
    cards_path = pack_dir / 'api_cards.json'
    if cards_path.exists():
        try:
            cards = json.loads(cards_path.read_text(encoding='utf-8'))
            by_id = {c.get('operation_id') or ((c.get('static') or {}).get('operation_id')): c for c in cards if isinstance(c, dict)}
            # Also index by endpoint path+method
            ccr_by_op = {c.get('operation_id'): c for c in doc.get('ccrs') or []}
            changed = False
            for card in cards:
                if not isinstance(card, dict):
                    continue
                oid = card.get('operation_id') or ((card.get('static') or {}).get('operation_id'))
                RCR = ccr_by_op.get(oid)
                if not RCR:
                    continue
                sem = card.get('semantic')
                if not isinstance(sem, dict):
                    sem = {}
                sem.update({
                    '_phase': 'ccr_static',
                    'identity_anchor': (RCR.get('request_semantics') or {}).get('identity_anchor'),
                    'binding_credentials': RCR.get('binding_credentials') or [],
                    'credentials': (RCR.get('request_semantics') or {}).get('credentials') or [],
                    'operation': (RCR.get('request_semantics') or {}).get('operation'),
                    'ccr_ref': oid,
                })
                card['semantic'] = sem
                changed = True
            if changed:
                write_json(cards_path, cards)
        except Exception:
            pass

    return doc
