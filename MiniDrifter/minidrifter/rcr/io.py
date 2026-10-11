# -*- coding: utf-8 -*-
"""Load RCR pack (paper: Reference Contract Representation)."""
from __future__ import annotations
import json
from pathlib import Path
from typing import Any, Dict, List

def load_rcr_pack(pack_dir) -> Dict[str, Any]:
    pack = Path(pack_dir)
    for name in ('rcr_pack.json', 'ccr_pack.json'):
        path = pack / name
        if path.exists():
            return json.loads(path.read_text(encoding='utf-8'))
    return {}

def load_rcrs(pack_dir) -> List[Dict[str, Any]]:
    doc = load_rcr_pack(pack_dir)
    return list(doc.get('rcrs') or doc.get('ccrs') or [])
