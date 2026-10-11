# -*- coding: utf-8 -*-
"""Mine signature-related evidence from decompiled JS and static pack artifacts."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

SIGN_FN_HINTS = (
    'getBaseApiData',
    'saltDataToStr',
    'makeSign',
    'getSign',
    'createSign',
    'buildSign',
    'signRequest',
)
SIGN_FIELD_HINTS = ('signature', 'nonce', 'timestamp', 'sign', 'noncestr', 'nonceStr')
MD5_HINTS = ('md5', 'spark-md5', 'hashBinary', 'VbxO4mge')
SALT_ARRAY_RE = re.compile(
    r'saltDataToStr\s*\(\s*[^,]+,\s*\[([0-9,\s]+)\]',
    re.I,
)
INDEX_ARRAY_RE = re.compile(r'\[((?:\s*\d+\s*,){3,}\s*\d+\s*)\]')


def _read_json(path: Path) -> Any:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except json.JSONDecodeError:
        return None


def _scan_js_text(text: str, *, label: str) -> Dict[str, Any]:
    lower = text.lower()
    hits = {
        'label': label,
        'functions': sorted({h for h in SIGN_FN_HINTS if h in text}),
        'sign_fields': sorted({h for h in SIGN_FIELD_HINTS if h.lower() in lower}),
        'md5_hints': sorted({h for h in MD5_HINTS if h.lower() in lower}),
        'salt_index_groups': [],
        'literal_secrets': [],
    }
    groups: List[Tuple[int, ...]] = []
    for m in SALT_ARRAY_RE.finditer(text):
        nums = tuple(int(x.strip()) for x in m.group(1).split(',') if x.strip())
        if nums and nums not in groups:
            groups.append(nums)
    if not groups:
        for m in INDEX_ARRAY_RE.finditer(text):
            nums = tuple(int(x.strip()) for x in m.group(1).split(',') if x.strip())
            if len(nums) >= 8 and nums not in groups:
                groups.append(nums)
    hits['salt_index_groups'] = [list(g) for g in groups[:6]]
    for m in re.finditer(r'["\']([A-Za-z0-9+/=]{12,64})["\']', text):
        val = m.group(1)
        if val.isdigit():
            continue
        hits['literal_secrets'].append(val)
    hits['literal_secrets'] = sorted(set(hits['literal_secrets']))[:20]
    return hits


def _iter_js_files(source_dir: Path, limit: int = 400) -> List[Path]:
    if not source_dir.exists():
        return []
    files = [p for p in source_dir.rglob('*.js') if p.is_file()]
    files.sort(key=lambda p: (
        0 if any(h in p.name.lower() for h in ('app.js', 'common', 'http', 'request')) else 1,
        len(str(p)),
    ))
    return files[:limit]


def mine_signature_static_evidence(
    *,
    pack_dir: Path,
    source_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    pack_dir = Path(pack_dir)
    evidence: Dict[str, Any] = {
        'wrapper_files': [],
        'function_hits': [],
        'sign_fields': [],
        'md5_hints': [],
        'salt_index_groups': [],
        'literal_secrets': [],
        'primary_wrapper': None,
    }

    wrappers = _read_json(pack_dir / 'request_wrappers.json') or []
    crypto_cards = _read_json(pack_dir / 'crypto_cards.json') or []
    if isinstance(wrappers, list):
        for wrap in wrappers:
            hints = (wrap.get('crypto_hints') or []) + (wrap.get('exported_or_defined_methods') or [])
            blob = ' '.join(str(x) for x in hints).lower()
            if not any(k in blob for k in ('sign', 'md5', 'nonce', 'signature')):
                continue
            evidence['wrapper_files'].append(wrap.get('file'))
    if isinstance(crypto_cards, list):
        for card in crypto_cards:
            fn = card.get('function') or ''
            if fn in SIGN_FN_HINTS or 'sign' in str(card.get('crypto_hints') or '').lower():
                evidence['function_hits'].append({
                    'file': card.get('file'),
                    'function': fn,
                })

    scanned: List[Dict[str, Any]] = []
    if source_dir:
        for js_path in _iter_js_files(Path(source_dir)):
            text = js_path.read_text(encoding='utf-8', errors='replace')
            if not any(h in text for h in SIGN_FN_HINTS) and 'signature' not in text.lower():
                continue
            rel = js_path.name
            hit = _scan_js_text(text, label=rel)
            if hit['functions'] or hit['salt_index_groups']:
                scanned.append(hit)
    scanned.sort(key=lambda h: (len(h.get('functions') or []), len(h.get('salt_index_groups') or [])), reverse=True)
    if scanned:
        top = scanned[0]
        evidence['primary_wrapper'] = top['label']
        evidence['function_hits'].extend(
            {'file': top['label'], 'function': fn} for fn in top.get('functions') or []
        )
        evidence['sign_fields'] = top.get('sign_fields') or []
        evidence['md5_hints'] = top.get('md5_hints') or []
        evidence['salt_index_groups'] = top.get('salt_index_groups') or []
        evidence['literal_secrets'] = top.get('literal_secrets') or []
    evidence['function_hits'] = _dedupe_dicts(evidence['function_hits'])
    evidence['wrapper_files'] = sorted(set(x for x in evidence['wrapper_files'] if x))
    return evidence


def _dedupe_dicts(rows: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    out: List[Dict[str, Any]] = []
    for row in rows:
        key = (row.get('file'), row.get('function'))
        if key in seen:
            continue
        seen.add(key)
        out.append(row)
    return out
