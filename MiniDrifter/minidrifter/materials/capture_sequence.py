# -*- coding: utf-8 -*-
"""capture_sequence.json — unified business-path artifact from intake captures."""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from minidrifter.core.utils import write_json
from minidrifter.materials.intake_param_hints import normalize_api_path

SCHEMA_VERSION = '1.0.0'

STAGE_RULES: List[tuple] = [
    (re.compile(r'login|auth|openid|federated|token|session|signin', re.I), 'login_or_profile'),
    (re.compile(r'profile|personal|userinfo|member/info|my/info', re.I), 'login_or_profile'),
    (re.compile(r'address|addr', re.I), 'address'),
    (re.compile(r'list|search|query', re.I), 'list_or_search'),
    (re.compile(r'detail|info/get|getbyid', re.I), 'object_detail'),
    (re.compile(r'balance|wallet|money|remain|cardinfo', re.I), 'wallet_or_balance'),
    (re.compile(r'order|booking|ticket', re.I), 'order_flow'),
    (re.compile(r'pay|confirm|checkout', re.I), 'order_confirm'),
    (re.compile(r'device', re.I), 'device'),
    (re.compile(r'invoice', re.I), 'invoice'),
]

DOMAIN_RULES: List[tuple] = [
    (re.compile(r'login|auth|openid|token', re.I), 'auth'),
    (re.compile(r'address', re.I), 'address'),
    (re.compile(r'order|booking|ticket', re.I), 'order'),
    (re.compile(r'pay|wallet|balance|money', re.I), 'payment'),
    (re.compile(r'device', re.I), 'device'),
    (re.compile(r'invoice', re.I), 'invoice'),
    (re.compile(r'user|member|profile|personal', re.I), 'user'),
]


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def infer_stage(path: str) -> str:
    for pat, stage in STAGE_RULES:
        if pat.search(path or ''):
            return stage
    return 'business_api'


def infer_business_domain(path: str) -> str:
    for pat, domain in DOMAIN_RULES:
        if pat.search(path or ''):
            return domain
    return 'general'


def _load_api_cards(pack_dir: Path) -> List[Dict[str, Any]]:
    for name in ('api_cards.json', 'reached_api_cards.json', 'all_api_cards.json'):
        path = pack_dir / name
        if not path.exists():
            continue
        doc = json.loads(path.read_text(encoding='utf-8'))
        if isinstance(doc, list):
            return doc
        return doc.get('cards') or doc.get('api_cards') or []
    return []


def match_api_card(path: str, cards: List[Dict[str, Any]]) -> Optional[str]:
    norm = normalize_api_path(path)
    if norm in ('/', ''):
        return None
    best_id: Optional[str] = None
    best_len = 0
    for card in cards:
        ep = card.get('endpoint') or {}
        candidates = [
            ep.get('resolved_url') or '',
            ep.get('url_key') or '',
            ep.get('path') or '',
        ]
        for raw in candidates:
            if not raw or raw.startswith('http') and raw.count('/') <= 3:
                continue
            p = normalize_api_path(raw.split('?', 1)[0])
            if not p or p == '/':
                continue
            if norm == p or norm.endswith(p) or p.endswith(norm):
                if len(p) > best_len:
                    best_len = len(p)
                    best_id = card.get('api_id')
    return best_id


def _produces_from_capture(cap: Dict[str, Any]) -> List[str]:
    fields: List[str] = []
    for key in ('response_fields',):
        fields.extend(cap.get(key) or [])
    harvest = cap.get('object_harvest') or {}
    fields.extend(harvest.get('produced_fields') or [])
    agg = (cap.get('crypto_processing') or {}).get('produces_fields') or {}
    fields.extend(agg.keys() if isinstance(agg, dict) else [])
    resp_proc = cap.get('response_crypto_processing') or {}
    fields.extend((resp_proc.get('produces_fields') or {}).keys())
    if cap.get('transport_assessment', {}).get('token_present'):
        fields.append('Token')
    seen: List[str] = []
    for f in fields:
        if f and f not in seen:
            seen.append(f)
    return seen


def _consumes_from_capture(cap: Dict[str, Any]) -> List[str]:
    consumes: List[str] = []
    if cap.get('transport_assessment', {}).get('token_present'):
        consumes.append('Token')
    for layer in cap.get('field_layers') or []:
        name = layer.get('name') or ''
        role = layer.get('layer') or ''
        if role in {'plaintext_auth_token', 'crypto_signature'}:
            if name and name not in consumes:
                consumes.append(name)
    return consumes


def build_capture_sequence(
    pack_dir: Path,
    captures: List[Dict[str, Any]],
    *,
    source: str = 'user_paste',
    har_meta: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    pack_dir = Path(pack_dir)
    cards = _load_api_cards(pack_dir)
    seq_captures: List[Dict[str, Any]] = []
    produced_all: List[str] = []
    matched = 0

    for cap in captures:
        path = cap.get('path') or '/'
        api_id = match_api_card(path, cards)
        if api_id:
            matched += 1
        produces = _produces_from_capture(cap)
        consumes = _consumes_from_capture(cap)
        produced_all.extend(produces)
        seq_captures.append({
            'idx': cap.get('capture_index') or len(seq_captures) + 1,
            'method': cap.get('method') or 'GET',
            'path': path,
            'matched_api_id': api_id,
            'business_domain': infer_business_domain(path),
            'stage': infer_stage(path),
            'produces': produces,
            'consumes': consumes,
            'has_response': bool(
                cap.get('response_fields')
                or cap.get('response_body_preview')
                or (cap.get('response_crypto_processing') or {}).get('body_json')
            ),
            'overall_status': cap.get('overall_status'),
            'started_at': cap.get('started_at'),
        })

    unique_produced = list(dict.fromkeys(produced_all))
    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': _utc_now(),
        'sequence_id': f"seq_{pack_dir.name}_{_utc_now()[:10].replace('-', '')}",
        'source': source,
        'har_meta': har_meta,
        'captures': seq_captures,
        'coverage': {
            'capture_count': len(seq_captures),
            'matched_api_count': matched,
            'unmatched_api_count': len(seq_captures) - matched,
            'produced_fields': unique_produced,
        },
    }


def write_capture_sequence(
    pack_dir: Path,
    report: Dict[str, Any],
    *,
    source: Optional[str] = None,
) -> Dict[str, Any]:
    pack_dir = Path(pack_dir)
    src = source or report.get('source_label') or 'user_paste'
    har_meta = report.get('har_sequence_meta')
    doc = build_capture_sequence(
        pack_dir,
        report.get('captures') or [],
        source=src,
        har_meta=har_meta,
    )
    write_json(pack_dir / 'capture_sequence.json', doc)
    return doc
