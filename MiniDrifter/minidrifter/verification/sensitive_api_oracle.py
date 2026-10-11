# -*- coding: utf-8 -*-
"""Sensitive API response oracle — PII scope + subject consistency."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from minidrifter.classification.api_plane_classifier import (
    classify_path_to_plane_entry,
    load_sensitive_field_ontology,
)
from minidrifter.classification.sensitive_field_normalizer import (
    detect_normalized_sensitive_fields,
    sensitive_fields_in_body_normalized,
)

_SENSITIVE_KEYWORD_PACK: Optional[Dict[str, Any]] = None


def _load_sensitive_keyword_pack() -> Dict[str, Any]:
    global _SENSITIVE_KEYWORD_PACK
    if _SENSITIVE_KEYWORD_PACK is not None:
        return _SENSITIVE_KEYWORD_PACK
    pack_path = Path(__file__).resolve().parent / 'oracle_packs' / 'sensitive_fields.json'
    if pack_path.exists():
        _SENSITIVE_KEYWORD_PACK = json.loads(pack_path.read_text(encoding='utf-8'))
    else:
        _SENSITIVE_KEYWORD_PACK = {}
    return _SENSITIVE_KEYWORD_PACK


def _norm_key(key: str) -> str:
    return ''.join(ch for ch in str(key or '').lower() if ch.isalnum())


def _keyword_hits(body: Any, keywords: List[str]) -> List[str]:
    flat = _flatten_values(body if isinstance(body, dict) else {})
    hits: List[str] = []
    seen: Set[str] = set()
    kw_norms = [_norm_key(k) for k in keywords if k]
    for raw_key, val in flat.items():
        if val in (None, '', [], {}):
            continue
        nk = _norm_key(raw_key.split('.')[-1])
        if not nk or nk in seen:
            continue
        for kw in kw_norms:
            if kw and (kw in nk or nk in kw):
                seen.add(nk)
                hits.append(raw_key.split('.')[-1])
                break
    return hits


def _path_plane_keywords(path: str) -> List[str]:
    pack = _load_sensitive_keyword_pack()
    entry = classify_path_to_plane_entry(path)
    plane = entry.get('primary_plane') or ''
    plane_doc = (pack.get('planes') or {}).get(plane) or {}
    return list(plane_doc.get('sensitive_field_keywords') or [])

def _flatten_values(obj: Any, out: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    if out is None:
        out = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, (dict, list)):
                _flatten_values(v, out)
            else:
                out[str(k)] = v
    elif isinstance(obj, list):
        for item in obj[:5]:
            _flatten_values(item, out)
    return out


def sensitive_fields_in_body(body: Any, *, ontology: Optional[Dict[str, Any]] = None) -> List[str]:
    return sensitive_fields_in_body_normalized(body, ontology=ontology)


def analyze_sensitive_response(
    *,
    path: str,
    body: Any,
    status_code: Optional[int] = None,
    credential_subject: Optional[Dict[str, Any]] = None,
    mutation_applied: bool = False,
) -> Dict[str, Any]:
    """Classify sensitive read outcomes for coverage + drift signals."""
    ont = load_sensitive_field_ontology()
    normalized_reads = detect_normalized_sensitive_fields(body, ontology=ont, path=path)
    fields = sensitive_fields_in_body(body, ontology=ont)
    keyword_hits = _keyword_hits(body, _path_plane_keywords(path))
    if keyword_hits:
        fields = sorted(set(fields + keyword_hits))
    has_sensitive = bool(normalized_reads or fields)
    success = status_code is None or (200 <= int(status_code) < 300)

    verdict = 'unknown_response'
    if not success:
        verdict = 'auth_required' if status_code in {401, 403} else 'business_blocked'
    elif has_sensitive:
        verdict = 'read_success_sensitive'
    elif success:
        verdict = 'read_success_no_sensitive'

    subject_drift = False
    subject_notes: List[str] = []
    if credential_subject and has_sensitive and isinstance(body, (dict, list)):
        flat = _flatten_values(body if isinstance(body, dict) else {})
        for sk, sv in credential_subject.items():
            if sk not in flat:
                continue
            if str(flat.get(sk)) != str(sv):
                subject_drift = True
                subject_notes.append(f'{sk}_mismatch')

    if mutation_applied and has_sensitive and success:
        verdict = 'accepted_sensitive'

    return {
        'verdict': verdict,
        'sensitive_fields': fields,
        'sensitive_field_reads': normalized_reads,
        'has_sensitive': has_sensitive,
        'subject_drift': subject_drift,
        'subject_notes': subject_notes,
        'mutation_applied': mutation_applied,
    }


def merge_sensitive_oracle_into_analysis(
    analysis: Dict[str, Any],
    *,
    path: str,
    response_body: Any,
    status_code: Optional[int] = None,
    credential_subject: Optional[Dict[str, Any]] = None,
    mutation_applied: bool = False,
) -> Dict[str, Any]:
    """Attach sensitive_api block to existing execution analysis."""
    sens = analyze_sensitive_response(
        path=path,
        body=response_body,
        status_code=status_code,
        credential_subject=credential_subject,
        mutation_applied=mutation_applied,
    )
    out = dict(analysis)
    out['sensitive_api'] = sens
    if sens.get('verdict') == 'accepted_sensitive' and not out.get('binding_status'):
        out['binding_status'] = 'likely_binding_drift'
    return out
