# -*- coding: utf-8 -*-
"""Resolve HMAC sign secrets from intake captures when static literals are placeholders."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from minidrifter.materials.intake_param_hints import load_intake_report
from minidrifter.runtime.crypto.sign_engines import compute_sign
from minidrifter.runtime.crypto.sign_payload_builders import build_relative_path_merge_params


def _header_value(cap: Dict[str, Any], name: str) -> Optional[str]:
    for layer in cap.get('field_layers') or []:
        if str(layer.get('name') or '').lower() == name.lower():
            val = layer.get('value')
            return str(val) if val is not None else None
    headers = cap.get('request_headers') or cap.get('headers') or {}
    if isinstance(headers, dict):
        for k, v in headers.items():
            if str(k).lower() == name.lower():
                return str(v)
    return None


def _is_placeholder(secret: str, patterns: List[str]) -> bool:
    low = secret.lower()
    if not secret or len(secret) < 4:
        return True
    for pat in patterns:
        if re.search(pat, low, re.I):
            return True
    return False


def _candidate_secrets_from_source(
    source_dir: Optional[Path],
    *,
    patterns: List[str],
) -> List[str]:
    if not source_dir or not source_dir.is_dir():
        return []
    found: List[str] = []
    seen: Set[str] = set()
    for path in source_dir.rglob('*.js'):
        if path.stat().st_size > 2_000_000:
            continue
        try:
            text = path.read_text(encoding='utf-8', errors='replace')
        except OSError:
            continue
        for pat in patterns:
            for m in re.finditer(pat, text, re.I):
                val = m.group(1) if m.lastindex else m.group(0)
                if val and val not in seen and len(val) >= 4:
                    seen.add(val)
                    found.append(val)
    return found


def try_resolve_hmac_secret_from_captures(
    pack_dir: Path,
    *,
    profile_doc: Dict[str, Any],
    candidate_secret: str = '',
    source_dir: Optional[Path] = None,
    max_captures: int = 40,
) -> Optional[str]:
    """Brute-verify sign secret against intake captures that carry Sign header."""
    pack_dir = Path(pack_dir)
    intake = load_intake_report(pack_dir) or {}
    captures = intake.get('captures') or []
    if not captures:
        return None

    spec = profile_doc.get('key_extraction') or {}
    placeholders = list(spec.get('placeholder_patterns') or [])
    sign_method = (profile_doc.get('sign') or {}).get('method') or 'hmac_sha256_base64url'
    payload_builder = (profile_doc.get('sign') or {}).get('payload_builder') or 'relative_path_merge_params'

    candidates: List[str] = []
    if candidate_secret and not _is_placeholder(candidate_secret, placeholders):
        candidates.append(candidate_secret)

    literal_patterns = []
    for rule in spec.get('literals') or []:
        literal_patterns.extend(rule.get('patterns') or [])
    candidates.extend(_candidate_secrets_from_source(source_dir, patterns=literal_patterns))

    seen: Set[str] = set()
    uniq_candidates = []
    for c in candidates:
        if c in seen or _is_placeholder(c, placeholders):
            continue
        seen.add(c)
        uniq_candidates.append(c)
    if not uniq_candidates:
        return None

    samples: List[Dict[str, Any]] = []
    for cap in captures:
        sign_val = _header_value(cap, 'Sign') or _header_value(cap, 'sign')
        if not sign_val:
            continue
        path = cap.get('path') or ''
        if not path:
            continue
        rel = path.lstrip('/')
        query = cap.get('query') or {}
        body = cap.get('body_form') or cap.get('body') or {}
        if not isinstance(query, dict):
            query = {}
        if not isinstance(body, dict):
            body = {}
        if payload_builder == 'relative_path_merge_params':
            payload = build_relative_path_merge_params(rel, query=query, body=body)
        else:
            payload = rel
        samples.append({'payload': payload, 'sign': sign_val, 'path': path})
        if len(samples) >= max_captures:
            break
    if not samples:
        return None

    for secret in uniq_candidates:
        hits = 0
        for sample in samples:
            try:
                expected = compute_sign(sample['payload'], sign_method)
            except (ValueError, TypeError):
                break
            if expected == sample['sign']:
                hits += 1
        if hits >= max(1, len(samples) // 2):
            return secret
    return None
