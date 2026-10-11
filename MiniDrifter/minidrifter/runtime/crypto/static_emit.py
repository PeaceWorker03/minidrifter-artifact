# -*- coding: utf-8 -*-
"""Emit crypto_static_profile.json from static pack + decompiled source."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from minidrifter.core.utils import write_json
from minidrifter.runtime.crypto.profile_key_extract import (
    extract_crypto_material,
    read_wrapper_js,
    collect_profile_source_texts,
)
from minidrifter.runtime.crypto.registry import (
    REGISTERED_PROFILES,
    _find_best_wrapper,
    _load_json,
    _match_profile,
    _score_wrapper_for_profile,
    normalize_profile_id,
)
from minidrifter.runtime.crypto.profile_key_extract import load_crypto_profile_doc

SM4_DUAL_PROFILE_ID = 'sm4_dual_form_wrapper'


def _merge_sm4_ancillary_material(
    material,
    *,
    source_dir: Optional[Path],
    pack_dir: Path,
    wrapper_file: str,
    snippet: str,
):
    """When baselifeConfig SM4 transport coexists with cipherH5, merge keys into extras."""
    if not material or not source_dir:
        return material
    if material.extras.get('sm4_type2_key_hex'):
        return material
    for label, text in collect_profile_source_texts(
        SM4_DUAL_PROFILE_ID,
        wrapper_file=wrapper_file,
        source_dir=source_dir,
        snippet=snippet,
    ):
        sm4_mat = extract_crypto_material(
            SM4_DUAL_PROFILE_ID,
            text,
            source_label=label,
            source_dir=source_dir,
            pack_dir=pack_dir,
            wrapper_file=wrapper_file,
        )
        if sm4_mat and sm4_mat.replay_ready:
            material.extras.update(sm4_mat.extras)
            material.extras['sm4_profile_id'] = SM4_DUAL_PROFILE_ID
            material.extras.setdefault('sm4_source_label', sm4_mat.source_label or label)
            break
    return material


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def emit_crypto_static_profile(
    pack_dir: Path,
    *,
    source_dir: Optional[Path] = None,
    profile_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Resolve wrapper + extract keys from JS → crypto_static_profile.json."""
    pack_dir = Path(pack_dir)
    wrappers = _load_json(pack_dir / 'request_wrappers.json') or []
    if not isinstance(wrappers, list):
        wrappers = []

    primary = _find_best_wrapper(wrappers)
    spec, detect_score = _match_profile(primary, source_dir=source_dir) if primary else (None, 0.0)
    if not spec:
        try:
            from minidrifter.adapters.pack_resolver import resolve_pack_profile
            pack_prof = resolve_pack_profile(pack_dir)
            hint = pack_prof.get('crypto_profile_hint')
            if hint and hint in REGISTERED_PROFILES:
                spec = REGISTERED_PROFILES[hint]
                detect_score = _score_wrapper_for_profile(primary or {}, spec) if primary else 0.0
        except Exception:
            pass
    if profile_id:
        spec = REGISTERED_PROFILES.get(profile_id)
        if spec:
            detect_score = _score_wrapper_for_profile(primary or {}, spec) if primary else 0.0

    pid = profile_id or (spec.profile_id if spec else None)
    material = None
    key_source = None
    texts = []
    if primary and pid:
        snippet = ((primary.get('evidence') or {}).get('snippet')) or ''
        wrapper_file = primary.get('file') or ''
        if normalize_profile_id(pid) == 'hmac_sha256_header_sign' and source_dir:
            seen_labels = set()
            texts = collect_profile_source_texts(
                pid, wrapper_file=wrapper_file, source_dir=source_dir, snippet=snippet,
            )
            seen_labels = {t[0] for t in texts}
            root = Path(source_dir)
            for js in root.rglob('*.js'):
                if js.stat().st_size > 1_500_000:
                    continue
                try:
                    body = js.read_text(encoding='utf-8', errors='replace')
                except OSError:
                    continue
                if 'HmacSHA256' not in body and 'buildRequestSignature' not in body:
                    continue
                label = str(js.relative_to(root)).replace('\\', '/')
                if label not in seen_labels:
                    texts.append((label, body))
        else:
            texts = collect_profile_source_texts(
                pid, wrapper_file=wrapper_file, source_dir=source_dir, snippet=snippet,
            )
        for label, text in texts:
            material = extract_crypto_material(
                pid,
                text,
                source_label=label,
                source_dir=source_dir,
                pack_dir=pack_dir,
                wrapper_file=wrapper_file,
            )
            if material and material.replay_ready:
                key_source = material.source_label or label
                break
            if material and not key_source:
                key_source = material.source_label or label

    if material and source_dir:
        material = _merge_sm4_ancillary_material(
            material,
            source_dir=source_dir,
            pack_dir=pack_dir,
            wrapper_file=(primary or {}).get('file') or '',
            snippet=((primary or {}).get('evidence') or {}).get('snippet') or '',
        )

    doc: Dict[str, Any] = {
        'schema_version': '1.0.0',
        'generated_at': _utc_now(),
        'pack_dir': str(pack_dir),
        'profile_id': pid,
        'detection_score': round(detect_score, 2),
        'primary_wrapper': (primary or {}).get('file'),
        'key_source': key_source,
        'source_dir': str(source_dir) if source_dir else None,
        'can_replay': bool(material and material.replay_ready),
        'can_decrypt': bool(material and material.replay_ready),
        'material': {
            'aes_key': material.aes_key if material else '',
            'aes_iv': material.aes_iv if material else '',
            'md5_aeskey': material.md5_aeskey if material else '',
            'cid': material.cid if material else '',
            'sign_key': material.sign_key if material else '',
            'sign_method': material.sign_method if material else '',
            'api_host': material.api_host if material else '',
            'transport_style': material.transport_style if material else '',
            'extraction_method': material.extraction_method if material else '',
            'extras': material.extras if material else {},
        } if material else {},
        'reason': (
            'crypto_static_profile_ready' if material and material.replay_ready
            else 'keys_partial' if material
            else 'profile_or_wrapper_not_matched' if not primary
            else 'keys_not_resolved_from_source'
        ),
    }

    if material and not material.replay_ready and pid:
        try:
            from minidrifter.runtime.crypto.hmac_sha256_header_sign import PROFILE_ID as HMAC_PID
            from minidrifter.runtime.crypto.sign_secret_parity import try_resolve_hmac_secret_from_captures

            if normalize_profile_id(pid) == HMAC_PID or material.transport_style == 'header_hmac_sign':
                prof_doc = load_crypto_profile_doc(pid or '')
                resolved = try_resolve_hmac_secret_from_captures(
                    pack_dir,
                    profile_doc=prof_doc,
                    candidate_secret=material.sign_key,
                    source_dir=source_dir,
                )
                if resolved:
                    material.sign_key = resolved
                    doc['material']['sign_key'] = resolved
                    doc['can_replay'] = True
                    doc['can_decrypt'] = True
                    doc['reason'] = 'sign_secret_resolved_from_capture_parity'
        except Exception:
            pass

    if material and material.replay_ready:
        doc['can_replay'] = True
        doc['can_decrypt'] = True
        if doc['reason'] == 'keys_not_resolved_from_source':
            doc['reason'] = 'crypto_static_profile_ready'

    out_path = pack_dir / 'crypto_static_profile.json'
    write_json(out_path, doc)
    doc['artifact'] = str(out_path)
    return doc
