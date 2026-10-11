# -*- coding: utf-8 -*-
"""Pluggable crypto profile registry — detect wrapper transport from static pack outputs."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from minidrifter.runtime.crypto.des_ecb_params_form_wrapper import (
    DesEcbParamsFormEngine,
    PROFILE_ID as DES_ECB_PARAMS_PROFILE_ID,
)
from minidrifter.runtime.crypto.aes_cbc_cipherh5_form_wrapper import (
    AesCbcCipherH5FormEngine,
    PROFILE_ID as AES_CBC_CIPHERH5_PROFILE_ID,
)
from minidrifter.runtime.crypto.sm4_dual_form_wrapper import (
    Sm4DualFormEngine,
    PROFILE_ID as SM4_DUAL_PROFILE_ID,
)
from minidrifter.runtime.crypto.aes_cfb_md5_wrapper import (
    PROFILE_ID as AES_CFB_MD5_PROFILE_ID,
    AesCfbMd5WrapperEngine,
    WrapperCryptoKeys,
)
from minidrifter.runtime.crypto.profile_key_extract import (
    CryptoMaterial,
    collect_profile_source_texts,
    extract_crypto_material,
    load_crypto_profile_doc,
    read_wrapper_js,
)
from minidrifter.runtime.crypto.sign_engines import load_sign_method_from_profile
from minidrifter.runtime.crypto.hmac_sha256_header_sign import (
    HmacSha256HeaderSignEngine,
    PROFILE_ID as HMAC_HEADER_SIGN_PROFILE_ID,
)
from minidrifter.runtime.crypto.token_sign_aes_wrapper import (
    PROFILE_ID as TOKEN_SIGN_AES_PROFILE_ID,
    TokenSignAesWrapperEngine,
)

PROFILE_ALIASES = {
    'ehai_aes_cfb_wrapper': AES_CFB_MD5_PROFILE_ID,
    'shenzhou_token_sign_wrapper': TOKEN_SIGN_AES_PROFILE_ID,
    'hengdian_hmac_sign': HMAC_HEADER_SIGN_PROFILE_ID,
}

CRYPTO_WRAPPER_HINTS = {'encrypt', 'decrypt', 'md5', 'aes', 'des', 'sign', 'hmac'}
WRAPPER_FILE_PATTERNS = [
    re.compile(r'(?:^|/)utils/http\.js$', re.I),
    re.compile(r'(?:^|/)common\.js$', re.I),
    re.compile(r'apiGetWayHttp\.js$', re.I),
    re.compile(r'(?:^|/)services/.+http\.js$', re.I),
    re.compile(r'request\.js$', re.I),
]

EngineType = Union[
    AesCfbMd5WrapperEngine,
    TokenSignAesWrapperEngine,
    HmacSha256HeaderSignEngine,
    AesCbcCipherH5FormEngine,
    Sm4DualFormEngine,
    DesEcbParamsFormEngine,
]


@dataclass
class CryptoProfileSpec:
    profile_id: str
    description: str
    required_header_hints: List[str] = field(default_factory=list)
    required_crypto_hints: List[str] = field(default_factory=list)
    transport_style: str = ''


REGISTERED_PROFILES: Dict[str, CryptoProfileSpec] = {
    AES_CFB_MD5_PROFILE_ID: CryptoProfileSpec(
        profile_id=AES_CFB_MD5_PROFILE_ID,
        description='AES-CFB encrypted query/body + MD5 Authorization + encrypted AppIdentity',
        required_header_hints=['AppIdentity', 'Authorization'],
        required_crypto_hints=['aes', 'md5', 'encrypt'],
        transport_style='header_query_encrypted',
    ),
    TOKEN_SIGN_AES_PROFILE_ID: CryptoProfileSpec(
        profile_id=TOKEN_SIGN_AES_PROFILE_ID,
        description='Form-body AES-ECB + custom sign (bundle-inline)',
        required_header_hints=['sign'],
        required_crypto_hints=['aes', 'sign', 'encrypt'],
        transport_style='form_cid_q_sign',
    ),
    HMAC_HEADER_SIGN_PROFILE_ID: CryptoProfileSpec(
        profile_id=HMAC_HEADER_SIGN_PROFILE_ID,
        description='Bearer + HMAC-SHA256 Sign header (relative path payload)',
        required_header_hints=['Sign', 'Authorization'],
        required_crypto_hints=['hmac', 'sign'],
        transport_style='header_hmac_sign',
    ),
    AES_CBC_CIPHERH5_PROFILE_ID: CryptoProfileSpec(
        profile_id=AES_CBC_CIPHERH5_PROFILE_ID,
        description='AES-CBC cipherH5 form body + baseInfo per-appId keys',
        required_header_hints=[],
        required_crypto_hints=['aes', 'md5', 'cipher', 'encrypt'],
        transport_style='form_cipherh5_encrypted',
    ),
    DES_ECB_PARAMS_PROFILE_ID: CryptoProfileSpec(
        profile_id=DES_ECB_PARAMS_PROFILE_ID,
        description='DES-ECB encrypted form params (CryptoJS Utf8 key)',
        required_header_hints=[],
        required_crypto_hints=['des', 'encrypt'],
        transport_style='form_des_params_encrypted',
    ),
    SM4_DUAL_PROFILE_ID: CryptoProfileSpec(
        profile_id=SM4_DUAL_PROFILE_ID,
        description='SM4 cipherOne/cipherTwo dual form via baselifeConfig',
        required_header_hints=[],
        required_crypto_hints=['sm4', 'cipher', 'encrypt'],
        transport_style='form_sm4_cipherone_ciphertwo',
    ),
}


@dataclass
class CryptoCapability:
    chain_available: bool
    profile_id: Optional[str]
    primary_wrapper: Optional[str]
    can_decrypt: bool
    can_replay: bool
    algorithm_hints: List[str] = field(default_factory=list)
    encryptor_count: int = 0
    wrapper_ids: List[str] = field(default_factory=list)
    key_source: Optional[str] = None
    md5_aeskey: Optional[str] = None
    transport_style: Optional[str] = None
    reason: str = ''
    detection_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            'chain_available': self.chain_available,
            'profile_id': self.profile_id,
            'primary_wrapper': self.primary_wrapper,
            'can_decrypt': self.can_decrypt,
            'can_replay': self.can_replay,
            'algorithm_hints': self.algorithm_hints,
            'encryptor_count': self.encryptor_count,
            'wrapper_ids': self.wrapper_ids,
            'key_source': self.key_source,
            'md5_aeskey': self.md5_aeskey,
            'transport_style': self.transport_style,
            'reason': self.reason,
            'detection_score': self.detection_score,
        }


def normalize_profile_id(profile_id: Optional[str]) -> Optional[str]:
    if not profile_id:
        return None
    return PROFILE_ALIASES.get(profile_id, profile_id)


def _load_json(path: Path) -> Any:
    if path.exists():
        return json.loads(path.read_text(encoding='utf-8'))
    return None


def _score_wrapper_for_profile(wrapper: Dict[str, Any], spec: CryptoProfileSpec) -> float:
    hints = {h.lower() for h in (wrapper.get('crypto_hints') or [])}
    headers = {h.lower() for h in (wrapper.get('header_hints') or [])}
    score = 0.0
    if not hints & CRYPTO_WRAPPER_HINTS:
        return 0.0
    for req in spec.required_crypto_hints:
        if req.lower() in hints:
            score += 8.0
    for req in spec.required_header_hints:
        if req.lower() in headers or req in (wrapper.get('header_hints') or []):
            score += 6.0
    if spec.profile_id == TOKEN_SIGN_AES_PROFILE_ID:
        snippet = ((wrapper.get('evidence') or {}).get('snippet')) or ''
        wf = wrapper.get('file') or ''
        if 'appletEncrypt' in snippet or 'appletencrypt' in snippet.lower():
            score += 8.0
        if 'common.js' in wf.replace('\\', '/').lower():
            score += 6.0
    if spec.profile_id == HMAC_HEADER_SIGN_PROFILE_ID:
        snippet = ((wrapper.get('evidence') or {}).get('snippet')) or ''
        if 'HmacSHA256' in snippet or 'hmacsha256' in snippet.lower():
            score += 14.0
        if 'buildRequestSignature' in snippet:
            score += 10.0
        if '.Sign' in snippet or 'h.Sign' in snippet or 'Sign=' in snippet:
            score += 8.0
        if 'appletEncrypt' in snippet:
            score -= 6.0
    if spec.profile_id == AES_CBC_CIPHERH5_PROFILE_ID:
        snippet = ((wrapper.get('evidence') or {}).get('snippet')) or ''
        if 'cipherH5' in snippet:
            score += 24.0
        if 'getBaseInfoModel' in snippet:
            score += 10.0
        if 'macValue' in snippet:
            score += 8.0
        if 'AppIdentity' in (wrapper.get('header_hints') or []):
            score -= 10.0
        if 'DES.encrypt' in snippet and 'cipherH5' not in snippet:
            score -= 20.0
    if spec.profile_id == DES_ECB_PARAMS_PROFILE_ID:
        snippet = ((wrapper.get('evidence') or {}).get('snippet')) or ''
        wf = (wrapper.get('file') or '').replace('\\', '/').lower()
        if 'des' not in hints and 'DES.encrypt' not in snippet and 'DES.decrypt' not in snippet:
            return 0.0
        if 'DES.encrypt' in snippet or 'DES.decrypt' in snippet:
            score += 28.0
        if 'des' in hints:
            score += 10.0
        if 'cipherH5' in snippet:
            score -= 24.0
        if 'common.js' in wf or 'vendors.js' in wf:
            score += 8.0
    if wrapper.get('calls_platform_request'):
        score += 12.0
    wf = wrapper.get('file') or ''
    if any(p.search(wf) for p in WRAPPER_FILE_PATTERNS):
        score += 10.0
    score += min(6.0, len(hints & {'encrypt', 'decrypt', 'md5', 'aes'}) * 2.0)
    return score


def _find_best_wrapper(wrappers: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not wrappers:
        return None
    scored = []
    for w in wrappers:
        best = max((_score_wrapper_for_profile(w, spec), spec.profile_id) for spec in REGISTERED_PROFILES.values())
        if best[0] > 0:
            scored.append((best[0], w, best[1]))
    if not scored:
        return None
    scored.sort(key=lambda x: x[0], reverse=True)
    return scored[0][1]


def _score_wrapper_with_source_text(
    wrapper: Dict[str, Any],
    spec: CryptoProfileSpec,
    text: str,
) -> float:
    score = _score_wrapper_for_profile(wrapper, spec)
    if not text:
        return score
    if spec.profile_id == AES_CBC_CIPHERH5_PROFILE_ID:
        if 'cipherH5' in text:
            score += 28.0
        if 'getBaseInfoModel' in text:
            score += 12.0
        if 'macValue' in text:
            score += 10.0
        if 'DES.encrypt' in text and 'cipherH5' not in text:
            score -= 30.0
    if spec.profile_id == DES_ECB_PARAMS_PROFILE_ID:
        if 'DES.encrypt' in text or 'DES.decrypt' in text:
            score += 32.0
        if re.search(r'ai\s*:\s*function\s*\(\s*\)\s*\{\s*return\s+\w+', text):
            score += 12.0
        if 'cipherH5' in text:
            score -= 30.0
    return score


def _match_profile(
    wrapper: Dict[str, Any],
    *,
    source_dir: Optional[Path] = None,
) -> Tuple[Optional[CryptoProfileSpec], float]:
    best_spec = None
    best_score = 0.0
    wrapper_text = ''
    if source_dir and wrapper.get('file'):
        wf = Path(source_dir) / str(wrapper.get('file')).replace('\\', '/')
        if wf.exists():
            try:
                wrapper_text = wf.read_text(encoding='utf-8', errors='replace')
            except OSError:
                wrapper_text = ''
    for spec in REGISTERED_PROFILES.values():
        s = (
            _score_wrapper_with_source_text(wrapper, spec, wrapper_text)
            if wrapper_text else _score_wrapper_for_profile(wrapper, spec)
        )
        if s > best_score:
            best_score = s
            best_spec = spec
    if best_spec and best_score >= 12.0:
        return best_spec, best_score
    return None, 0.0


def _resolve_material(
    wrapper: Dict[str, Any],
    profile_id: str,
    *,
    source_dir: Optional[Path] = None,
    pack_dir: Optional[Path] = None,
) -> Tuple[Optional[CryptoMaterial], Optional[str]]:
    snippet = ((wrapper.get('evidence') or {}).get('snippet')) or ''
    wrapper_file = wrapper.get('file') or ''
    best: Optional[CryptoMaterial] = None
    best_label: Optional[str] = None
    for label, text in collect_profile_source_texts(
        profile_id,
        wrapper_file=wrapper_file,
        source_dir=source_dir,
        snippet=snippet,
    ):
        mat = extract_crypto_material(
            profile_id,
            text,
            source_label=label,
            source_dir=source_dir,
            pack_dir=pack_dir,
            wrapper_file=wrapper_file,
        )
        if not mat:
            continue
        if mat.replay_ready:
            return mat, mat.source_label or label
        if best is None:
            best, best_label = mat, mat.source_label or label
    return best, best_label


def _material_to_wrapper_keys(material: CryptoMaterial) -> Optional[WrapperCryptoKeys]:
    if material.transport_style == 'header_query_encrypted' and material.aes_key and material.aes_iv:
        return WrapperCryptoKeys(
            aes_key=material.aes_key.encode('utf-8'),
            aes_iv=material.aes_iv.encode('utf-8'),
            md5_aeskey=material.md5_aeskey,
        )
    return None


def build_engine(material: CryptoMaterial) -> Optional[EngineType]:
    pid = normalize_profile_id(material.profile_id)
    if pid == TOKEN_SIGN_AES_PROFILE_ID and material.replay_ready:
        return TokenSignAesWrapperEngine(material)
    if pid == HMAC_HEADER_SIGN_PROFILE_ID and material.replay_ready:
        return HmacSha256HeaderSignEngine(material)
    if pid == AES_CBC_CIPHERH5_PROFILE_ID and material.replay_ready:
        return AesCbcCipherH5FormEngine(material)
    if pid == DES_ECB_PARAMS_PROFILE_ID and material.replay_ready:
        return DesEcbParamsFormEngine(material)
    if pid == SM4_DUAL_PROFILE_ID and material.replay_ready:
        return Sm4DualFormEngine(material)
    keys = _material_to_wrapper_keys(material)
    if pid == AES_CFB_MD5_PROFILE_ID and keys:
        return AesCfbMd5WrapperEngine(keys)
    return None


def load_crypto_capability(
    output_dir: Path,
    *,
    source_dir: Optional[Path] = None,
) -> CryptoCapability:
    output_dir = Path(output_dir)
    wrappers = _load_json(output_dir / 'request_wrappers.json') or []
    chains = _load_json(output_dir / 'crypto_core_chains.json') or {}
    enc = chains.get('core_request_encryptors') or []
    decryptors = chains.get('core_response_decryptors') or []

    static_prof = _load_json(output_dir / 'crypto_static_profile.json') or {}

    primary = _find_best_wrapper(wrappers if isinstance(wrappers, list) else [])
    spec, detect_score = _match_profile(primary, source_dir=source_dir) if primary else (None, 0.0)

    algo_hints = sorted({h for c in enc for h in (c.get('algorithm_hints') or []) if h})
    chain_available = bool(enc) and bool(primary)

    # Prefer emitted static profile when replay-ready (avoids wrong live matcher overrides)
    profile_id = None
    if static_prof.get('can_replay') and static_prof.get('profile_id'):
        profile_id = normalize_profile_id(static_prof.get('profile_id'))
    if not profile_id:
        profile_id = spec.profile_id if spec else static_prof.get('profile_id')
    can_decrypt = False
    can_replay = False
    key_source = static_prof.get('key_source')
    md5_aeskey = None
    transport_style = None
    if static_prof.get('material'):
        transport_style = (static_prof.get('material') or {}).get('transport_style')
    if not transport_style:
        transport_style = (spec.transport_style if spec else None) or static_prof.get('transport_style')

    material: Optional[CryptoMaterial] = None
    if static_prof.get('can_replay') and static_prof.get('material'):
        m = static_prof['material']
        material = CryptoMaterial(
            profile_id=profile_id or '',
            aes_key=m.get('aes_key') or '',
            aes_iv=m.get('aes_iv') or '',
            md5_aeskey=m.get('md5_aeskey') or '',
            cid=m.get('cid') or '',
            sign_key=m.get('sign_key') or '',
            sign_method=m.get('sign_method') or '',
            api_host=m.get('api_host') or '',
            transport_style=m.get('transport_style') or '',
            extraction_method=m.get('extraction_method') or 'crypto_static_profile',
            source_label=key_source or 'crypto_static_profile.json',
            extras=m.get('extras') or {},
        )
    elif spec and primary:
        material, key_source = _resolve_material(
            primary, spec.profile_id, source_dir=source_dir, pack_dir=output_dir,
        )

    if material:
        md5_aeskey = material.md5_aeskey or None
        can_replay = material.replay_ready
        can_decrypt = material.replay_ready
        transport_style = material.transport_style or transport_style

    if chain_available and can_replay:
        reason = 'crypto_chain_and_replay_profile_ready'
    elif chain_available and material:
        reason = 'crypto_chain_indexed_but_keys_not_resolved'
    elif spec:
        reason = 'profile_matched_keys_pending_source_dir'
    else:
        reason = 'no_actionable_crypto_chain'

    return CryptoCapability(
        chain_available=chain_available,
        profile_id=profile_id,
        primary_wrapper=(primary or {}).get('file') or static_prof.get('primary_wrapper'),
        can_decrypt=can_decrypt,
        can_replay=can_replay,
        algorithm_hints=algo_hints,
        encryptor_count=len(enc) + len(decryptors),
        wrapper_ids=[w.get('wrapper_id') for w in (wrappers if isinstance(wrappers, list) else [])[:5] if w.get('wrapper_id')],
        key_source=key_source,
        md5_aeskey=md5_aeskey,
        transport_style=transport_style,
        reason=reason,
        detection_score=round(detect_score or static_prof.get('detection_score') or 0.0, 2),
    )


def get_crypto_engine_for_pack(
    output_dir: Path,
    *,
    source_dir: Optional[Path] = None,
) -> Tuple[Optional[EngineType], CryptoCapability]:
    cap = load_crypto_capability(output_dir, source_dir=source_dir)
    if not cap.can_replay or not cap.profile_id:
        return None, cap

    static_prof = _load_json(Path(output_dir) / 'crypto_static_profile.json') or {}
    material: Optional[CryptoMaterial] = None
    if static_prof.get('material'):
        m = static_prof['material']
        material = CryptoMaterial(
            profile_id=cap.profile_id or '',
            aes_key=m.get('aes_key') or '',
            aes_iv=m.get('aes_iv') or '',
            md5_aeskey=m.get('md5_aeskey') or '',
            cid=m.get('cid') or '',
            sign_key=m.get('sign_key') or '',
            sign_method=m.get('sign_method') or '',
            api_host=m.get('api_host') or '',
            transport_style=m.get('transport_style') or cap.transport_style or '',
            source_label=static_prof.get('key_source') or '',
            extras=m.get('extras') or {},
        )
    else:
        primary = {'file': cap.primary_wrapper, 'evidence': {}}
        material, _ = _resolve_material(primary, cap.profile_id, source_dir=source_dir)

    if not material or not material.replay_ready:
        return None, cap
    if not material.sign_method:
        material.sign_method = load_sign_method_from_profile(
            load_crypto_profile_doc(normalize_profile_id(material.profile_id)),
        )
    engine = build_engine(material)
    if not engine:
        return None, cap
    return engine, cap


def resolve_crypto_material(
    output_dir: Path,
    *,
    source_dir: Optional[Path] = None,
) -> Optional[CryptoMaterial]:
    engine, cap = get_crypto_engine_for_pack(output_dir, source_dir=source_dir)
    if not engine:
        return None
    if isinstance(engine, TokenSignAesWrapperEngine):
        return engine.material
    if isinstance(engine, AesCfbMd5WrapperEngine):
        k = engine.keys
        return CryptoMaterial(
            profile_id=AES_CFB_MD5_PROFILE_ID,
            aes_key=k.aes_key.decode('utf-8', errors='replace'),
            aes_iv=k.aes_iv.decode('utf-8', errors='replace'),
            md5_aeskey=k.md5_aeskey,
            transport_style='header_query_encrypted',
        )
    return None
