# -*- coding: utf-8 -*-
"""Pluggable sign engines — profile-driven, not app-specific."""
from __future__ import annotations

import base64
import hashlib
import hmac
import struct
from typing import Any, Callable, Dict, Optional


def _to_int32(value: int) -> int:
    """Emulate JavaScript 32-bit signed integer (| 0 / >>> 0 semantics for OR chain)."""
    value &= 0xFFFFFFFF
    if value >= 0x80000000:
        value -= 0x100000000
    return value


def _int_chunk_js_compat(digest_str: str, offset: int) -> int:
    """spark-md5 raw digest string → one 32-bit chunk (matches webpack bundle m())."""
    n = _to_int32((ord(digest_str[offset]) & 255) << 24)
    r = _to_int32((ord(digest_str[offset + 1]) & 255) << 16)
    i = _to_int32((ord(digest_str[offset + 2]) & 255) << 8)
    o = ord(digest_str[offset + 3]) & 255
    return abs(_to_int32(_to_int32(n | r | i | o)))


def md5_raw_four_int_concat(sign_input: str) -> str:
    """spark-md5 raw digest → four JS 32-bit chunks (Taro/bundle form transport)."""
    raw = hashlib.md5(sign_input.encode('utf-8')).digest().decode('latin-1')
    return ''.join(str(_int_chunk_js_compat(raw, off)) for off in (0, 4, 8, 12))


def md5_hex_four_int_concat(sign_input: str) -> str:
    """MD5 hex string → four charCode chunks (legacy / mis-detection fallback)."""
    digest = hashlib.md5(sign_input.encode('utf-8')).hexdigest()
    return ''.join(str(_int_chunk_js_compat(digest, off)) for off in (0, 4, 8, 12))


def hmac_sha256_base64url(sign_input: str, *, secret: str = '') -> str:
    """CryptoJS HmacSHA256 → Base64 URL-safe without padding (uni-app Sign header)."""
    if not secret:
        raise ValueError('hmac_sha256_base64url requires secret')
    digest = hmac.new(secret.encode('utf-8'), sign_input.encode('utf-8'), hashlib.sha256).digest()
    b64 = base64.b64encode(digest).decode('ascii')
    return b64.replace('+', '-').replace('/', '_').replace('=', '')


def _hmac_sha256_base64url_bound(sign_input: str) -> str:
    raise ValueError('hmac_sha256_base64url requires bound secret via compute_sign(..., secret=)')


SIGN_ENGINES: Dict[str, Callable[[str], str]] = {
    'md5_raw_four_int_concat': md5_raw_four_int_concat,
    'md5_hex_four_int_concat': md5_hex_four_int_concat,
    'hmac_sha256_base64url': _hmac_sha256_base64url_bound,
}


def compute_sign(sign_input: str, method: Optional[str] = None, *, secret: str = '') -> str:
    meth = method or 'md5_raw_four_int_concat'
    if meth == 'hmac_sha256_base64url':
        return hmac_sha256_base64url(sign_input, secret=secret)
    fn = SIGN_ENGINES.get(meth)
    if not fn:
        raise ValueError(f'unknown sign method: {method}')
    return fn(sign_input)


def load_sign_method_from_profile(profile_doc: Optional[Dict[str, Any]]) -> str:
    if not profile_doc:
        return 'md5_raw_four_int_concat'
    sign = profile_doc.get('sign') or {}
    return sign.get('method') or 'md5_raw_four_int_concat'
