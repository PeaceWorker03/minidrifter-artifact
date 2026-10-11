# -*- coding: utf-8 -*-
"""Shared crypto utilities for wrapper transport profiles."""
from __future__ import annotations

import re
from typing import Dict
from urllib.parse import unquote

try:
    from Crypto.Util.Padding import unpad as _pkcs7_unpad_bytes
except ImportError:  # pragma: no cover
    _pkcs7_unpad_bytes = None

PKCS7_TRAIL_RE = re.compile(r'[\x00-\x1f]+$')


def strip_padding(text: str) -> str:
    return PKCS7_TRAIL_RE.sub('', text)


def pkcs7_unpad(data: bytes, *, block_size: int = 16) -> bytes:
    if _pkcs7_unpad_bytes is not None:
        try:
            return _pkcs7_unpad_bytes(data, block_size)
        except ValueError:
            pass
    # Fallback: strip trailing control chars (legacy captures)
    return PKCS7_TRAIL_RE.sub('', data.decode('utf-8', errors='replace')).encode('utf-8')


def pkcs7_pad(data: bytes, *, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return data + bytes([pad_len] * pad_len)


def parse_kv_string(text: str) -> Dict[str, str]:
    text = strip_padding(text.strip())
    out: Dict[str, str] = {}
    if not text:
        return out
    for part in text.split('&'):
        if '=' not in part:
            continue
        k, v = part.split('=', 1)
        if k:
            out[k] = v
    return out


def prep_cipher_blob(value: str) -> bytes:
    import base64
    s = unquote(value.strip())
    s = s.replace('*', '=').replace('$', '+')
    return base64.b64decode(s)


def urlsafe_cipher_out(raw_b64: str) -> str:
    from urllib.parse import quote
    s = raw_b64.replace('=', '*').replace('+', '$')
    return quote(s, safe='')
