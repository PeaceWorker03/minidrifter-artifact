# -*- coding: utf-8 -*-
"""DES-ECB form `params` wrapper (CryptoJS DES + Utf8 key material, PKCS7)."""
from __future__ import annotations

import base64
import hashlib
import json
import uuid
from datetime import datetime
from typing import Any, Dict, Optional
from urllib.parse import urlencode

try:
    from Crypto.Cipher import DES
except ImportError as exc:  # pragma: no cover
    raise ImportError('pycryptodome required: pip install pycryptodome') from exc

from minidrifter.runtime.crypto.common import pkcs7_pad, pkcs7_unpad
from minidrifter.runtime.crypto.profile_key_extract import CryptoMaterial

PROFILE_ID = 'des_ecb_params_form_wrapper'

# Outer fields excluded from MD5 sign payload (matches mini-program reduce filter)
_SIGN_SKIP = frozenset({'sign', 'isDonum', 'request_resource', 'wkplatform'})


def _des_key_bytes(material_key: str) -> bytes:
    """CryptoJS DES uses the first 8 UTF-8 bytes of the Utf8.parse WordArray."""
    raw = (material_key or '').encode('utf-8')
    if len(raw) < 8:
        raise ValueError('des_key too short')
    return raw[:8]


class DesEcbParamsFormEngine:
    profile_id = PROFILE_ID

    def __init__(self, material: CryptoMaterial) -> None:
        key_src = material.aes_key or material.extras.get('des_key') or ''
        if not key_src:
            raise ValueError('des_key required')
        self.material = material
        self._key_material = key_src
        self._key = _des_key_bytes(key_src)

    def decrypt_params_blob(self, blob: str) -> str:
        raw = base64.b64decode(str(blob).strip())
        plain = pkcs7_unpad(DES.new(self._key, DES.MODE_ECB).decrypt(raw), block_size=8)
        return plain.decode('utf-8', errors='replace')

    def encrypt_params_blob(self, inner_plain: str) -> str:
        enc = DES.new(self._key, DES.MODE_ECB).encrypt(
            pkcs7_pad(inner_plain.encode('utf-8'), block_size=8),
        )
        return base64.b64encode(enc).decode('ascii')

    def decrypt_body_blob(self, blob: str) -> str:
        return self.decrypt_params_blob(blob)

    def decrypt_params_to_obj(self, blob: str) -> Any:
        plain = self.decrypt_params_blob(blob)
        try:
            return json.loads(plain)
        except json.JSONDecodeError:
            return plain

    def encrypt_obj(self, obj: Any) -> str:
        if isinstance(obj, (dict, list)):
            plain = json.dumps(obj, ensure_ascii=False, separators=(',', ':'))
        else:
            plain = str(obj)
        return self.encrypt_params_blob(plain)

    def compute_sign(self, outer_with_plain_params: Dict[str, Any]) -> str:
        """MD5(sorted key=value& ... + ai_key). Sign uses plaintext params JSON before DES."""
        parts = ''
        for k in sorted(outer_with_plain_params.keys()):
            if k in _SIGN_SKIP:
                continue
            if k == 'token' and not outer_with_plain_params.get(k):
                continue
            parts += f"{k}={outer_with_plain_params[k]}&"
        parts += self._key_material
        return hashlib.md5(parts.encode('utf-8')).hexdigest()

    def build_form_post(
        self,
        url: str,
        *,
        inner_obj: Dict[str, Any],
        outer_form: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        refresh_sign: bool = True,
    ) -> Dict[str, Any]:
        outer = dict(outer_form or {})
        if refresh_sign:
            outer['timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            outer['nonce'] = str(uuid.uuid4())
        plain_params = json.dumps(inner_obj, ensure_ascii=False, separators=(',', ':'))
        sign_src = dict(outer)
        sign_src['params'] = plain_params
        if refresh_sign or not outer.get('sign'):
            outer['sign'] = self.compute_sign(sign_src)
        outer['params'] = self.encrypt_obj(inner_obj)
        hdrs = {str(k): str(v) for k, v in (headers or {}).items()}
        if not any(k.lower() == 'content-type' for k in hdrs):
            hdrs['Content-Type'] = 'application/x-www-form-urlencoded'
        return {
            'url': url,
            'method': 'POST',
            'headers': hdrs,
            'body_form': outer,
            'body': urlencode(outer),
            'query_plain': plain_params,
            'sign_refresh': refresh_sign,
        }
