# -*- coding: utf-8 -*-
"""AES-CBC cipherH5 form-body wrapper (CryptoJS-compatible)."""
from __future__ import annotations

import base64
from typing import Any, Dict, Optional
from urllib.parse import parse_qsl, urlencode, urljoin

try:
    from Crypto.Cipher import AES
except ImportError as exc:  # pragma: no cover
    raise ImportError('pycryptodome required: pip install pycryptodome') from exc

from minidrifter.runtime.crypto.common import pkcs7_pad, pkcs7_unpad
from minidrifter.runtime.crypto.profile_key_extract import CryptoMaterial

PROFILE_ID = 'aes_cbc_cipherh5_form_wrapper'


class AesCbcCipherH5FormEngine:
    profile_id = PROFILE_ID

    def __init__(self, material: CryptoMaterial) -> None:
        if not material.aes_key or not material.aes_iv:
            raise ValueError('aes_key and aes_iv required')
        self.material = material
        self._key = material.aes_key.encode('utf-8')
        self._iv = material.aes_iv.encode('utf-8')

    def decrypt_cipher_h5(self, blob: str) -> str:
        raw = base64.b64decode(blob.strip())
        cipher = AES.new(self._key, AES.MODE_CBC, self._iv)
        plain = pkcs7_unpad(cipher.decrypt(raw))
        return plain.decode('utf-8', errors='replace')

    def encrypt_cipher_h5(self, inner_plain: str) -> str:
        cipher = AES.new(self._key, AES.MODE_CBC, self._iv)
        enc = cipher.encrypt(pkcs7_pad(inner_plain.encode('utf-8')))
        return base64.b64encode(enc).decode('ascii')

    def decrypt_body_blob(self, blob: str) -> str:
        return self.decrypt_cipher_h5(blob)

    def decrypt_cipher_blob_to_fields(self, blob: str) -> Dict[str, str]:
        plain = self.decrypt_cipher_h5(blob)
        return {k: v for k, v in parse_qsl(plain, keep_blank_values=True)}

    def build_post_request(
        self,
        base_url: str,
        path: str,
        params: Dict[str, Any],
        ctx: Any = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Rebuild form body: requestType + cipherH5(urlencode(params))."""
        params = dict(params or {})
        request_type = str(params.pop('requestType', None) or params.pop('_requestType', None) or 'mini')
        locale = params.pop('_locale', None)
        inner = {k: v for k, v in params.items() if v is not None and str(k).lower() not in {
            'cipherh5', 'cipherone', 'ciphertwo',
        }}
        plain = urlencode({str(k): str(v) for k, v in inner.items()}, doseq=True)
        body = {
            'requestType': request_type,
            'cipherH5': self.encrypt_cipher_h5(plain),
        }
        if locale is not None:
            body['_locale'] = str(locale)
        url = urljoin(base_url.rstrip('/') + '/', (path or '').lstrip('/'))
        return {
            'url': url,
            'method': 'POST',
            'headers': {'Content-Type': 'application/x-www-form-urlencoded'},
            'data': body,
            'crypto': True,
            'transport_style': 'form_cipherh5_encrypted',
        }
