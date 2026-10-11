# -*- coding: utf-8 -*-
"""SM4 cipherOne + cipherTwo form transport (baselifeConfig getPostDataSM4)."""
from __future__ import annotations

import base64
import hashlib
from typing import Any, Dict, Optional
from urllib.parse import parse_qsl

try:
    from gmssl.sm4 import CryptSM4, SM4_DECRYPT
except ImportError as exc:  # pragma: no cover
    raise ImportError('gmssl required: pip install gmssl') from exc

from minidrifter.runtime.crypto.profile_key_extract import CryptoMaterial
from minidrifter.runtime.crypto.triple_mix_key import derive_triple_mix_key

PROFILE_ID = 'sm4_dual_form_wrapper'


def _sm4_decrypt_ecb(blob_b64: str, key_hex: str) -> bytes:
    raw = base64.b64decode(str(blob_b64).strip())
    key = bytes.fromhex(key_hex)
    crypt = CryptSM4()
    crypt.set_key(key, SM4_DECRYPT)
    return crypt.crypt_ecb(raw)


class Sm4DualFormEngine:
    profile_id = PROFILE_ID

    def __init__(self, material: CryptoMaterial) -> None:
        self.material = material
        extras = material.extras or {}
        self._type2_key = extras.get('sm4_type2_key_hex') or ''
        self._type1_default = extras.get('sm4_type1_default_hex') or ''
        if not self._type2_key:
            raise ValueError('sm4_type2_key_hex required')

    def decrypt_cipher_two(self, blob: str) -> str:
        return _sm4_decrypt_ecb(blob, self._type2_key).decode('utf-8', errors='replace')

    def decrypt_cipher_one(
        self,
        blob: str,
        *,
        session_keys: Optional[Dict[str, str]] = None,
    ) -> str:
        session_keys = session_keys or {}
        candidates = []
        if session_keys.get('user_key1') and session_keys.get('user_key2') and session_keys.get('user_key3'):
            session_hex = derive_triple_mix_key(
                session_keys['user_key1'],
                session_keys['user_key2'],
                session_keys['user_key3'],
            )
            if session_hex:
                candidates.append(session_hex)
        if self._type1_default:
            candidates.append(self._type1_default)

        last_err: Optional[Exception] = None
        for key_hex in candidates:
            try:
                plain = _sm4_decrypt_ecb(blob, key_hex).decode('utf-8', errors='replace')
                if plain and '=' in plain:
                    return plain
            except Exception as exc:
                last_err = exc
                continue
        if last_err:
            raise last_err
        return ''

    def decrypt_body_blob(self, blob: str) -> str:
        return self.decrypt_cipher_two(blob)

    def decrypt_dual_form(
        self,
        cipher_one: Optional[str],
        cipher_two: Optional[str],
        *,
        session_keys: Optional[Dict[str, str]] = None,
    ) -> Dict[str, str]:
        out: Dict[str, str] = {}
        if cipher_two:
            for k, v in parse_qsl(self.decrypt_cipher_two(cipher_two), keep_blank_values=True):
                out[k] = v
        if cipher_one:
            for k, v in parse_qsl(
                self.decrypt_cipher_one(cipher_one, session_keys=session_keys),
                keep_blank_values=True,
            ):
                out.setdefault(k, v)
        return out

    def encrypt_cipher_two(self, inner_plain: str) -> str:
        from gmssl.sm4 import CryptSM4, SM4_ENCRYPT
        crypt = CryptSM4()
        crypt.set_key(bytes.fromhex(self._type2_key), SM4_ENCRYPT)
        # PKCS7 via gmssl crypt_ecb expects padded input in some versions; pad manually
        data = inner_plain.encode('utf-8')
        pad_len = 16 - (len(data) % 16)
        data = data + bytes([pad_len] * pad_len)
        return base64.b64encode(crypt.crypt_ecb(data)).decode('ascii')

    def build_post_request(
        self,
        base_url: str,
        path: str,
        params: Dict[str, Any],
        ctx: Any = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Rebuild SM4 dual form: requestType + cipherTwo(urlencode(params))."""
        from urllib.parse import urlencode, urljoin
        params = dict(params or {})
        request_type = str(params.pop('requestType', None) or 'mini')
        locale = params.pop('_locale', None)
        inner = {k: v for k, v in params.items() if v is not None and str(k).lower() not in {
            'cipherh5', 'cipherone', 'ciphertwo',
        }}
        plain = urlencode({str(k): str(v) for k, v in inner.items()}, doseq=True)
        body = {
            'requestType': request_type,
            'cipherTwo': self.encrypt_cipher_two(plain),
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
            'transport_style': 'form_sm4_cipherone_ciphertwo',
        }


def session_keys_from_resolved(resolved: Dict[str, Any]) -> Dict[str, str]:
    """Build userKey1/2/3 candidates from prior decrypted intake fields."""
    keys: Dict[str, str] = {}
    factor = str(resolved.get('factor') or '')
    if factor and not factor.startswith('{'):
        keys['user_key1'] = factor
    code = resolved.get('code')
    if code:
        code_s = code if isinstance(code, str) else str(code)
        if len(code_s) > 20 and all(c in '0123456789abcdef' for c in code_s.lower()):
            try:
                code_s = bytes.fromhex(code_s).decode('utf-8', errors='replace')
            except ValueError:
                pass
        keys['user_key2'] = hashlib.md5(code_s.encode('utf-8')).hexdigest()
    uk3 = str(
        resolved.get('user_key3')
        or resolved.get('userKey3')
        or ''
    )
    if not uk3:
        factor = str(resolved.get('factor') or '')
        if factor and not resolved.get('code'):
            uk3 = factor
    if uk3:
        keys['user_key3'] = uk3
    return keys
