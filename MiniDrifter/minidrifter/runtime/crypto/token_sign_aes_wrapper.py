# -*- coding: utf-8 -*-
"""Form-body AES-ECB + custom sign wrapper (Taro/webpack bundle transport)."""
from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Any, Dict, Optional
from urllib.parse import urlencode

try:
    from Crypto.Cipher import AES
except ImportError as exc:  # pragma: no cover
    raise ImportError('pycryptodome required: pip install pycryptodome') from exc

from minidrifter.runtime.crypto.common import pkcs7_pad, pkcs7_unpad
from minidrifter.runtime.crypto.profile_key_extract import CryptoMaterial
from minidrifter.runtime.crypto.sign_engines import compute_sign as run_sign_engine

PROFILE_ID = 'token_sign_aes_wrapper'


@dataclass
class TokenSignSessionContext:
    uid: str = ''
    cid: str = ''
    api_host: str = ''

    @classmethod
    def from_baseline_pool(cls, pool: Dict[str, Any]) -> 'TokenSignSessionContext':
        uid = str(pool.get('uid') or pool.get('Uid') or '')
        cid = str(pool.get('cid') or pool.get('Cid') or '')
        host = str(pool.get('Host') or pool.get('api_host') or '')
        if host and not host.startswith('http'):
            host = f'https://{host}'
        return cls(uid=uid, cid=cid, api_host=host or '')


class TokenSignAesWrapperEngine:
    profile_id = PROFILE_ID

    def __init__(self, material: CryptoMaterial) -> None:
        if not material.aes_key:
            raise ValueError('aes_key required')
        self.material = material
        self._key_bytes = self._init_key_bytes(material.aes_key)

    @staticmethod
    def _init_key_bytes(key: str) -> bytes:
        raw = key.encode('utf-8')
        n = 16
        if len(raw) < n:
            return raw.ljust(n, b'\0')
        if len(raw) > n:
            return raw[:n]
        return raw

    @staticmethod
    def _urlsafe_to_b64(blob: str) -> str:
        s = blob.replace('-', '+').replace('_', '/')
        pad = 4 - len(s) % 4
        if pad < 4:
            s += '=' * pad
        return s

    @staticmethod
    def _b64_to_urlsafe(raw_b64: str) -> str:
        return raw_b64.replace('+', '-').replace('/', '_').replace('=', '')

    def encrypt_aes_ecb(self, plaintext: str, *, url_safe: bool = True) -> str:
        cipher = AES.new(self._key_bytes, AES.MODE_ECB)
        enc = cipher.encrypt(pkcs7_pad(plaintext.encode('utf-8')))
        b64 = base64.b64encode(enc).decode('ascii')
        return self._b64_to_urlsafe(b64) if url_safe else b64

    def decrypt_aes_ecb(self, blob: str, *, url_safe: bool = True) -> str:
        b64 = self._urlsafe_to_b64(blob) if url_safe else blob
        raw = base64.b64decode(b64)
        cipher = AES.new(self._key_bytes, AES.MODE_ECB)
        plain = pkcs7_unpad(cipher.decrypt(raw))
        return plain.decode('utf-8', errors='replace')

    @staticmethod
    def _sign_int_chunk(raw: bytes, offset: int) -> int:
        n = (raw[offset] & 255) << 24
        r = (raw[offset + 1] & 255) << 16
        i = (raw[offset + 2] & 255) << 8
        o = raw[offset + 3] & 255
        return abs(n | r | i | o)

    def compute_sign(self, sign_input: str) -> str:
        method = getattr(self.material, 'sign_method', None) or 'md5_raw_four_int_concat'
        return run_sign_engine(sign_input, method=method)

    def build_sign_input(self, *, cid: str, q: str, uid: Optional[str] = None) -> str:
        sign_key = self.material.sign_key or self.material.aes_key
        uid_part = f';uid={uid}' if uid else ''
        return f'cid={cid};q={q}{uid_part}{sign_key}'

    def build_form_body(
        self,
        data: Dict[str, Any],
        *,
        uid: Optional[str] = None,
        bucket_id_list: Any = None,
        global_merge: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, str]:
        payload = dict(global_merge or {})
        payload.update(data or {})
        if bucket_id_list is not None and 'bucketIdList' not in payload:
            payload['bucketIdList'] = bucket_id_list
        plain = json.dumps(payload, ensure_ascii=False, separators=(',', ':'))
        q = self.encrypt_aes_ecb(plain, url_safe=True)
        cid = self.material.cid or ''
        uid_val = uid or ''
        sign = self.compute_sign(self.build_sign_input(cid=cid, q=q, uid=uid_val or None))
        body = {'cid': cid, 'q': q, 'sign': sign}
        if uid_val:
            body['uid'] = uid_val
        return body

    def decrypt_body_blob(self, q_blob: str) -> str:
        return self.decrypt_aes_ecb(q_blob, url_safe=True)

    def decrypt_params_to_obj(self, blob: str) -> Dict[str, Any]:
        """Alias for DES-style callers: decrypt form ``q`` blob → inner JSON object."""
        plain = self.decrypt_body_blob(str(blob or ''))
        obj = json.loads(plain)
        if not isinstance(obj, dict):
            raise ValueError('token_sign q decrypt did not yield object')
        return obj

    def build_form_post(
        self,
        url: str,
        *,
        inner_obj: Optional[Dict[str, Any]] = None,
        outer_form: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Rebuild cid/q/sign(/uid) form body for mutated inner JSON (DES-pool compatible)."""
        outer = dict(outer_form or {})
        uid = str(outer.get('uid') or '')
        cid = str(outer.get('cid') or self.material.cid or '')
        if cid:
            self.material.cid = cid
        ctx = TokenSignSessionContext(uid=uid, cid=cid)
        body = self.build_form_body(inner_obj or {}, uid=uid or None)
        hdrs = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'appletEncrypt': 'appletEncrypt',
        }
        for k, v in (headers or {}).items():
            if not k or v is None:
                continue
            lk = str(k).lower()
            if lk in {'host', 'content-length', 'connection'}:
                continue
            hdrs[str(k)] = str(v)
        return {
            'profile_id': self.profile_id,
            'method': 'POST',
            'url': url,
            'headers': hdrs,
            'body_form': body,
            'body': urlencode(body),
            'query_plain': json.dumps(inner_obj or {}, ensure_ascii=False),
        }

    def decrypt_query_blob(self, blob: str) -> tuple[str, Dict[str, str]]:
        plain = self.decrypt_body_blob(blob)
        try:
            obj = json.loads(plain)
            if isinstance(obj, dict):
                return plain, {str(k): str(v) for k, v in obj.items() if v is not None}
        except json.JSONDecodeError:
            pass
        return plain, {}

    def decrypt_response_content(self, content: str) -> Any:
        if not content:
            return None
        plain = self.decrypt_aes_ecb(content, url_safe=True)
        try:
            return json.loads(plain)
        except json.JSONDecodeError:
            return plain

    def decrypt_response_result(self, payload: Any) -> Any:
        if isinstance(payload, dict) and 'content' in payload:
            inner = self.decrypt_response_content(str(payload.get('content') or ''))
            if inner is not None:
                return inner
        if isinstance(payload, str):
            return self.decrypt_response_content(payload)
        return payload

    def verify_sign(self, *, cid: str, q: str, uid: str, sign: str) -> bool:
        expected = self.compute_sign(self.build_sign_input(cid=cid, q=q, uid=uid or None))
        return expected == sign

    def build_post_request(
        self,
        base_url: str,
        path: str,
        params: Optional[Dict[str, Any]],
        *,
        ctx: Optional[TokenSignSessionContext] = None,
        global_merge: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        ctx = ctx or TokenSignSessionContext()
        cid = ctx.cid or self.material.cid
        if cid:
            self.material.cid = cid
        body = self.build_form_body(
            params or {}, uid=ctx.uid or None, global_merge=global_merge,
        )
        url = f'{base_url.rstrip("/")}{path}'
        return {
            'profile_id': self.profile_id,
            'method': 'POST',
            'url': url,
            'headers': {
                'Content-Type': 'application/x-www-form-urlencoded',
                'appletEncrypt': 'appletEncrypt',
            },
            'body_form': body,
            'body': urlencode(body),
            'query_plain': json.dumps(params or {}, ensure_ascii=False),
        }

    def build_request(
        self,
        method: str,
        base_url: str,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        *,
        ctx: Optional[TokenSignSessionContext] = None,
        timespan: Optional[int] = None,
    ) -> Dict[str, Any]:
        return self.build_post_request(base_url, path, params, ctx=ctx)

    def build_get_request(
        self,
        base_url: str,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        *,
        ctx: Optional[TokenSignSessionContext] = None,
        timespan: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Alias — form-body transport always builds POST."""
        return self.build_post_request(base_url, path, params, ctx=ctx)
