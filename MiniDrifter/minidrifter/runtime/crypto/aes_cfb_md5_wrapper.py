# -*- coding: utf-8 -*-
"""Generic AES-CFB + MD5 header/query wrapper (WeChat mini-program transport pattern)."""
from __future__ import annotations

import base64
import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

try:
    from Crypto.Cipher import AES
except ImportError as exc:  # pragma: no cover
    raise ImportError('pycryptodome required: pip install pycryptodome') from exc

from minidrifter.runtime.crypto.common import (
    parse_kv_string,
    pkcs7_pad,
    pkcs7_unpad,
    prep_cipher_blob,
    strip_padding,
    urlsafe_cipher_out,
)

PROFILE_ID = 'aes_cfb_md5_header_query_wrapper'


@dataclass
class WrapperCryptoKeys:
    aes_key: bytes = b''
    aes_iv: bytes = b''
    md5_aeskey: str = ''
    des_key: bytes = b''
    des_iv: bytes = b''


@dataclass
class WrapperSessionContext:
    version: str = '7101'
    source: str = 'WeChatApp'
    company: str = ''
    model_version: str = ''
    operator_id: str = ''
    token: str = ''
    md5_aeskey: str = ''

    @classmethod
    def from_app_identity(cls, fields: Dict[str, str], *, token: str = '', md5_aeskey: str = '') -> 'WrapperSessionContext':
        return cls(
            version=fields.get('Version', fields.get('AppVersion', '7101')),
            source=fields.get('Source', fields.get('AppPlatform', 'WeChatApp')),
            company=fields.get('Company', ''),
            model_version=fields.get('ModelVersion', ''),
            operator_id=fields.get('OperatorId', ''),
            token=token,
            md5_aeskey=md5_aeskey,
        )

    @classmethod
    def from_baseline_pool(cls, pool: Dict[str, Any]) -> 'WrapperSessionContext':
        return cls(
            version=str(pool.get('AppVersion') or pool.get('Version') or '7101'),
            source=str(pool.get('AppPlatform') or pool.get('Source') or 'WeChatApp'),
            company=str(pool.get('Company') or ''),
            model_version=str(pool.get('ModelVersion') or ''),
            operator_id=str(pool.get('OperatorId') or pool.get('UserId') or ''),
            token=str(pool.get('Token') or ''),
            md5_aeskey=str(pool.get('md5_aeskey') or pool.get('Md5Aeskey') or ''),
        )


class AesCfbMd5WrapperEngine:
    """Encrypt/decrypt/sign for header+query wrapper transports."""

    profile_id = PROFILE_ID

    def __init__(self, keys: WrapperCryptoKeys, *, cfb_encrypt_padding: str = 'pkcs7'):
        if not keys.aes_key or not keys.aes_iv:
            raise ValueError('aes_key and aes_iv required for wrapper engine')
        self.keys = keys
        self.cfb_encrypt_padding = cfb_encrypt_padding

    def _cfb_plain_bytes(self, plaintext: str) -> bytes:
        data = plaintext.encode('utf-8')
        if self.cfb_encrypt_padding == 'pkcs7':
            return pkcs7_pad(data)
        return data

    def _cfb_decrypt_plain(self, raw: bytes, *, use_cbc: bool = False) -> str:
        mode = AES.MODE_CBC if use_cbc else AES.MODE_CFB
        cipher = AES.new(self.keys.aes_key, mode, iv=self.keys.aes_iv, segment_size=128)
        decrypted = cipher.decrypt(raw)
        if self.cfb_encrypt_padding == 'pkcs7':
            try:
                return pkcs7_unpad(decrypted).decode('utf-8', errors='replace')
            except Exception:
                pass
        return strip_padding(decrypted.decode('utf-8', errors='replace'))

    def decrypt_aes_cfb(self, cipher_url: str, *, use_cbc: bool = False) -> str:
        raw = prep_cipher_blob(cipher_url)
        return self._cfb_decrypt_plain(raw, use_cbc=use_cbc)

    def encrypt_aes_cfb(self, plaintext: str, *, use_cbc: bool = False) -> str:
        mode = AES.MODE_CBC if use_cbc else AES.MODE_CFB
        cipher = AES.new(self.keys.aes_key, mode, iv=self.keys.aes_iv, segment_size=128)
        enc = cipher.encrypt(self._cfb_plain_bytes(plaintext))
        return urlsafe_cipher_out(base64.b64encode(enc).decode('ascii'))

    def md5_auth(self, param_str: str, timespan: int, ctx: WrapperSessionContext) -> str:
        signing_key = ctx.md5_aeskey or self.keys.md5_aeskey
        base = signing_key + param_str
        suffix = (
            f'Version={ctx.version}&Source={ctx.source}&TimeSpan={timespan}'
            + (f'&OperatorId={ctx.operator_id}' if ctx.operator_id else '')
            + f'&Company={ctx.company}&ModelVersion={ctx.model_version}'
        )
        return hashlib.md5((base + suffix).encode()).hexdigest()

    def build_app_identity(self, timespan: int, ctx: WrapperSessionContext) -> str:
        plain = (
            f'Version={ctx.version}&Source={ctx.source}&TimeSpan={timespan}'
            + (f'&OperatorId={ctx.operator_id}' if ctx.operator_id else '')
            + f'&Company={ctx.company}&ModelVersion={ctx.model_version}'
        )
        return self.encrypt_aes_cfb(plain)

    def get_param_encrypt(self, param_str: str, timespan: int, ctx: WrapperSessionContext) -> Dict[str, str]:
        auth = self.md5_auth(param_str, timespan, ctx)
        des = self.encrypt_aes_cfb(param_str) if param_str else ''
        return {'auth': auth, 'des': des}

    def decrypt_app_identity(self, blob: str) -> Dict[str, str]:
        return parse_kv_string(self.decrypt_aes_cfb(blob))

    def _decrypt_plain_no_unpad(self, blob: str) -> str:
        """CFB 解密，不做 PKCS7 unpad（适用于不填充的传输）。"""
        raw = prep_cipher_blob(blob)
        cipher = AES.new(self.keys.aes_key, AES.MODE_CFB, iv=self.keys.aes_iv, segment_size=128)
        return cipher.decrypt(raw).decode('utf-8', errors='replace').rstrip('\x00')

    def _decrypt_plain_robust(self, blob: str) -> str:
        """鲁棒解密：先尝试带 unpad，若结果异常则回退无 unpad。"""
        try:
            plain = self.decrypt_aes_cfb(blob)
            # 检查是否像被错误 unpad 截断（无 '=' 或长度明显偏短）
            if '=' in plain and len(plain) > 10:
                return plain
        except Exception:
            pass
        return self._decrypt_plain_no_unpad(blob)

    def decrypt_query_blob(self, blob: str) -> Tuple[str, Dict[str, str]]:
        plain = self._decrypt_plain_robust(blob)
        return plain, parse_kv_string(plain)

    def decrypt_response_result(self, result_value: Any) -> Dict[str, Any]:
        text = str(result_value)
        plain = self._decrypt_plain_robust(text)
        plain = plain.rstrip('\x00').rstrip()
        try:
            return json.loads(plain)
        except json.JSONDecodeError as e:
            # 从错误位置向前搜索最近的 } 或 ]，截断 padding 后重试
            for i in range(min(e.pos, len(plain)) - 1, -1, -1):
                if plain[i] in ('}', ']'):
                    try:
                        return json.loads(plain[:i + 1])
                    except Exception:
                        continue
            raise

    def verify_authorization(
        self,
        authorization: str,
        param_str: str,
        app_identity_fields: Dict[str, str],
    ) -> Dict[str, Any]:
        ctx = WrapperSessionContext.from_app_identity(app_identity_fields, md5_aeskey=self.keys.md5_aeskey)
        ts_raw = app_identity_fields.get('TimeSpan')
        if not ts_raw:
            return {'verified': False, 'reason': 'missing_timespan_in_app_identity'}
        timespan = int(ts_raw)
        expected = self.md5_auth(param_str, timespan, ctx)
        return {
            'verified': expected.lower() == authorization.lower(),
            'expected': expected,
            'captured': authorization,
            'param_str': param_str,
            'timespan': timespan,
        }

    def build_get_request(
        self,
        base_url: str,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        *,
        ctx: WrapperSessionContext,
        timespan: Optional[int] = None,
    ) -> Dict[str, Any]:
        ts = timespan or int(time.time() * 1000)
        param_str = ''
        if params:
            param_str = '&'.join(f'{k}={v}' for k, v in params.items())
        pe = self.get_param_encrypt(param_str, ts, ctx)
        path_part = path
        blob = pe['des'] if param_str else ''
        if blob:
            if path_part.endswith('?'):
                url = base_url.rstrip('/') + path_part + blob
            else:
                url = base_url.rstrip('/') + path_part + '?' + blob
        else:
            url = base_url.rstrip('/') + path_part
        return {
            'method': 'GET',
            'url': url,
            'path': path,
            'profile_id': self.profile_id,
            'headers': {
                'Content-Type': 'application/json',
                'Token': ctx.token,
                'Remark': 'Unchecked',
                'AppVersion': ctx.version,
                'AppPlatform': ctx.source,
                'Authorization': pe['auth'],
                'AppIdentity': self.build_app_identity(ts, ctx),
            },
            'query_plain': param_str,
            'query_encrypted': pe['des'] if param_str else None,
            'timespan': ts,
        }

    def md5_auth_for_body(self, body_plain: str, timespan: int, ctx: WrapperSessionContext) -> str:
        """POST body 的 Authorization：md5(md5_aeskey + body_plain + suffix)。"""
        signing_key = ctx.md5_aeskey or self.keys.md5_aeskey
        base = signing_key + body_plain
        suffix = (
            f'Version={ctx.version}&Source={ctx.source}&TimeSpan={timespan}'
            + (f'&OperatorId={ctx.operator_id}' if ctx.operator_id else '')
            + f'&Company={ctx.company}&ModelVersion={ctx.model_version}'
            + f'&Culture=zh-CN'
        )
        return hashlib.md5((base + suffix).encode()).hexdigest()

    def build_post_request(
        self,
        base_url: str,
        path: str,
        body_plain: str,
        *,
        ctx: WrapperSessionContext,
        timespan: Optional[int] = None,
    ) -> Dict[str, Any]:
        ts = timespan or int(time.time() * 1000)
        if not isinstance(body_plain, str):
            body_plain = json.dumps(body_plain, ensure_ascii=False)
        body_cipher = self.encrypt_aes_cfb(body_plain, use_cbc=False)
        auth = self.md5_auth_for_body(body_plain, ts, ctx)
        return {
            'method': 'POST',
            'url': base_url.rstrip('/') + path,
            'path': path,
            'profile_id': self.profile_id,
            'headers': {
                'Content-Type': 'application/json',
                'Token': ctx.token,
                'Remark': 'Unchecked',
                'AppVersion': ctx.version,
                'AppPlatform': ctx.source,
                'Authorization': auth,
                'AppIdentity': self.build_app_identity(ts, ctx),
            },
            'body_plain': body_plain,
            'body_cipher': body_cipher,
            'data': body_cipher,
            'timespan': ts,
        }

    def build_request(
        self,
        method: str,
        base_url: str,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        *,
        ctx: WrapperSessionContext,
        timespan: Optional[int] = None,
        body_plain: Optional[str] = None,
    ) -> Dict[str, Any]:
        method_u = (method or 'GET').upper()
        if method_u == 'POST' and body_plain is not None:
            return self.build_post_request(base_url, path, body_plain, ctx=ctx, timespan=timespan)
        if method_u != 'GET':
            raise NotImplementedError(f'{self.profile_id} replay v1 supports GET only, got {method_u}')
        return self.build_get_request(base_url, path, params, ctx=ctx, timespan=timespan)
