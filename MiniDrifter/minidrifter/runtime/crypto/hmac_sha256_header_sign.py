# -*- coding: utf-8 -*-
"""Header Sign = HMAC-SHA256(payload, secret) with URL-safe Base64 (no padding)."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

from minidrifter.runtime.crypto.profile_key_extract import CryptoMaterial
from minidrifter.runtime.crypto.sign_engines import compute_sign
from minidrifter.runtime.crypto.sign_payload_builders import build_relative_path_merge_params

PROFILE_ID = 'hmac_sha256_header_sign'
SIGN_HEADER = 'Sign'


@dataclass
class HmacHeaderSignContext:
    sign_key: str
    sign_method: str = 'hmac_sha256_base64url'
    payload_builder: str = 'relative_path_merge_params'
    sign_header: str = SIGN_HEADER

    @classmethod
    def from_material(cls, material: CryptoMaterial) -> 'HmacHeaderSignContext':
        return cls(
            sign_key=material.sign_key or material.extras.get('hmac_secret') or '',
            sign_method=material.sign_method or 'hmac_sha256_base64url',
            payload_builder=material.extras.get('payload_builder') or 'relative_path_merge_params',
            sign_header=material.extras.get('sign_header') or SIGN_HEADER,
        )


class HmacSha256HeaderSignEngine:
    profile_id = PROFILE_ID

    def __init__(self, material: CryptoMaterial) -> None:
        if not material.sign_key:
            raise ValueError('sign_key required for hmac_sha256_header_sign')
        self.material = material
        self.ctx = HmacHeaderSignContext.from_material(material)

    def build_sign_payload(
        self,
        relative_path: str,
        *,
        query: Optional[Dict[str, Any]] = None,
        body: Optional[Dict[str, Any]] = None,
    ) -> str:
        if self.ctx.payload_builder == 'relative_path_merge_params':
            return build_relative_path_merge_params(relative_path, query=query, body=body)
        return relative_path

    def sign(
        self,
        relative_path: str,
        *,
        query: Optional[Dict[str, Any]] = None,
        body: Optional[Dict[str, Any]] = None,
    ) -> str:
        payload = self.build_sign_payload(relative_path, query=query, body=body)
        return compute_sign(payload, self.ctx.sign_method)

    def sign_headers(
        self,
        relative_path: str,
        *,
        query: Optional[Dict[str, Any]] = None,
        body: Optional[Dict[str, Any]] = None,
        base_headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, str]:
        headers = dict(base_headers or {})
        headers[self.ctx.sign_header] = self.sign(relative_path, query=query, body=body)
        return headers
