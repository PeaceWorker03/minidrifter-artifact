# -*- coding: utf-8 -*-
"""Profile-driven crypto HTTP request builder — dispatches by transport.style, not app name."""
from __future__ import annotations

import json
from typing import Any, Dict, Optional

from minidrifter.runtime.crypto.aes_cfb_md5_wrapper import (
    AesCfbMd5WrapperEngine,
    WrapperSessionContext,
)
from minidrifter.runtime.crypto.registry import CryptoCapability, normalize_profile_id
from minidrifter.runtime.crypto.token_sign_aes_wrapper import (
    TokenSignAesWrapperEngine,
    TokenSignSessionContext,
)

FORM_BODY_STYLES = frozenset({
    'form_cid_q_sign',
    'form_encrypted_body',
    'form_cipherh5_encrypted',
    'form_sm4_cipherone_ciphertwo',
})
HEADER_QUERY_STYLES = frozenset({'header_query_encrypted', 'encrypted_query_header'})


def transport_style_of(cap: CryptoCapability) -> str:
    style = (cap.transport_style or '').strip().lower()
    if style:
        return style
    pid = normalize_profile_id(cap.profile_id)
    if pid == 'token_sign_aes_wrapper':
        return 'form_cid_q_sign'
    if pid == 'aes_cfb_md5_header_query_wrapper':
        return 'header_query_encrypted'
    return style


def session_context_from_pool(cap: CryptoCapability, pool: Dict[str, Any]) -> Any:
    if transport_style_of(cap) in FORM_BODY_STYLES:
        return TokenSignSessionContext.from_baseline_pool(pool)
    return WrapperSessionContext.from_baseline_pool(pool)


def build_crypto_http_request(
    engine: Any,
    cap: CryptoCapability,
    *,
    method: str,
    base_url: str,
    path: str,
    params: Optional[Dict[str, Any]] = None,
    pool: Optional[Dict[str, Any]] = None,
    ctx: Any = None,
    timespan: Optional[int] = None,
    global_merge: Optional[Dict[str, Any]] = None,
    force_query: bool = False,
) -> Dict[str, Any]:
    """Build signed/encrypted HTTP request using engine + profile transport style."""
    method_u = (method or 'GET').upper()
    style = transport_style_of(cap)
    params = dict(params or {})

    if pool is not None and ctx is None:
        ctx = session_context_from_pool(cap, pool)

    if style in FORM_BODY_STYLES or isinstance(engine, TokenSignAesWrapperEngine):
        if hasattr(engine, 'build_post_request'):
            build_kwargs: Dict[str, Any] = {}
            if global_merge is not None and hasattr(engine, 'build_form_body'):
                build_kwargs['global_merge'] = global_merge
            built = engine.build_post_request(
                base_url, path, params, ctx=ctx or TokenSignSessionContext(), **build_kwargs,
            )
            built['method'] = method_u if method_u in {'POST', 'PUT', 'PATCH'} else 'POST'
            return built
        raise TypeError(f'{type(engine).__name__} missing build_post_request for {style}')

    if isinstance(engine, AesCfbMd5WrapperEngine) or style in HEADER_QUERY_STYLES:
        session = ctx or WrapperSessionContext()
        if cap.md5_aeskey and hasattr(session, 'md5_aeskey') and not session.md5_aeskey:
            session.md5_aeskey = cap.md5_aeskey
        # 一嗨/耀东方大量接口是 POST + 加密 query（URL 以 ? 结尾），不是 JSON body
        if force_query or method_u == 'GET' or not params:
            built = engine.build_get_request(
                base_url, path, params, ctx=session, timespan=timespan,
            )
            if method_u != 'GET' and isinstance(built, dict):
                built['method'] = method_u
            return built
        if method_u == 'POST' and params and hasattr(engine, 'build_post_request'):
            body_plain = json.dumps(params, ensure_ascii=False)
            return engine.build_post_request(
                base_url, path, body_plain, ctx=session, timespan=timespan,
            )

    if hasattr(engine, 'build_request'):
        return engine.build_request(
            method_u, base_url, path, params, ctx=ctx, timespan=timespan,
        )
    if method_u == 'GET' and hasattr(engine, 'build_get_request'):
        return engine.build_get_request(base_url, path, params, ctx=ctx, timespan=timespan)
    if hasattr(engine, 'build_post_request'):
        return engine.build_post_request(base_url, path, params, ctx=ctx)
    raise TypeError(f'unsupported crypto build for style={style} engine={type(engine).__name__}')


def verify_intake_crypto_parity(
    engine: Any,
    cap: CryptoCapability,
    capture: Dict[str, Any],
    pool: Dict[str, Any],
    *,
    base_url: str,
) -> Dict[str, Any]:
    """Recompute crypto fields from intake capture and compare with captured values."""
    proc = capture.get('crypto_processing') or {}
    path = (capture.get('path') or '').split('?', 1)[0]
    style = transport_style_of(cap)

    if style in FORM_BODY_STYLES:
        sign_ok = proc.get('sign_check')
        if sign_ok is True:
            return {'ok': True, 'mode': 'sign_check_verified', 'path': path}
        decrypted = proc.get('decrypted') or {}
        params: Dict[str, Any] = {}
        if decrypted.get('body_form'):
            try:
                import json
                obj = json.loads(decrypted['body_form'])
                if isinstance(obj, dict):
                    params = obj
            except json.JSONDecodeError:
                pass
        if not params:
            params = {
                k: v for k, v in (proc.get('resolved_fields') or {}).items()
                if k.lower() not in {'cid', 'uid', 'sign', 'q', 'token'}
            }
        captured = str((proc.get('resolved_fields') or {}).get('sign') or '')
        built = build_crypto_http_request(
            engine, cap, method='POST', base_url=base_url, path=path,
            params=params, pool=pool,
        )
        got_sign = (built.get('body_form') or {}).get('sign', '')
        return {
            'ok': bool(got_sign and captured and got_sign == captured),
            'mode': 'sign_rebuild_parity',
            'path': path,
            'expected': captured,
            'rebuilt': got_sign,
        }

    auth = proc.get('authorization_check') or {}
    if not auth.get('param_str'):
        return {'ok': False, 'mode': 'no_auth_baseline', 'path': path}
    session = session_context_from_pool(cap, pool)
    if cap.md5_aeskey and hasattr(session, 'md5_aeskey'):
        session.md5_aeskey = cap.md5_aeskey
    ts = int(auth.get('timespan') or 0)
    params: Dict[str, str] = {}
    for part in str(auth.get('param_str')).split('&'):
        if '=' in part:
            k, v = part.split('=', 1)
            params[k] = v
    built = build_crypto_http_request(
        engine, cap, method='GET', base_url=base_url, path=path.rstrip('?'),
        params=params, ctx=session, timespan=ts,
    )
    expected = str(auth.get('expected', '')).lower()
    got = str((built.get('headers') or {}).get('Authorization', '')).lower()
    return {
        'ok': bool(expected and got and expected == got),
        'mode': 'authorization_parity',
        'path': path,
        'expected': expected,
        'rebuilt': got,
        'capture_index': capture.get('capture_index'),
    }
