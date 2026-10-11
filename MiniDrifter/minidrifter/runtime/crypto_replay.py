# -*- coding: utf-8 -*-
"""Transform captures and build replay-ready requests."""
from __future__ import annotations

import json
import hashlib
from pathlib import Path
from typing import Any, Dict, List, Optional

from minidrifter.runtime.crypto.common import parse_kv_string
from minidrifter.runtime.crypto.aes_cfb_md5_wrapper import WrapperSessionContext
from minidrifter.runtime.crypto.profile_key_extract import CryptoMaterial
from minidrifter.runtime.crypto.registry import CryptoCapability, get_crypto_engine_for_pack
from minidrifter.runtime.crypto.sm4_dual_form_wrapper import (
    Sm4DualFormEngine,
    session_keys_from_resolved,
)
from minidrifter.runtime.crypto.universal_build import build_crypto_http_request, session_context_from_pool


def sm4_engine_from_material(material: Optional[CryptoMaterial]) -> Optional[Sm4DualFormEngine]:
    if not material or not material.extras.get('sm4_type2_key_hex'):
        return None
    sm4_mat = CryptoMaterial(
        profile_id='sm4_dual_form_wrapper',
        transport_style='form_sm4_cipherone_ciphertwo',
        extras=dict(material.extras),
        source_label=material.extras.get('sm4_source_label') or material.source_label,
    )
    try:
        return Sm4DualFormEngine(sm4_mat)
    except ValueError:
        return None


def is_ciphertext_blob(layer: str) -> bool:
    return layer in {
        'crypto_encrypted_query',
        'crypto_encrypted_body',
        'crypto_encrypted_header',
        'crypto_signature',
    }


def _attach_plaintext_wire_params(req: Dict[str, Any], out: Dict[str, Any]) -> None:
    """Populate decrypted wire for plaintext form/query when no crypto engine is needed."""
    query = req.get('query') or {}
    body_form = req.get('body_form') or {}
    url = req.get('url') or ''

    if query:
        out['decrypted']['query'] = dict(query)
        out['resolved_fields'].update(
            {str(k): str(v) for k, v in query.items() if v is not None}
        )
        out['input_mode'] = 'plaintext_query'
    elif '?' in url:
        raw_q = url.split('?', 1)[-1]
        out['decrypted']['query'] = raw_q
        out['resolved_fields'].update(parse_kv_string(unquote_safe(raw_q)))
        out['input_mode'] = 'plaintext_query'

    if body_form:
        try:
            out['decrypted']['body_form'] = json.dumps(body_form, ensure_ascii=False)
        except TypeError:
            out['decrypted']['body_form'] = str(body_form)
        out['resolved_fields'].update(
            {str(k): str(v) for k, v in body_form.items() if v is not None}
        )
        if out['input_mode'] == 'unknown':
            out['input_mode'] = 'plaintext_form'

    headers = {str(k).lower(): str(v) for k, v in (req.get('headers') or {}).items()}
    if headers.get('host'):
        out['resolved_fields']['Host'] = headers['host']


def process_request_crypto(
    req: Dict[str, Any],
    field_layers: List[Dict[str, Any]],
    capability: CryptoCapability,
    *,
    output_dir: Optional[Path] = None,
    source_dir: Optional[Path] = None,
    engine=None,
    session_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Decrypt ciphertext or normalize plaintext params; verify Authorization when possible."""
    if engine is None and output_dir:
        engine, _ = get_crypto_engine_for_pack(Path(output_dir), source_dir=source_dir)
    headers = {k.lower(): v for k, v in (req.get('headers') or {}).items()}
    query = req.get('query') or {}
    url = req.get('url') or ''

    out: Dict[str, Any] = {
        'profile_id': capability.profile_id,
        'can_replay': capability.can_replay,
        'input_mode': 'unknown',
        'decrypted': {},
        'resolved_fields': {},
        'authorization_check': None,
        'errors': [],
    }

    if not engine:
        has_cipher = any(is_ciphertext_blob(l.get('layer', '')) for l in field_layers)
        out['input_mode'] = 'ciphertext_blocked' if has_cipher else 'plaintext_no_engine'
        if has_cipher:
            out['errors'].append('ciphertext_without_replay_profile')
        else:
            _attach_plaintext_wire_params(req, out)
        return out

    param_str = ''
    query_blob = ''
    query_layer = next((l for l in field_layers if l.get('location') == 'query'), None)
    if query:
        if len(query) == 1 and query_layer and query_layer.get('layer') == 'crypto_encrypted_query':
            query_blob = next(iter(query.values()))
        elif query_layer and query_layer.get('layer') == 'plaintext_param':
            param_str = '&'.join(f'{k}={v}' for k, v in query.items())
            out['input_mode'] = 'plaintext_query'
        else:
            param_str = '&'.join(f'{k}={v}' for k, v in query.items())
            out['input_mode'] = 'plaintext_query'
    elif '?' in url:
        raw_q = url.split('?', 1)[-1]
        if query_layer and query_layer.get('layer') == 'crypto_encrypted_query':
            query_blob = raw_q
        else:
            param_str = unquote_safe(raw_q)

    if query_blob:
        try:
            if hasattr(engine, 'decrypt_query_blob'):
                param_str, param_dict = engine.decrypt_query_blob(query_blob)
            else:
                raise AttributeError('decrypt_query_blob')
            out['input_mode'] = 'ciphertext_query_decrypted'
            out['decrypted']['query'] = param_str
            out['resolved_fields'].update(param_dict)
        except Exception as e:
            out['errors'].append(f'query_decrypt_failed:{e}')

    body_form = req.get('body_form') or {}
    cipher_one = body_form.get('cipherOne') or body_form.get('cipherone')
    cipher_two = body_form.get('cipherTwo') or body_form.get('ciphertwo')
    cipher_h5 = body_form.get('cipherH5') or body_form.get('cipherh5')
    params_blob = body_form.get('params')
    if cipher_h5 and hasattr(engine, 'decrypt_cipher_h5'):
        try:
            plain = engine.decrypt_cipher_h5(str(cipher_h5))
            out['input_mode'] = 'ciphertext_cipherh5_decrypted'
            out['decrypted']['body_form'] = plain
            if hasattr(engine, 'decrypt_cipher_blob_to_fields'):
                out['resolved_fields'].update(engine.decrypt_cipher_blob_to_fields(str(cipher_h5)))
            else:
                out['resolved_fields'].update(parse_kv_string(plain))
            if body_form.get('requestType'):
                out['resolved_fields']['requestType'] = str(body_form['requestType'])
            factor = out['resolved_fields'].get('factor')
            code = out['resolved_fields'].get('code')
            if factor and code:
                out['resolved_fields']['user_key1'] = str(factor)
                code_s = str(code)
                if len(code_s) > 20 and all(c in '0123456789abcdef' for c in code_s.lower()):
                    try:
                        code_s = bytes.fromhex(code_s).decode('utf-8', errors='replace')
                    except ValueError:
                        pass
                out['resolved_fields']['user_key2'] = hashlib.md5(code_s.encode('utf-8')).hexdigest()
        except Exception as e:
            out['errors'].append(f'cipherh5_decrypt_failed:{e}')

    if params_blob and hasattr(engine, 'decrypt_params_to_obj') and not cipher_h5:
        try:
            obj = engine.decrypt_params_to_obj(str(params_blob))
            out['input_mode'] = 'ciphertext_des_params_decrypted'
            out['decrypted']['body_form'] = obj if not isinstance(obj, (dict, list)) else json.dumps(obj, ensure_ascii=False)
            if isinstance(obj, dict):
                out['resolved_fields'].update(
                    {str(k): str(v) for k, v in obj.items() if v is not None and not isinstance(v, (dict, list))}
                )
            for keep in ('appid', 'request_resource', 'channel'):
                if body_form.get(keep) is not None:
                    out['resolved_fields'][keep] = str(body_form[keep])
        except Exception as e:
            out['errors'].append(f'des_params_decrypt_failed:{e}')

    cipher_one = body_form.get('cipherOne') or body_form.get('cipherone')
    cipher_two = body_form.get('cipherTwo') or body_form.get('ciphertwo')
    if cipher_one or cipher_two:
        sm4_engine = None
        material = getattr(engine, 'material', None) if engine else None
        if material:
            sm4_engine = sm4_engine_from_material(material)
        if sm4_engine:
            try:
                merged_ctx = dict(session_context or {})
                merged_ctx.update(out.get('resolved_fields') or {})
                session_keys = session_keys_from_resolved(merged_ctx)
                fields = sm4_engine.decrypt_dual_form(
                    str(cipher_one) if cipher_one else None,
                    str(cipher_two) if cipher_two else None,
                    session_keys=session_keys or None,
                )
                out['input_mode'] = 'ciphertext_sm4_dual_decrypted'
                if cipher_two:
                    out['decrypted']['cipherTwo'] = sm4_engine.decrypt_cipher_two(str(cipher_two))
                if cipher_one:
                    try:
                        out['decrypted']['cipherOne'] = sm4_engine.decrypt_cipher_one(
                            str(cipher_one),
                            session_keys=session_keys or None,
                        )
                    except Exception:
                        pass
                out['resolved_fields'].update(fields)
                if body_form.get('requestType'):
                    out['resolved_fields']['requestType'] = str(body_form['requestType'])
            except Exception as e:
                out['errors'].append(f'sm4_dual_decrypt_failed:{e}')
        elif capability.can_replay:
            out['errors'].append('sm4_dual_fields_without_sm4_keys')

    q_blob = body_form.get('q')
    if q_blob and not query_blob and not cipher_h5 and not cipher_one and not cipher_two:
        try:
            if hasattr(engine, 'decrypt_body_blob'):
                plain = engine.decrypt_body_blob(q_blob)
            elif hasattr(engine, 'decrypt_query_blob'):
                plain, param_dict = engine.decrypt_query_blob(q_blob)
                out['resolved_fields'].update(param_dict)
            else:
                plain = ''
            out['input_mode'] = 'ciphertext_form_body_decrypted'
            out['decrypted']['body_form'] = plain
            try:
                import json
                obj = json.loads(plain)
                if isinstance(obj, dict):
                    out['resolved_fields'].update({str(k): str(v) for k, v in obj.items() if v is not None})
            except json.JSONDecodeError:
                pass
            cid = body_form.get('cid')
            uid = body_form.get('uid')
            sign = body_form.get('sign')
            if cid:
                out['resolved_fields']['cid'] = cid
            if uid:
                out['resolved_fields']['uid'] = uid
                out['resolved_fields']['Token'] = uid
            if sign:
                out['resolved_fields']['sign'] = sign
            if q_blob:
                out['resolved_fields']['q'] = q_blob
            if hasattr(engine, 'verify_sign') and cid and sign and q_blob:
                out['sign_check'] = engine.verify_sign(
                    cid=str(cid), q=str(q_blob), uid=str(uid or ''), sign=str(sign),
                )
        except Exception as e:
            out['errors'].append(f'body_q_decrypt_failed:{e}')
    elif param_str:
        out['decrypted']['query'] = param_str
        out['resolved_fields'].update(parse_kv_string(param_str))
    elif body_form:
        for bk in ('cid', 'uid', 'sign', 'q'):
            if body_form.get(bk):
                out['resolved_fields'][bk] = body_form[bk]
        if body_form.get('uid'):
            out['resolved_fields']['Token'] = body_form['uid']

    app_blob = headers.get('appidentity') or headers.get('appidentity'.lower())
    app_fields: Dict[str, str] = {}
    if app_blob:
        app_layer = next((l for l in field_layers if l.get('name') == 'appidentity'), None)
        if app_layer and app_layer.get('layer') == 'crypto_encrypted_header':
            try:
                app_fields = engine.decrypt_app_identity(app_blob)
                out['input_mode'] = out['input_mode'] or 'ciphertext_header_decrypted'
                out['decrypted']['app_identity'] = app_fields
            except Exception as e:
                out['errors'].append(f'appidentity_decrypt_failed:{e}')
        else:
            app_fields = parse_kv_string(app_blob)
            out['decrypted']['app_identity'] = app_fields

    for k, v in app_fields.items():
        out['resolved_fields'][k] = v
        canon = {'OperatorId': 'OperatorId', 'Version': 'AppVersion', 'Source': 'AppPlatform'}.get(k, k)
        out['resolved_fields'][canon] = v

    auth = headers.get('authorization', '')
    if auth and app_fields and param_str is not None:
        try:
            out['authorization_check'] = engine.verify_authorization(auth, param_str, app_fields)
        except Exception as e:
            out['errors'].append(f'auth_verify_failed:{e}')

    if headers.get('token'):
        out['resolved_fields']['Token'] = headers['token']
    if headers.get('appversion'):
        out['resolved_fields']['AppVersion'] = headers['appversion']
    if headers.get('appplatform'):
        out['resolved_fields']['AppPlatform'] = headers['appplatform']
    if headers.get('host'):
        out['resolved_fields']['Host'] = headers['host']

    uid = out['resolved_fields'].get('userId') or out['resolved_fields'].get('UserId')
    if uid:
        out['resolved_fields']['UserId'] = uid
        out['resolved_fields']['userId'] = uid

    oid = out['resolved_fields'].get('OperatorId')
    if oid and 'UserId' not in out['resolved_fields']:
        out['resolved_fields']['UserId'] = oid

    if out['resolved_fields'].get('openId'):
        out['resolved_fields']['OpenId'] = out['resolved_fields']['openId']

    return out


def unquote_safe(s: str) -> str:
    from urllib.parse import unquote
    return unquote(s)


_DEFAULT_PRODUCE_TARGETS = frozenset({
    'UserId', 'userId', 'DeviceId', 'deviceId', 'OrderId', 'orderId', 'orderNo',
    'OpenId', 'openId', 'Phone', 'deptId', 'DeptId', 'cityId', 'taskId', 'TaskId',
    'memberId', 'MemberId', 'cardId',
    'UserJwt', 'MarketToken', 'unionId', 'ticket', 'code',
})


def collect_chain_target_fields(pack_dir: Path) -> set:
    """Union target_fields from chain material plan and business chains."""
    pack_dir = Path(pack_dir)
    fields: set = set()
    plan_path = pack_dir / 'chain_material_request_plan.json'
    if plan_path.exists():
        try:
            plan = json.loads(plan_path.read_text(encoding='utf-8'))
            for req in plan.get('requests') or []:
                for bag in (
                    req.get('target_fields') or [],
                    req.get('binding_fields') or [],
                    req.get('expected_response_fields') or [],
                ):
                    fields.update(str(f) for f in bag if f)
        except Exception:
            pass
    chains_path = pack_dir / 'business_chains.json'
    if chains_path.exists():
        try:
            doc = json.loads(chains_path.read_text(encoding='utf-8'))
            for chain in doc.get('chains') or []:
                fields.update(str(f) for f in (chain.get('objects') or []) if f)
                fields.update(str(f) for f in (chain.get('binding_fields') or []) if f)
        except Exception:
            pass
    return fields


def process_response_result(
    body: Any,
    capability: CryptoCapability,
    *,
    output_dir: Optional[Path] = None,
    source_dir: Optional[Path] = None,
    engine=None,
    extra_targets: Optional[set] = None,
) -> Dict[str, Any]:
    if engine is None and output_dir:
        engine, _ = get_crypto_engine_for_pack(Path(output_dir), source_dir=source_dir)
    if extra_targets is None and output_dir:
        extra_targets = collect_chain_target_fields(Path(output_dir))
    targets = set(_DEFAULT_PRODUCE_TARGETS) | set(extra_targets or set())
    out: Dict[str, Any] = {'produces_fields': {}, 'body_json': None, 'decrypt_mode': None, 'errors': []}
    if body is None:
        return out

    if isinstance(body, dict):
        if 'content' in body and engine and hasattr(engine, 'decrypt_response_content'):
            try:
                inner = engine.decrypt_response_content(str(body.get('content') or ''))
                out['body_json'] = inner
                out['decrypt_mode'] = 'content_field_decrypted'
                out['produces_fields'] = _extract_produces(inner, extra_targets=targets)
                return out
            except Exception as e:
                out['errors'].append(f'content_decrypt_failed:{e}')
        if 'Result' in body and engine:
            try:
                inner = engine.decrypt_response_result(body['Result'])
                out['body_json'] = inner
                out['decrypt_mode'] = 'result_field_decrypted'
                out['produces_fields'] = _extract_produces(inner, extra_targets=targets)
                return out
            except Exception as e:
                out['errors'].append(f'result_decrypt_failed:{e}')
        out['body_json'] = body
        out['decrypt_mode'] = 'plaintext_json'
        out['produces_fields'] = _extract_produces(body, extra_targets=targets)
        return out

    if isinstance(body, str) and engine:
        try:
            inner = engine.decrypt_response_result(body)
            out['body_json'] = inner
            out['decrypt_mode'] = 'result_string_decrypted'
            out['produces_fields'] = _extract_produces(inner, extra_targets=targets)
            return out
        except Exception as e:
            out['errors'].append(f'response_string_decrypt_failed:{e}')

    return out


def _extract_produces(
    obj: Any,
    prefix: str = '',
    *,
    extra_targets: Optional[set] = None,
) -> Dict[str, Any]:
    fields: Dict[str, Any] = {}
    targets = set(_DEFAULT_PRODUCE_TARGETS) | set(extra_targets or set())
    if isinstance(obj, dict):
        for k, v in obj.items():
            path = f'{prefix}.{k}' if prefix else k
            if k in targets and v not in (None, ''):
                fields[k] = v
            if isinstance(v, (dict, list)):
                fields.update(_extract_produces(v, path, extra_targets=targets))
    elif isinstance(obj, list):
        for i, item in enumerate(obj[:20]):
            fields.update(_extract_produces(item, f'{prefix}[{i}]', extra_targets=targets))
    return fields


def build_replay_request(
    path: str,
    params: Optional[Dict[str, Any]],
    ctx: Any,
    *,
    base_url: str = '',
    capability: CryptoCapability,
    output_dir: Optional[Path] = None,
    source_dir: Optional[Path] = None,
    method: str = 'GET',
) -> Dict[str, Any]:
    engine, cap = get_crypto_engine_for_pack(
        Path(output_dir) if output_dir else Path('.'),
        source_dir=source_dir,
    )
    if not engine:
        raise RuntimeError('no crypto replay profile available')
    if not base_url:
        raise ValueError('base_url required for replay request build')
    pool = {}
    if hasattr(ctx, 'token'):
        pool['Token'] = getattr(ctx, 'token', '')
    if hasattr(ctx, 'uid'):
        pool['uid'] = getattr(ctx, 'uid', '')
    if hasattr(ctx, 'cid'):
        pool['cid'] = getattr(ctx, 'cid', '')
    return build_crypto_http_request(
        engine, cap,
        method=method,
        base_url=base_url,
        path=path,
        params=params,
        ctx=ctx,
        pool=pool or None,
    )
