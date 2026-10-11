# -*- coding: utf-8 -*-
"""Anchor replay — verify baseline by replaying user captures before broad API search."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode

from minidrifter.materials.intake_param_hints import (
    hint_lookup,
    index_capture_query_hints,
    normalize_api_path,
    params_from_intake_hint,
)
from minidrifter.verification.response_oracle import _bare_json_success
from minidrifter.verification.request_builder import build_request_preview
from minidrifter.runtime.crypto.registry import get_crypto_engine_for_pack
from minidrifter.runtime.crypto.universal_build import (
    FORM_BODY_STYLES,
    HEADER_QUERY_STYLES,
    build_crypto_http_request,
    session_context_from_pool,
    transport_style_of,
    verify_intake_crypto_parity,
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _baseline_pool(ctx: Dict[str, Any]) -> Dict[str, str]:
    return {
        k: str(v.get('value'))
        for k, v in (ctx.get('resolved_fields') or {}).items()
        if isinstance(v, dict) and v.get('value') is not None
    }


def _is_plaintext_direct(ctx: Dict[str, Any]) -> bool:
    strategy = (ctx.get('intake_strategy') or {}).get('strategy') or ctx.get('replay_mode')
    return strategy == 'plaintext_direct'


def _business_ok(body_json: Any) -> bool:
    return _bare_json_success(body_json)


def _replay_plaintext_capture(
    cap_row: Dict[str, Any],
    *,
    pack_dir: Path,
    baseline_context: Dict[str, Any],
    host: str,
    hints: Dict[str, Dict[str, Any]],
    mode: str,
) -> Optional[Dict[str, Any]]:
    path = normalize_api_path(cap_row.get('path') or '')
    hint = hint_lookup(hints, path, cap_row.get('method') or 'GET')
    if not hint or not hint.get('param_pairs'):
        return None

    pool = _baseline_pool(baseline_context)
    params = params_from_intake_hint(hint, {
        k: {'value': v} for k, v in pool.items()
    })
    method = (hint.get('method') or cap_row.get('method') or 'GET').upper()
    preview = build_request_preview(
        {
            'method': method,
            'path': cap_row.get('path') or '',
            'params': params if hint.get('transport') == 'query' else {},
            'body_params': params if hint.get('transport') == 'form_body' else {},
            'crypto_required': False,
            'transport_style': 'form_urlencoded' if hint.get('transport') == 'form_body' else None,
        },
        pack_dir=pack_dir,
        baseline_context=baseline_context,
        base_url=host,
    )
    if preview.get('build_status') != 'ok':
        return {'ok': False, 'error': preview.get('build_status'), 'mode': 'plaintext_capture'}

    if mode != 'execute':
        return {'ok': True, 'mode': 'dry_run_plaintext_capture'}

    import urllib.request
    try:
        url = preview.get('url') or ''
        headers = preview.get('headers') or {}
        body = preview.get('body')
        if body and method in {'POST', 'PUT', 'PATCH'}:
            req = urllib.request.Request(
                url, data=body.encode() if isinstance(body, str) else body,
                method=method, headers=headers,
            )
        else:
            req = urllib.request.Request(url, method=method, headers=headers)
        with urllib.request.urlopen(req, timeout=20) as resp:
            body_text = resp.read().decode('utf-8', errors='replace')
            body_json = json.loads(body_text)
        ok = _business_ok(body_json)
        return {
            'ok': ok,
            'http_status': resp.status,
            'mode': 'plaintext_capture',
            'path': path,
        }
    except Exception as exc:
        return {'ok': False, 'error': str(exc), 'mode': 'plaintext_capture'}


def _capture_transport_snapshot(cap: Dict[str, Any]) -> Dict[str, str]:
    snap = dict(cap.get('transport_snapshot') or {})
    if snap:
        return snap
    proc = cap.get('crypto_processing') or {}
    resolved = proc.get('resolved_fields') or {}
    for k in ('cid', 'q', 'uid', 'sign'):
        if resolved.get(k):
            snap[k] = str(resolved[k])
    return snap


def run_anchor_capture_replay(
    pack_dir: Path,
    *,
    baseline_context: Dict[str, Any],
    mode: str = 'execute',
    source_dir: Optional[Path] = None,
    base_url: Optional[str] = None,
) -> Dict[str, Any]:
    """Replay each intake capture: exact body first, then parametric rebuild."""
    pack_dir = Path(pack_dir)
    intake_path = pack_dir / 'baseline_intake_report.json'
    if not intake_path.exists():
        return {'status': 'skipped', 'reason': 'no_intake_report'}

    intake = json.loads(intake_path.read_text(encoding='utf-8'))
    pool = _baseline_pool(baseline_context)
    host = base_url or pool.get('Host') or pool.get('api_host') or ''
    if host and not str(host).startswith('http'):
        host = f'https://{host}'

    engine, cap = get_crypto_engine_for_pack(pack_dir, source_dir=source_dir)
    style = transport_style_of(cap)
    plaintext_direct = _is_plaintext_direct(baseline_context)
    hints = index_capture_query_hints(intake, pack_dir=pack_dir)
    results: List[Dict[str, Any]] = []
    exact_ok = 0
    rebuild_ok = 0

    for cap_row in intake.get('captures') or []:
        path = (cap_row.get('path') or '').split('?', 1)[0]
        if not path:
            continue
        snap = _capture_transport_snapshot(cap_row)
        entry: Dict[str, Any] = {
            'capture_index': cap_row.get('capture_index'),
            'path': path,
            'method': cap_row.get('method') or 'POST',
        }

        if style in FORM_BODY_STYLES and snap.get('q') and snap.get('sign'):
            url = f'{host.rstrip("/")}{path}'
            body = urlencode({
                'cid': snap.get('cid', ''),
                'q': snap.get('q', ''),
                'sign': snap.get('sign', ''),
                **({'uid': snap['uid']} if snap.get('uid') else {}),
            })
            tc_exact = {
                'test_id': f'anchor_exact_{cap_row.get("capture_index")}',
                'path': path,
                'method': 'POST',
                'crypto_required': False,
                'anchor_mode': 'capture_exact',
            }
            if mode == 'execute':
                import urllib.request
                try:
                    req = urllib.request.Request(
                        url, data=body.encode(), method='POST',
                        headers={
                            'Content-Type': 'application/x-www-form-urlencoded',
                            'appletEncrypt': 'appletEncrypt',
                        },
                    )
                    with urllib.request.urlopen(req, timeout=20) as resp:
                        body_json = json.loads(resp.read().decode('utf-8', errors='replace'))
                    entry['exact_replay'] = {
                        'ok': body_json.get('code') == 1 or body_json.get('status') == 'SUCCESS',
                        'http_status': resp.status,
                        'code': body_json.get('code'),
                        'status': body_json.get('status'),
                        'msg': body_json.get('msg'),
                    }
                    if entry['exact_replay']['ok']:
                        exact_ok += 1
                except Exception as exc:
                    entry['exact_replay'] = {'ok': False, 'error': str(exc)}
            else:
                entry['exact_replay'] = {'ok': True, 'mode': 'dry_run_skipped'}

        if engine and style in FORM_BODY_STYLES:
            proc = cap_row.get('crypto_processing') or {}
            params: Dict[str, Any] = {}
            plain = (proc.get('decrypted') or {}).get('body_form')
            if plain:
                try:
                    params = json.loads(str(plain))
                except json.JSONDecodeError:
                    pass
            if params:
                built = build_crypto_http_request(
                    engine, cap, method='POST', base_url=host, path=path,
                    params=params, pool=pool,
                )
                sign_ok = snap.get('sign') and (built.get('body_form') or {}).get('sign') == snap.get('sign')
                entry['parametric_rebuild'] = {
                    'sign_matches_capture': bool(sign_ok),
                    'rebuilt_sign': (built.get('body_form') or {}).get('sign'),
                    'captured_sign': snap.get('sign'),
                }
                if sign_ok:
                    rebuild_ok += 1

        if engine and style in HEADER_QUERY_STYLES:
            parity = verify_intake_crypto_parity(
                engine, cap, cap_row, pool, base_url=host or '',
            )
            auth_ok = bool(parity.get('ok'))
            entry['parametric_rebuild'] = {
                'sign_matches_capture': auth_ok,
                'mode': parity.get('mode'),
                'rebuilt_auth': parity.get('rebuilt'),
                'captured_auth': parity.get('expected'),
            }
            if auth_ok:
                rebuild_ok += 1

            if auth_ok and mode == 'execute':
                import urllib.request
                try:
                    proc = cap_row.get('crypto_processing') or {}
                    auth = proc.get('authorization_check') or {}
                    params: Dict[str, Any] = {}
                    for part in str(auth.get('param_str') or '').split('&'):
                        if '=' in part:
                            k, v = part.split('=', 1)
                            params[k] = v
                    session = session_context_from_pool(cap, pool)
                    if cap.md5_aeskey and hasattr(session, 'md5_aeskey'):
                        session.md5_aeskey = cap.md5_aeskey
                    built = build_crypto_http_request(
                        engine, cap, method='GET', base_url=host, path=path,
                        params=params, ctx=session,
                        timespan=int(auth.get('timespan') or 0),
                    )
                    req = urllib.request.Request(
                        built['url'],
                        headers=built.get('headers') or {},
                        method='GET',
                    )
                    with urllib.request.urlopen(req, timeout=20) as resp:
                        body_json = json.loads(resp.read().decode('utf-8', errors='replace'))
                    ok = body_json.get('IsSuccess') is True or body_json.get('ErrorCode') == 0
                    entry['exact_replay'] = {
                        'ok': ok,
                        'http_status': resp.status,
                        'IsSuccess': body_json.get('IsSuccess'),
                        'ErrorCode': body_json.get('ErrorCode'),
                    }
                    if ok:
                        exact_ok += 1
                except Exception as exc:
                    entry['exact_replay'] = {'ok': False, 'error': str(exc)}
            elif auth_ok:
                entry['exact_replay'] = {'ok': True, 'mode': 'dry_run_auth_parity'}
                exact_ok += 1

        if plaintext_direct and not entry.get('exact_replay'):
            plain_result = _replay_plaintext_capture(
                cap_row,
                pack_dir=pack_dir,
                baseline_context=baseline_context,
                host=host,
                hints=hints,
                mode=mode,
            )
            if plain_result:
                entry['exact_replay'] = plain_result
                if plain_result.get('ok'):
                    exact_ok += 1

        results.append(entry)

    report = {
        'schema_version': '1.0.0',
        'generated_at': _utc_now(),
        'mode': mode,
        'transport_style': style,
        'capture_count': len(results),
        'exact_replay_ok': exact_ok,
        'parametric_sign_match': rebuild_ok,
        'baseline_usable': exact_ok > 0 or rebuild_ok > 0 or (plaintext_direct and bool(hints)),
        'results': results,
    }
    out_path = pack_dir / 'anchor_replay_report.json'
    out_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    return report
