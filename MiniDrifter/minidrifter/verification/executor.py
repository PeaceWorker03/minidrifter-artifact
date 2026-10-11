# -*- coding: utf-8 -*-
"""Guarded HTTP executor — dry-run and live execute modes."""
from __future__ import annotations

import hashlib
import json
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from minidrifter.runtime.crypto_replay import process_response_result
from minidrifter.runtime.crypto.registry import load_crypto_capability
from minidrifter.verification.redactor import redact_dict, redact_request_preview
from minidrifter.verification.request_builder import build_request_preview
from minidrifter.verification.sensitive_replay_context_builder import lookup_replay_context


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _hash_text(text: str) -> str:
    return hashlib.sha256(text.encode('utf-8', errors='replace')).hexdigest()[:16]


def execute_test_case(
    test_case: Dict[str, Any],
    *,
    pack_dir: Path,
    baseline_context: Dict[str, Any],
    mode: str = 'dry-run',
    source_dir: Optional[Path] = None,
    base_url: Optional[str] = None,
    timeout_sec: float = 30.0,
    responses_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    test_id = test_case.get('test_id') or 'unknown'
    replay_entry = lookup_replay_context(pack_dir, test_case.get('path') or '')
    preview = build_request_preview(
        test_case, pack_dir=pack_dir, baseline_context=baseline_context,
        source_dir=source_dir, base_url=base_url, replay_entry=replay_entry,
    )

    result: Dict[str, Any] = {
        'test_id': test_id,
        'api_id': test_case.get('api_id'),
        'path': test_case.get('path'),
        'mode': mode,
        'executed': False,
        'timestamp': _utc_now(),
        'build_status': preview.get('build_status'),
        'request_preview_redacted': redact_request_preview(preview),
    }

    if preview.get('build_status') != 'ok':
        result['transport_status'] = None
        result['call_outcome'] = 'build_failed'
        result['errors'] = [preview.get('build_status')]
        return result

    if mode == 'dry-run':
        result['executed'] = False
        result['call_outcome'] = 'dry_run_ok'
        result['transport_status'] = None
        result['would_request'] = {
            'method': preview.get('method'),
            'url_redacted': _redact_url(preview.get('url') or ''),
        }
        return result

    url = preview.get('url') or ''
    headers = preview.get('headers') or {}
    method = (preview.get('method') or 'GET').upper()
    body = preview.get('body')
    started = time.time()

    try:
        if body and method in {'POST', 'PUT', 'PATCH'}:
            data = body.encode('utf-8') if isinstance(body, str) else body
            req = urllib.request.Request(url, data=data, method=method, headers=headers)
        else:
            req = urllib.request.Request(url, method=method, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
            body_bytes = resp.read()
            latency = int((time.time() - started) * 1000)
            body_text = body_bytes.decode('utf-8', errors='replace')
            result.update({
                'executed': True,
                'transport_status': resp.status,
                'latency_ms': latency,
                'response_hash': _hash_text(body_text),
                'response_size': len(body_bytes),
                'response_headers': dict(resp.headers),
            })
            result['call_outcome'] = 'transport_success' if resp.status < 400 else 'transport_error'

            body_json = None
            try:
                body_json = json.loads(body_text)
            except json.JSONDecodeError:
                body_json = {'_raw': body_text[:8000]}

            cap = load_crypto_capability(pack_dir, source_dir=source_dir)
            decrypted = process_response_result(
                body_json, cap, output_dir=pack_dir, source_dir=source_dir,
            )
            result['response_decrypt_mode'] = decrypted.get('decrypt_mode')
            result['produces_fields_hint'] = decrypted.get('produces_fields')
            result['body_json'] = decrypted.get('body_json') or body_json

            if responses_dir:
                responses_dir.mkdir(parents=True, exist_ok=True)
                redacted_path = responses_dir / f'{test_id}.redacted.json'
                redacted_path.write_text(
                    json.dumps(redact_dict(result.get('body_json')), ensure_ascii=False, indent=2),
                    encoding='utf-8',
                )
                result['raw_response_path'] = str(redacted_path.relative_to(pack_dir))

    except urllib.error.HTTPError as e:
        latency = int((time.time() - started) * 1000)
        body_text = e.read().decode('utf-8', errors='replace') if e.fp else ''
        result.update({
            'executed': True,
            'transport_status': e.code,
            'latency_ms': latency,
            'response_hash': _hash_text(body_text),
            'response_size': len(body_text),
            'call_outcome': 'transport_error',
            'errors': [str(e.reason)],
        })
        try:
            result['body_json'] = json.loads(body_text)
        except json.JSONDecodeError:
            result['body_json'] = {'_raw': body_text[:4000]}

    except Exception as e:
        result.update({
            'executed': True,
            'call_outcome': 'transport_error',
            'errors': [str(e)],
        })

    return result


def _redact_url(url: str) -> str:
    if len(url) <= 80:
        return url[:40] + '...' if len(url) > 40 else url
    return url[:30] + '...' + url[-20:]
