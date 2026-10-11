# -*- coding: utf-8 -*-
"""Sync AppVersion/Version in baseline_runtime_context from captures and static source."""
from __future__ import annotations

import json
import re
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

VERSION_HEADER_RE = re.compile(r'^\s*Appversion:\s*(\S+)\s*$', re.I | re.M)
STATIC_VERSION_RE = re.compile(r'\bVersion:\s*"(\d+)"')
STATIC_APP_VERSION_RE = re.compile(r'\bapp_version:\s*"(\d+)"')


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _field_entry(value: str, source: str, *, status: str = 'resolved') -> Dict[str, Any]:
    return {'value': value, 'source': source, 'status': status}


def extract_static_version(source_dir: Path) -> Optional[str]:
    """Read Version from decompiled app.js globalData (generic pattern)."""
    for name in ('app.js', 'app-service.js'):
        path = source_dir / name
        if not path.exists():
            continue
        text = path.read_text(encoding='utf-8', errors='replace')
        for pattern in (STATIC_VERSION_RE, STATIC_APP_VERSION_RE):
            m = pattern.search(text)
            if m:
                return m.group(1)
    return None


def extract_capture_versions(materials_dir: Path) -> List[Tuple[str, str]]:
    """Collect Appversion header values from *.http materials."""
    found: List[Tuple[str, str]] = []
    if not materials_dir.is_dir():
        return found
    for path in sorted(materials_dir.glob('*.http')):
        text = path.read_text(encoding='utf-8', errors='replace')
        for m in VERSION_HEADER_RE.finditer(text):
            found.append((m.group(1), f'{path.name}:Appversion'))
    return found


def collect_version_candidates(
    baseline_context: Dict[str, Any],
    *,
    materials_dir: Optional[Path] = None,
    source_dir: Optional[Path] = None,
    override_version: Optional[str] = None,
) -> Dict[str, Any]:
    """Gather version strings from baseline, captures, and static source."""
    resolved = baseline_context.get('resolved_fields') or {}
    candidates: Dict[str, str] = {}

    for key in ('AppVersion', 'Version'):
        entry = resolved.get(key)
        if isinstance(entry, dict) and entry.get('value'):
            candidates[f'baseline.{key}'] = str(entry['value'])

    if materials_dir:
        for ver, src in extract_capture_versions(materials_dir):
            candidates[src] = ver

    if source_dir and source_dir.is_dir():
        static_ver = extract_static_version(source_dir)
        if static_ver:
            candidates['static.app.js'] = static_ver

    if override_version:
        candidates['cli.override'] = str(override_version)

    numeric = []
    for src, ver in candidates.items():
        if ver.isdigit():
            numeric.append((int(ver), ver, src))

    selected = None
    selected_source = None
    if numeric:
        numeric.sort(reverse=True)
        _, selected, selected_source = numeric[0]

    return {
        'candidates': candidates,
        'selected_version': selected,
        'selected_source': selected_source,
    }


def _probe_one_version(
    *,
    pack_dir: Path,
    source_dir: Optional[Path],
    base_url: str,
    probe_path: str,
    version: str,
    pool: Dict[str, str],
) -> Dict[str, Any]:
    from minidrifter.runtime.crypto.aes_cfb_md5_wrapper import WrapperSessionContext
    from minidrifter.runtime.crypto.registry import get_crypto_engine_for_pack, load_crypto_capability
    from minidrifter.runtime.crypto_replay import process_response_result

    engine, cap = get_crypto_engine_for_pack(pack_dir, source_dir=source_dir)
    if not engine:
        return {'version': version, 'ok': False, 'reason': 'crypto_engine_unavailable'}

    session = WrapperSessionContext.from_baseline_pool(pool)
    session.version = version
    session.source = str(pool.get('AppPlatform') or pool.get('Source') or session.source)
    if cap.md5_aeskey and not session.md5_aeskey:
        session.md5_aeskey = cap.md5_aeskey

    built = engine.build_get_request(base_url.rstrip('/'), probe_path, {}, ctx=session)
    req = urllib.request.Request(built['url'], method='GET', headers=built['headers'])
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            transport_status = resp.status
            raw = json.loads(resp.read().decode('utf-8', errors='replace'))
    except Exception as exc:
        return {'version': version, 'ok': False, 'reason': str(exc)}

    cap2 = load_crypto_capability(pack_dir, source_dir=source_dir)
    proc = process_response_result(
        raw, cap2, output_dir=pack_dir, source_dir=source_dir,
    )
    body = proc.get('body_json') or {}
    is_success = bool(body.get('IsSuccess'))
    return {
        'version': version,
        'ok': is_success,
        'transport_status': transport_status,
        'error_code': body.get('ErrorCode'),
        'message': (body.get('Message') or '')[:120],
    }


def probe_live_versions(
    *,
    pack_dir: Path,
    baseline_context: Dict[str, Any],
    versions: List[str],
    source_dir: Optional[Path] = None,
    base_url: Optional[str] = None,
    probe_path: str = '/Wechat/mobile/CurrentTime',
) -> List[Dict[str, Any]]:
    pool = {
        k: str(v.get('value'))
        for k, v in (baseline_context.get('resolved_fields') or {}).items()
        if isinstance(v, dict) and v.get('value') is not None
    }
    host = base_url or pool.get('Host') or ''
    if host and not host.startswith('http'):
        host = f'https://{host.lstrip("/")}'

    results = []
    for ver in versions:
        results.append(_probe_one_version(
            pack_dir=pack_dir,
            source_dir=source_dir,
            base_url=host,
            probe_path=probe_path,
            version=ver,
            pool=pool,
        ))
        if results[-1].get('ok'):
            break
    return results


def repair_baseline_version(
    baseline_context: Dict[str, Any],
    *,
    materials_dir: Optional[Path] = None,
    source_dir: Optional[Path] = None,
    override_version: Optional[str] = None,
    probe_live: bool = False,
    pack_dir: Optional[Path] = None,
    base_url: Optional[str] = None,
    probe_path: str = '/Wechat/mobile/CurrentTime',
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Return (updated_baseline, repair_report)."""
    info = collect_version_candidates(
        baseline_context,
        materials_dir=materials_dir,
        source_dir=source_dir,
        override_version=override_version,
    )

    selected = info.get('selected_version')
    probe_results: List[Dict[str, Any]] = []
    if probe_live and pack_dir and selected:
        to_try = [selected]
        static = info['candidates'].get('static.app.js')
        if static and static not in to_try:
            to_try.append(static)
        for src, ver in info['candidates'].items():
            if ver not in to_try:
                to_try.append(ver)
        probe_results = probe_live_versions(
            pack_dir=pack_dir,
            baseline_context=baseline_context,
            versions=to_try[:8],
            source_dir=source_dir,
            base_url=base_url,
            probe_path=probe_path,
        )
        for row in probe_results:
            if row.get('ok'):
                selected = row['version']
                info['selected_source'] = f'live_probe:{row["version"]}'
                break

    report: Dict[str, Any] = {
        'schema_version': '1.0.0',
        'repaired_at': _utc_now(),
        'candidates': info['candidates'],
        'selected_version': selected,
        'selected_source': info.get('selected_source'),
        'live_probe': probe_results or None,
        'changed': False,
    }

    ctx = json.loads(json.dumps(baseline_context))
    if not selected:
        report['status'] = 'no_version_candidate'
        return ctx, report

    resolved = ctx.setdefault('resolved_fields', {})
    prev_app = (resolved.get('AppVersion') or {}).get('value')
    prev_ver = (resolved.get('Version') or {}).get('value')
    src_tag = f'version_repair:{info.get("selected_source") or "unknown"}'

    if str(prev_app) != selected:
        resolved['AppVersion'] = _field_entry(selected, src_tag)
        report['changed'] = True
    if str(prev_ver) != selected:
        resolved['Version'] = _field_entry(selected, src_tag)
        report['changed'] = True

    if probe_results and not any(r.get('ok') for r in probe_results):
        report['status'] = 'version_synced_probe_failed'
        report['recommendation'] = (
            'Server rejected all probed AppVersion values (often 1011023). '
            'Refresh baseline capture from the live mini-program: new Token + AppVersion header.'
        )
    elif report['changed']:
        report['status'] = 'repaired'
    else:
        report['status'] = 'already_consistent'

    report['previous'] = {'AppVersion': prev_app, 'Version': prev_ver}
    return ctx, report
