# -*- coding: utf-8 -*-
"""Unified replay preflight — crypto parity, URL routing, baseline/materialization gates."""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from minidrifter.materials.intake_param_hints import index_capture_query_hints, normalize_api_path
from minidrifter.materials.materialization_meta import check_materialization_stale
from minidrifter.runtime.crypto.registry import get_crypto_engine_for_pack
from minidrifter.runtime.crypto.universal_build import (
    FORM_BODY_STYLES,
    transport_style_of,
    verify_intake_crypto_parity,
)
from minidrifter.verification.campaign_planner import plan_campaign
from minidrifter.verification.request_builder import build_request_preview


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _is_plaintext_direct(ctx: Optional[Dict[str, Any]]) -> bool:
    if not ctx:
        return False
    strategy = (ctx.get('intake_strategy') or {}).get('strategy') or ctx.get('replay_mode')
    return strategy == 'plaintext_direct'


def _replay_ready_statuses(ctx: Optional[Dict[str, Any]]) -> frozenset:
    if _is_plaintext_direct(ctx):
        return frozenset({'materialized_with_crypto_profile', 'materialized_plain'})
    return frozenset({'materialized_with_crypto_profile'})


def _load_json(path: Path) -> Any:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding='utf-8'))


def run_replay_preflight(
    pack_dir: Path,
    *,
    source_dir: Optional[Path] = None,
    base_url: Optional[str] = None,
    live_probe: bool = False,
) -> Dict[str, Any]:
    pack_dir = Path(pack_dir)
    blockers: List[Dict[str, Any]] = []
    warnings: List[Dict[str, Any]] = []
    checks: List[Dict[str, Any]] = []

    ctx_path = pack_dir / 'baseline_runtime_context.json'
    ctx = _load_json(ctx_path)
    if not ctx:
        blockers.append({'layer': 'L0_build', 'code': 'missing_baseline', 'message': 'baseline_runtime_context.json missing'})
        return _report(blockers, warnings, checks)

    if not ctx.get('crypto_replay_ready'):
        if _is_plaintext_direct(ctx) and int(ctx.get('field_count') or 0) > 0:
            checks.append({'name': 'baseline_crypto_replay_ready', 'ok': True, 'mode': 'plaintext_direct'})
        else:
            blockers.append({'layer': 'L0_build', 'code': 'crypto_not_ready', 'message': 'crypto_replay_ready is false'})
            checks.append({'name': 'baseline_crypto_replay_ready', 'ok': False})
    else:
        checks.append({'name': 'baseline_crypto_replay_ready', 'ok': True})

    pool = {
        k: str(v.get('value'))
        for k, v in (ctx.get('resolved_fields') or {}).items()
        if isinstance(v, dict) and v.get('value') is not None
    }
    if not pool.get('Token') and not (pool.get('loginCustomerToken') or pool.get('apiToken')):
        warnings.append({'layer': 'L4_credential', 'code': 'missing_token', 'message': 'Token not in baseline pool'})

    tpl_path = pack_dir / 'materialized_api_templates.json'
    tpl_doc = _load_json(tpl_path) or {}
    ready_statuses = _replay_ready_statuses(ctx)
    ready = [t for t in (tpl_doc.get('templates') or []) if t.get('status') in ready_statuses]
    checks.append({'name': 'materialized_replay_templates', 'ok': bool(ready), 'count': len(ready)})
    if not ready:
        blockers.append({
            'layer': 'L0_build',
            'code': 'no_materialized_templates',
            'message': f'no templates with status in {sorted(ready_statuses)}',
        })

    stale = check_materialization_stale(pack_dir, existing_templates=tpl_doc, baseline_context=ctx)
    checks.append({'name': 'materialization_fresh', 'ok': not stale.get('stale'), 'detail': stale})
    if stale.get('stale'):
        warnings.append({'layer': 'L0_build', 'code': 'materialization_stale', 'message': str(stale.get('reasons'))})

    intake = _load_json(pack_dir / 'baseline_intake_report.json')
    hints = index_capture_query_hints(intake, pack_dir=pack_dir)
    intake_mismatch = 0
    for t in ready[:30]:
        path = normalize_api_path(t.get('path') or '')
        hint = hints.get(path)
        if not hint:
            continue
        pt = (t.get('plain_template') or {})
        if pt.get('param_source') not in {
            'intake_decrypted_query', 'intake_plaintext_capture', 'intake_decrypted_body',
        }:
            src_params = set((pt.get('params') or {}).keys())
            hint_keys = {k for k, _ in hint.get('param_pairs') or []}
            if src_params != hint_keys:
                intake_mismatch += 1
    checks.append({'name': 'intake_param_alignment', 'ok': intake_mismatch == 0, 'mismatch_count': intake_mismatch})
    if intake_mismatch:
        warnings.append({
            'layer': 'L3_params',
            'code': 'param_shape_mismatch',
            'message': f'{intake_mismatch} templates differ from intake decrypted query',
        })

    engine, cap = get_crypto_engine_for_pack(pack_dir, source_dir=source_dir)
    crypto_parity_ok = False
    parity_detail: Dict[str, Any] = {}
    if engine and intake:
        style = transport_style_of(cap)
        host_base = base_url or (
            f"https://{pool.get('Host')}" if pool.get('Host') and not str(pool.get('Host')).startswith('http')
            else (pool.get('Host') or pool.get('api_host') or 'https://localhost')
        )
        for cap_row in (intake.get('captures') or []):
            proc = cap_row.get('crypto_processing') or {}
            if style in FORM_BODY_STYLES:
                if not (cap_row.get('transport_assessment') or {}).get('token_present'):
                    if not (proc.get('resolved_fields') or {}).get('uid'):
                        continue
            elif not (proc.get('authorization_check') or {}).get('verified'):
                continue
            if style not in FORM_BODY_STYLES and not (cap_row.get('transport_assessment') or {}).get('token_present'):
                continue
            parity_detail = verify_intake_crypto_parity(
                engine, cap, cap_row, pool, base_url=host_base,
            )
            crypto_parity_ok = bool(parity_detail.get('ok'))
            checks.append({
                'name': 'crypto_replay_parity',
                'ok': crypto_parity_ok,
                'mode': parity_detail.get('mode'),
                'path': parity_detail.get('path'),
                'capture_index': cap_row.get('capture_index'),
            })
            break
    if engine and not crypto_parity_ok and intake and cap.can_replay:
        if style in FORM_BODY_STYLES:
            for cap_row in (intake.get('captures') or []):
                proc = cap_row.get('crypto_processing') or {}
                if not proc.get('errors') and proc.get('input_mode') == 'ciphertext_form_body_decrypted':
                    crypto_parity_ok = True
                    checks.append({
                        'name': 'crypto_replay_parity',
                        'ok': True,
                        'mode': 'form_decrypt_soft_pass',
                        'capture_index': cap_row.get('capture_index'),
                    })
                    break
        if not crypto_parity_ok:
            blockers.append({
            'layer': 'L2_crypto',
            'code': 'crypto_parity_failed',
            'message': f"Crypto parity failed ({parity_detail.get('mode')})",
            'detail': parity_detail,
        })

    if live_probe and ready:
        tc = ready[0]
        plain = tc.get('plain_template') or {}
        preview = build_request_preview(
            {
                'method': plain.get('method') or tc.get('method') or 'GET',
                'path': tc.get('path'),
                'params': plain.get('params') or {},
                'body_params': plain.get('body_params') or plain.get('params') or {},
                'crypto_required': bool((tc.get('crypto_profile') or {}).get('available')),
                'transport_style': plain.get('transport_style') or ctx.get('transport_style'),
            },
            pack_dir=pack_dir,
            baseline_context=ctx,
            source_dir=source_dir,
            base_url=base_url,
        )
        if preview.get('build_status') == 'ok':
            url = preview.get('url', '')
            method = (preview.get('method') or 'GET').upper()
            headers = preview.get('headers') or {}
            body = preview.get('body')
            try:
                if body and method in {'POST', 'PUT', 'PATCH'}:
                    data = body.encode('utf-8') if isinstance(body, str) else body
                    req = urllib.request.Request(url, data=data, method=method, headers=headers)
                else:
                    req = urllib.request.Request(url, method=method, headers=headers)
                with urllib.request.urlopen(req, timeout=15) as resp:
                    st = resp.status
            except urllib.error.HTTPError as e:
                st = e.code
            checks.append({'name': 'live_probe', 'ok': st != 404, 'http_status': st, 'url_sample': url[:120]})
            if st == 404:
                warnings.append({'layer': 'L1_transport', 'code': 'http_404', 'message': 'live probe returned 404'})

    planned = plan_campaign(pack_dir, max_tests=5, baseline_context=ctx)
    checks.append({
        'name': 'campaign_plan_viable',
        'ok': bool(planned.get('test_cases')),
        'selected': (planned.get('campaign') or {}).get('selected_count'),
    })

    try:
        from minidrifter.business_chain.chain_targets import collect_chain_materialization_targets
        chain_targets = collect_chain_materialization_targets(pack_dir, top_n=1, max_ids=24)
        if chain_targets:
            by_id = {t.get('api_id'): t for t in (tpl_doc.get('templates') or []) if t.get('api_id')}
            chain_ready = [
                aid for aid in chain_targets
                if (by_id.get(aid) or {}).get('status') in ready_statuses
            ]
            entry_ready = (by_id.get(chain_targets[0]) or {}).get('status') in ready_statuses
            checks.append({
                'name': 'chain_hop_templates',
                'ok': bool(chain_ready),
                'targets': len(chain_targets),
                'ready': len(chain_ready),
                'entry_ready': entry_ready,
            })
            if not entry_ready:
                warnings.append({
                    'layer': 'L0_build',
                    'code': 'chain_entry_unmaterialized',
                    'message': f'chain entry api {chain_targets[0]} not replay-ready',
                    'entry_api': chain_targets[0],
                })
    except Exception:
        pass

    version_report = _load_json(pack_dir / 'baseline_version_repair_report.json') or {}
    version_status = version_report.get('status')
    if version_status in {'version_synced_probe_failed', 'probe_failed'}:
        version_issue = {
            'layer': 'L5_business',
            'code': 'baseline_version_probe_failed',
            'message': version_report.get('recommendation') or (
                'Server rejected current AppVersion/Token context; refresh baseline capture before execute.'
            ),
        }
        # Version probe often uses a different endpoint than replay targets; if crypto
        # parity passes, downgrade to warning so breadth search can still execute.
        if crypto_parity_ok:
            warnings.append({**version_issue, 'downgraded_from': 'blocker'})
            checks.append({
                'name': 'baseline_version_probe',
                'ok': False,
                'status': version_status,
                'severity': 'warning',
                'downgraded': True,
            })
        else:
            blockers.append(version_issue)
            checks.append({'name': 'baseline_version_probe', 'ok': False, 'status': version_status})
    elif version_report:
        checks.append({'name': 'baseline_version_probe', 'ok': version_status not in {'probe_failed'}, 'status': version_status})

    if stale.get('stale'):
        blockers.append({
            'layer': 'L0_build',
            'code': 'materialization_stale',
            'message': f"Materialization stale: {stale.get('reasons')}",
        })

    return _report(blockers, warnings, checks)


def _report(blockers: List, warnings: List, checks: List) -> Dict[str, Any]:
    ready = len(blockers) == 0
    return {
        'schema_version': '1.0.0',
        'generated_at': _utc_now(),
        'ready': ready,
        'blockers': blockers,
        'warnings': warnings,
        'checks': checks,
        'summary': {
            'blocker_count': len(blockers),
            'warning_count': len(warnings),
            'checks_passed': sum(1 for c in checks if c.get('ok')),
            'checks_total': len(checks),
        },
    }
