# -*- coding: utf-8 -*-
"""Intelligent baseline intake — universal transport/crypto decision engine."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from minidrifter.runtime.source_dir import resolve_decompile_source_dir
from minidrifter.core.utils import write_json
from minidrifter.materials.baseline_importer import (
    import_baseline_from_directory,
    merge_baseline_runtime_context,
)
from minidrifter.quality.resolvers.host_pool import apply_baseline_host_override
from minidrifter.materials.baseline_intake import build_intake_report, split_multi_raw_http
from minidrifter.runtime.crypto.static_emit import emit_crypto_static_profile
from minidrifter.runtime.crypto.registry import load_crypto_capability


def ensure_crypto_static_profile(
    pack_dir: Path,
    *,
    source_dir: Optional[Path] = None,
    profile_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Always refresh crypto_static_profile.json when source_dir is available."""
    pack_dir = Path(pack_dir)
    source_dir = resolve_decompile_source_dir(pack_dir, source_dir)
    doc = emit_crypto_static_profile(pack_dir, source_dir=source_dir, profile_id=profile_id)
    cap = load_crypto_capability(pack_dir, source_dir=source_dir)
    return {
        'crypto_static_profile': doc,
        'capability': cap.to_dict(),
        'can_replay': cap.can_replay,
        'transport_style': cap.transport_style,
    }


def classify_capture_transport(capture: Dict[str, Any]) -> str:
    """plaintext_only | ciphertext_only | mixed | unknown."""
    layers = capture.get('field_layers') or []
    has_cipher = any(
        (l.get('layer') or '').startswith('crypto_') and l.get('layer') != 'crypto_signature'
        or l.get('layer') in {'crypto_encrypted_query', 'crypto_encrypted_body'}
        for l in layers
    )
    has_sign = any(l.get('layer') == 'crypto_signature' for l in layers)
    has_plain_auth = bool(capture.get('transport_assessment', {}).get('token_present'))
    has_plain_meta = any(
        l.get('layer') in {'plaintext_metadata', 'plaintext_auth_token', 'plaintext_param'}
        for l in layers
    )
    if has_cipher and (has_plain_auth or has_plain_meta):
        return 'mixed'
    if has_cipher or has_sign:
        return 'ciphertext_only'
    if has_plain_auth or has_plain_meta:
        return 'plaintext_only'
    return 'unknown'


def plan_intake_strategy(
    captures: List[Dict[str, Any]],
    *,
    crypto_capability: Dict[str, Any],
) -> Dict[str, Any]:
    """Decide how baseline material should be consumed (universal rules)."""
    can_replay = bool(crypto_capability.get('can_replay'))
    chain = bool(crypto_capability.get('chain_available'))
    profile = crypto_capability.get('profile_id')

    modes = [classify_capture_transport(c) for c in captures]
    has_cipher = any(m in {'ciphertext_only', 'mixed'} for m in modes)
    has_plain = any(m in {'plaintext_only', 'mixed'} for m in modes)

    if not has_cipher:
        strategy = 'plaintext_direct'
        replay_tier = 'header_or_body_plaintext'
        crypto_required = False
        rationale = '抓包无密文 transport，直接提取明文 session/参数字段进入 materialize。'
    elif can_replay:
        strategy = 'crypto_full_pipeline'
        replay_tier = 'parametric_crypto_replay'
        crypto_required = True
        rationale = (
            f'检测到密文且静态 profile={profile} 密钥已就绪，'
            '自动解密 q/AppIdentity/content 并启用 parametric replay。'
        )
    elif chain and not can_replay:
        strategy = 'plaintext_fallback'
        replay_tier = 'plaintext_only_fallback'
        crypto_required = False
        rationale = (
            '检测到密文且静态已索引加密链，但密钥未解析；'
            '仅使用抓包中的明文 session 字段（Token/uid/cid），密文段不参与 replay。'
        )
    elif has_plain:
        strategy = 'plaintext_fallback'
        replay_tier = 'plaintext_only_fallback'
        crypto_required = False
        rationale = '密文 transport 且无静态解密能力；降级为明文字段导入。'
    else:
        strategy = 'blocked'
        replay_tier = 'none'
        crypto_required = False
        rationale = '纯密文抓包且无静态解密链，无法进入 N1 materialize。'

    eligible = sum(1 for c in captures if (c.get('n1_gate') or {}).get('n1_eligible'))
    return {
        'strategy': strategy,
        'replay_tier': replay_tier,
        'crypto_required_for_replay': crypto_required,
        'rationale': rationale,
        'capture_transport_modes': modes,
        'has_ciphertext': has_cipher,
        'has_plaintext': has_plain,
        'static_can_replay': can_replay,
        'static_chain_available': chain,
        'eligible_captures': eligible,
        'total_captures': len(captures),
    }


def run_intelligent_baseline_intake(
    pack_dir: Path,
    raw_text: str,
    *,
    source_dir: Optional[Path] = None,
    source_label: str = 'user_paste',
    source_path: Optional[Path] = None,
    import_after: bool = True,
    materialize_after: bool = False,
    materialize_limit: int = 120,
    refresh_crypto: bool = True,
) -> Dict[str, Any]:
    """Crypto-aware intake: static profile → classify → decrypt or plaintext fallback → import."""
    pack_dir = Path(pack_dir)
    source_dir = resolve_decompile_source_dir(pack_dir, source_dir)
    tmpl_path = pack_dir / 'baseline_material_template.json'
    template = json.loads(tmpl_path.read_text(encoding='utf-8')) if tmpl_path.exists() else {}

    if refresh_crypto or not (pack_dir / 'crypto_static_profile.json').exists():
        crypto_prep = ensure_crypto_static_profile(pack_dir, source_dir=source_dir)
    else:
        from minidrifter.runtime.crypto.registry import load_crypto_capability
        cap = load_crypto_capability(pack_dir, source_dir=source_dir)
        crypto_prep = {
            'crypto_static_profile': json.loads(
                (pack_dir / 'crypto_static_profile.json').read_text(encoding='utf-8')
            ),
            'capability': cap.to_dict(),
            'can_replay': cap.can_replay,
            'transport_style': cap.transport_style,
            'skipped_refresh': True,
        }
    # Infer HAR path from label when caller forgot source_path
    if source_path is None and str(source_label).lower().endswith('.har'):
        cand = Path(source_label)
        if cand.exists():
            source_path = cand
    intake_report = build_intake_report(
        raw_text, pack_dir, template,
        source_label=source_label, source_dir=source_dir, source_path=source_path,
    )
    intake_report['crypto_prep'] = crypto_prep
    intake_report['intake_strategy'] = plan_intake_strategy(
        intake_report.get('captures') or [],
        crypto_capability=intake_report.get('crypto_capability') or {},
    )

    strategy = intake_report['intake_strategy']
    write_json(pack_dir / 'baseline_intake_report.json', intake_report)
    write_json(pack_dir / 'intake_strategy.json', strategy)

    result: Dict[str, Any] = {
        'intake_report': str(pack_dir / 'baseline_intake_report.json'),
        'intake_strategy': strategy,
        'crypto_prep': crypto_prep,
        'capture_count': intake_report.get('capture_count'),
    }

    if strategy.get('strategy') == 'blocked':
        result['status'] = 'blocked'
        result['verdict'] = 'ciphertext_no_decrypt_path'
        return result

    ctx = None
    if import_after:
        mat_dir = pack_dir / 'user_materials'
        mat_dir.mkdir(parents=True, exist_ok=True)
        from minidrifter.materials.har_sequence import (
            har_text_to_capture_inputs,
            looks_like_har,
            har_entry_to_raw_http_chunk,
        )

        if looks_like_har(raw_text):
            har = json.loads(raw_text)
            entries = har.get('log', {}).get('entries') or []
            from minidrifter.materials.har_sequence import filter_har_entries
            filtered = filter_har_entries(entries)
            for i, entry in enumerate(filtered[:50]):
                chunk = har_entry_to_raw_http_chunk(entry)
                (mat_dir / f'har_capture_{i + 1:03d}.http').write_text(chunk, encoding='utf-8')
            if filtered:
                (mat_dir / 'authenticated_request_sample.http').write_text(
                    har_entry_to_raw_http_chunk(filtered[0]), encoding='utf-8',
                )
        else:
            chunks = split_multi_raw_http(raw_text)
            rec = intake_report.get('recommended_file_split') or {}
            written = set()
            for mid, idx in rec.items():
                if idx and 1 <= idx <= len(chunks):
                    (mat_dir / f'{mid}.http').write_text(chunks[idx - 1], encoding='utf-8')
                    written.add(mid)
            if not written and chunks:
                (mat_dir / 'authenticated_request_sample.http').write_text(chunks[0], encoding='utf-8')

        existing_ctx = None
        ctx_path = pack_dir / 'baseline_runtime_context.json'
        if ctx_path.exists():
            existing_ctx = json.loads(ctx_path.read_text(encoding='utf-8'))

        ctx = import_baseline_from_directory(
            mat_dir, template,
            pack_id=template.get('pack_id'),
            intake_report=intake_report,
        )
        ctx = merge_baseline_runtime_context(existing_ctx, ctx)
        ctx['intake_strategy'] = strategy
        ctx['crypto_replay_ready'] = bool(
            strategy.get('static_can_replay') and strategy.get('crypto_required_for_replay')
        )
        crypto_cap = intake_report.get('crypto_capability') or {}
        ctx['transport_style'] = crypto_cap.get('transport_style') or (
            (crypto_prep.get('capability') or {}).get('transport_style')
        )
        if strategy.get('replay_tier') == 'plaintext_only_fallback':
            ctx['crypto_replay_ready'] = False
            ctx['replay_mode'] = 'plaintext_only_fallback'
        elif strategy.get('replay_tier') == 'parametric_crypto_replay':
            ctx['crypto_replay_ready'] = True
            ctx['replay_mode'] = 'parametric_crypto_replay'
        else:
            ctx['replay_mode'] = 'plaintext_direct'

        ctx['n1_materialize_allowed'] = bool(
            (intake_report.get('n1_gate') or {}).get('n1_materialize_allowed')
        )
        try:
            from minidrifter.materials.object_pool_writer import write_baseline_object_artifacts
            write_baseline_object_artifacts(pack_dir, intake_report, ctx=ctx)
        except Exception:
            pass
        write_json(pack_dir / 'baseline_runtime_context.json', ctx)
        if apply_baseline_host_override(pack_dir, ctx):
            from minidrifter.quality.runner import write_static_quality_report
            write_static_quality_report(
                pack_dir,
                phase='post_baseline',
                resolutions_applied=['baseline_host_authoritative', 'baseline_incremental_merge'],
            )
        result['baseline'] = {
            'field_count': ctx.get('field_count'),
            'crypto_replay_ready': ctx.get('crypto_replay_ready'),
            'replay_mode': ctx.get('replay_mode'),
            'n1_materialize_allowed': ctx.get('n1_materialize_allowed'),
        }

    if materialize_after and ctx:
        from minidrifter.business_chain.chain_targets import run_chain_targeted_materialize
        mat_doc = run_chain_targeted_materialize(
            pack_dir, ctx,
            limit=materialize_limit,
            force=True,
            intake_report=intake_report,
        )
        result['materialize'] = mat_doc.get('summary') or {}
        try:
            from minidrifter.business_chain.export import refresh_business_chains_for_pack
            refresh_business_chains_for_pack(pack_dir)
        except Exception:
            pass

    result['status'] = 'ok'
    result['verdict'] = strategy.get('strategy')
    return result
