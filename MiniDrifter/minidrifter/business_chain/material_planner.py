# -*- coding: utf-8
"""Chain-level material requests — baseline-aware minimal capture plan."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from minidrifter.business_chain.chain_hop_enrichment import (
    build_semantic_user_action,
    resolve_entry_context,
)
from minidrifter.business_chain.chain_templates import chain_type_label
from minidrifter.business_chain.schema import SCHEMA_VERSION
from minidrifter.core.utils import stable_id
from minidrifter.materials.intake_param_hints import normalize_api_path

_DOMAIN_ACTIONS = {
    'member': '请登录测试账号，打开「个人中心/会员中心」页面，并上传该过程抓包。',
    'order': '请登录测试账号，进入「订单列表」并打开任意订单详情，上传抓包。',
    'device': '请登录测试账号，进入「我的设备/设备列表」页面，并上传抓包。',
    'cart': '请登录测试账号，进入「购物车」页面，并上传抓包。',
    'address': '请登录测试账号，进入「地址列表」页面，并上传抓包。',
    'payment': '请登录测试账号，进入支付相关页面（仅浏览，勿完成支付），上传抓包。',
    'general': '请登录测试账号，在小程序中触发该业务页面请求，并上传抓包。',
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _load_json(path: Path) -> Any:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding='utf-8'))


def _baseline_binding_fields(pack_dir: Optional[Path]) -> Set[str]:
    if not pack_dir:
        return set()
    ctx = _load_json(Path(pack_dir) / 'baseline_runtime_context.json') or {}
    intake = _load_json(Path(pack_dir) / 'baseline_intake_report.json') or {}
    fields: Set[str] = set()
    for k, ent in (ctx.get('resolved_fields') or {}).items():
        if isinstance(ent, dict) and ent.get('value') not in (None, ''):
            fields.add(k)
    agg = ((intake or {}).get('decrypted_fields_aggregate') or {}).get('fields') or {}
    for k, v in agg.items():
        if v not in (None, ''):
            fields.add(k)
    return fields


def _baseline_capture_paths(pack_dir: Optional[Path]) -> List[str]:
    if not pack_dir:
        return []
    paths: List[str] = []
    ctx = _load_json(Path(pack_dir) / 'baseline_runtime_context.json') or {}
    for row in ctx.get('capture_index') or []:
        p = row.get('path')
        if p:
            paths.append(normalize_api_path(p))
    intake = _load_json(Path(pack_dir) / 'baseline_intake_report.json') or {}
    for cap in intake.get('captures') or []:
        p = cap.get('path') or cap.get('request_path')
        if p:
            paths.append(normalize_api_path(p))
    return list(dict.fromkeys(paths))


def _alias_index(pack_dir: Optional[Path]) -> Dict[str, Dict[str, Any]]:
    if not pack_dir:
        return {}
    doc = _load_json(Path(pack_dir) / 'runtime_alias_map.json') or {}
    out: Dict[str, Dict[str, Any]] = {}
    for entry in doc.get('aliases') or []:
        static = normalize_api_path(entry.get('static_api') or '')
        if static:
            out[static] = entry
    return out


def _entry_satisfied_by_baseline(
    entry_path: str,
    binding_fields: List[str],
    *,
    baseline_fields: Set[str],
    alias_index: Dict[str, Dict[str, Any]],
    baseline_paths: List[str],
) -> Optional[Dict[str, Any]]:
    """Return satisfaction record if baseline + alias already unlock this entry."""
    norm_entry = normalize_api_path(entry_path)
    alias = alias_index.get(norm_entry)
    runtime_api = normalize_api_path((alias or {}).get('runtime_material_api') or '')
    shared = (alias or {}).get('shared_fields') or []

    need = [f for f in binding_fields if f]
    if need and not all(f in baseline_fields for f in need):
        return None

    if alias and runtime_api:
        matched_capture = runtime_api if runtime_api in baseline_paths else None
        if not matched_capture:
            for bp in baseline_paths:
                if bp == runtime_api or runtime_api.endswith(bp) or bp.endswith(runtime_api):
                    matched_capture = bp
                    break
        if matched_capture or (need and all(f in baseline_fields for f in need)):
            return {
                'static_entry': entry_path,
                'runtime_material_api': (alias or {}).get('runtime_material_api'),
                'matched_capture': matched_capture or runtime_api,
                'alias_type': alias.get('alias_type'),
                'confidence': alias.get('confidence'),
                'shared_fields': shared or need,
                'reason': 'runtime_alias_and_baseline_fields',
            }

    if norm_entry in baseline_paths:
        return {
            'static_entry': entry_path,
            'runtime_material_api': entry_path,
            'matched_capture': norm_entry,
            'shared_fields': need,
            'reason': 'direct_baseline_capture',
        }

    if need and all(f in baseline_fields for f in need):
        return {
            'static_entry': entry_path,
            'runtime_material_api': None,
            'matched_capture': None,
            'shared_fields': need,
            'reason': 'binding_fields_in_baseline_pool',
        }
    return None


def build_chain_material_request_plan(
    rank_plan: Dict[str, Any],
    chains_doc: Dict[str, Any],
    *,
    domain_tree: Optional[Dict[str, Any]] = None,
    pack_dir: Optional[Path] = None,
    cards_by_id: Optional[Dict[str, Dict[str, Any]]] = None,
    limit: int = 12,
) -> Dict[str, Any]:
    """Generate baseline-aware chain-level seed plan — only true gaps, not static entries already covered."""
    chains_by_id = {c['chain_id']: c for c in (chains_doc.get('chains') or []) if c.get('chain_id')}
    requests: List[Dict[str, Any]] = []
    satisfied: List[Dict[str, Any]] = []
    seen_entries: Set[str] = set()
    seen_satisfied_static: Set[str] = set()

    baseline_fields = _baseline_binding_fields(pack_dir)
    baseline_paths = _baseline_capture_paths(pack_dir)
    alias_index = _alias_index(pack_dir)
    has_baseline = bool(baseline_fields) or bool(baseline_paths)

    for ranked in (rank_plan.get('top_chains') or [])[:limit]:
        cid = ranked.get('chain_id')
        chain = chains_by_id.get(cid) or ranked
        entry = ranked.get('entry_api') or chain.get('entry_api')
        if not entry or entry in seen_entries:
            continue
        seen_entries.add(entry)

        fields = ranked.get('binding_fields') or chain.get('binding_fields') or []
        objects = chain.get('objects') or ranked.get('required_materials') or []
        unlock_chains = list(dict.fromkeys(
            x.get('chain_id') for x in (rank_plan.get('top_chains') or [])
            if x.get('entry_api') == entry and x.get('chain_id')
        ))
        entry_path = chain.get('entry_path') or ranked.get('entry_path') or ''

        sat = _entry_satisfied_by_baseline(
            entry_path, fields,
            baseline_fields=baseline_fields,
            alias_index=alias_index,
            baseline_paths=baseline_paths,
        ) if has_baseline else None

        if sat and normalize_api_path(entry_path) not in seen_satisfied_static:
            seen_satisfied_static.add(normalize_api_path(entry_path))
            satisfied.append({
                **sat,
                'entry_api': entry,
                'unlocks_chains': unlock_chains[:12],
                'binding_fields': fields[:6],
            })
            continue

        entry_ctx = resolve_entry_context(
            pack_dir, entry_path, cards_by_id=cards_by_id, api_id=entry,
        )
        if chain.get('entry_page'):
            entry_ctx['entry_page'] = chain.get('entry_page')
        if chain.get('entry_event'):
            entry_ctx['entry_event'] = chain.get('entry_event')
        expected_fields = list(dict.fromkeys(
            (chain.get('expected_response_fields') or [])
            + (entry_ctx.get('expected_response_fields') or [])
            + objects[:6] + fields[:4]
        ))[:8]
        rid = stable_id('need', entry, 'seed')
        requests.append({
            'request_id': rid,
            'priority': 'high' if ranked.get('rank', 99) <= 3 else 'medium',
            'material_type': 'chain_seed_capture',
            'account': 'A',
            'target_fields': objects[:6],
            'binding_fields': fields[:6],
            'expected_response_fields': expected_fields,
            'entry_page': entry_ctx.get('entry_page'),
            'entry_event': entry_ctx.get('entry_event'),
            'entry_page_evidence': entry_ctx.get('entry_page_evidence'),
            'entry_event_evidence': entry_ctx.get('entry_event_evidence'),
            'page_label': entry_ctx.get('page_label'),
            'recommended_user_action': build_semantic_user_action(chain, entry_ctx),
            'recommended_api_roles': [chain.get('chain_type') or 'entry'],
            'example_paths': [entry_path],
            'why_needed': (
                f'链入口可解锁 {len(unlock_chains)} 条业务链；'
                f'类型 {chain_type_label(chain.get("chain_type") or "")}；'
                f'变异字段 {", ".join(fields[:4]) or "待从响应 harvest"}；'
                f'runtime_ready={ranked.get("entry_runtime_replay_ready", False)} '
                f'partial={ranked.get("entry_request_template_partial", False)}'
            ),
            'unlocks': {
                'chains': unlock_chains[:8],
                'risky_hops': ranked.get('risk_hops') or [],
                'fields': objects[:6],
            },
            'minimum': ranked.get('rank', 99) <= 5,
            'safe_to_capture': chain.get('safe_to_execute', True),
            'entry_api': entry,
            'chain_id': cid,
            'redaction_policy': {
                'can_redact': ['name', 'phone', 'address', 'nickName'],
                'must_keep': ['path', 'method', 'headers', 'field names', 'object ids', 'status code'],
            },
        })

    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': _utc_now(),
        'verification_scope': 'single_account',
        'request_count': len(requests),
        'requests': requests,
        'satisfied_by_baseline': satisfied,
        'satisfied_count': len(satisfied),
        'still_needed_count': len(requests),
        'baseline_aware': has_baseline,
        'note': (
            'Baseline-aware plan: satisfied_by_baseline lists captures already unlocking static entries; '
            'requests lists only remaining gaps (not per-hop).'
        ),
    }
