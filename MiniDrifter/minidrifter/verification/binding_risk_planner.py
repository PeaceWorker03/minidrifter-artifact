# -*- coding: utf-8 -*-
"""Binding-risk planner — rank APIs for identity/credential drift probing (rule + optional LLM)."""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from minidrifter.core.utils import write_json
from minidrifter.materials.intake_param_hints import load_intake_report, normalize_api_path
from minidrifter.quality.sensitive_surface import (
    INTENT_BINDING,
    INTENT_PII_SCOPE,
    INTENT_PII_SUBMIT,
    classify_sensitive_surface,
    classify_sensitive_surface_from_card,
    pii_path_match,
)
from minidrifter.reasoning.pack_loader import load_pack, load_rule_erd

EXTERNAL_SDK_PATH_RE = re.compile(
    r'^/(geocoding|place|reverse_geocoding|telematics|direction|distance|'
    r'assistant|restapi/amap|v3/weather|staticmap|maps/api)',
    re.I,
)
SENSITIVE_PATH_RE = re.compile(
    r'(personal|profile|user/|customer|order|address|cart|money|score|'
    r'invoice|member|account|remain|detail|collect|submit|sign|'
    r'deposit|pledge|auth)',
    re.I,
)
IDENTITY_PARAM_RE = re.compile(
    r'^(user_?id|customer_?id|login_?customer_?id|member_?id|openid|platform_?user_?id|'
    r'order_?id|from_?customer_?id)$',
    re.I,
)
OBJECT_PARAM_RE = re.compile(
    r'^(order_?id|device_?id|shop_?id|invoice_?id|cart_?id|goods_?id|member_?id)$',
    re.I,
)

BINDING_INTENTS = frozenset({INTENT_BINDING, INTENT_PII_SCOPE})
HIGH_RISK_INTENTS = BINDING_INTENTS


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _load_json(path: Path, default: Any = None) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding='utf-8'))


def is_external_sdk_path(path: str) -> bool:
    p = (path or '').split('?', 1)[0]
    return bool(EXTERNAL_SDK_PATH_RE.search(p))


def _card_path(card: Dict[str, Any]) -> str:
    return ((card.get('static') or {}).get('endpoint') or {}).get('path') or ''


def _card_method(card: Dict[str, Any]) -> str:
    return ((card.get('static') or {}).get('http') or {}).get('method') or 'GET'


def _card_params(card: Dict[str, Any]) -> List[Dict[str, Any]]:
    return ((card.get('bindings') or {}).get('params') or [])


def _erd_by_card(erd_items: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    return {i.get('card_id'): i for i in erd_items if i.get('card_id')}


def _materialized_lookup(pack_dir: Path) -> Dict[str, Dict[str, Any]]:
    doc = _load_json(pack_dir / 'materialized_api_templates.json') or {}
    out: Dict[str, Dict[str, Any]] = {}
    for t in doc.get('templates') or []:
        aid = t.get('api_id')
        if aid:
            out[aid] = t
    for r in doc.get('ready_for_replay') or []:
        aid = r.get('api_id')
        if aid and aid in out:
            out[aid]['replay_ready'] = True
    return out


def _intake_paths(pack_dir: Path) -> Set[str]:
    paths: Set[str] = set()
    report = load_intake_report(pack_dir) or {}
    for cap in report.get('captures') or []:
        norm = normalize_api_path(cap.get('path') or '')
        if norm and norm != '/':
            paths.add(norm)
    return paths


def _materialized_ok(mat: Optional[Dict[str, Any]]) -> bool:
    return bool(mat and mat.get('status') in {'materialized_plain', 'materialized_with_crypto_profile'})


def probe_eligible_for_candidate(
    card: Dict[str, Any],
    *,
    materialized: Optional[Dict[str, Any]] = None,
    surface: Optional[Dict[str, Any]] = None,
) -> bool:
    """Materialized read-surface APIs are probe-eligible; PII write/upload flows are not."""
    if not _materialized_ok(materialized):
        return False
    surf = surface or classify_sensitive_surface_from_card(card)
    if surf.get('probe_blocked'):
        return False
    side = ((card.get('replay') or {}).get('side_effect') or {}).get('category') or ''
    if side in {'state_changing', 'write', 'S2_state_changing'} and surf.get('flow_kind') == 'write':
        return False
    return True


def rule_binding_risk_score(
    card: Dict[str, Any],
    erd_item: Optional[Dict[str, Any]],
    *,
    materialized: Optional[Dict[str, Any]] = None,
    intake_anchor: bool = False,
    crypto_profile: Optional[Dict[str, Any]] = None,
) -> Tuple[float, List[str], Dict[str, Any]]:
    path = _card_path(card)
    signals: List[str] = []
    score = 0.0

    if is_external_sdk_path(path):
        return 0.0, ['external_sdk_excluded'], {'pii_surface': False}

    kind = (card.get('provenance') or {}).get('card_kind')
    if kind != 'operation':
        return 0.0, ['not_operation'], {'pii_surface': False}

    side = ((card.get('replay') or {}).get('side_effect') or {}).get('category') or ''
    params = _card_params(card)
    param_names = [p.get('name') for p in params if p.get('name')]
    surface = classify_sensitive_surface(
        path,
        method=_card_method(card),
        side_effect_category=side,
        param_names=param_names,
    )

    intent = (erd_item or {}).get('verification_intent') or ''
    if intent == INTENT_BINDING:
        score += 28.0
        signals.append('binding_check_intent')
    elif intent == INTENT_PII_SCOPE:
        score += 22.0
        signals.append('pii_scope_check_intent')
    elif intent == INTENT_PII_SUBMIT:
        score += 8.0
        signals.append('pii_submission_intent')
    elif (card.get('ranking') or {}).get('validation_value') in {'high', 'medium'}:
        score += 12.0
        signals.append('validation_value_medium_high')

    ranking = card.get('ranking') or {}
    tier = ranking.get('priority_tier') or ''
    if tier in {'P0', 'P1', 'P2'}:
        score += {'P0': 8, 'P1': 6, 'P2': 4}.get(tier, 0)

    identity_fields = [p.get('name') for p in params if p.get('name') and IDENTITY_PARAM_RE.match(str(p.get('name')))]
    object_fields = [p.get('name') for p in params if p.get('name') and OBJECT_PARAM_RE.match(str(p.get('name')))]
    if identity_fields:
        score += min(15.0, 5.0 * len(identity_fields))
        signals.append('identity_params:' + ','.join(identity_fields[:4]))
    if object_fields and identity_fields:
        score += 10.0
        signals.append('subject_and_object_params')
    ambiguous = [p.get('name') for p in params if p.get('ambiguity')]
    if ambiguous:
        score += min(8.0, 2.0 * len(ambiguous))
        signals.append('param_role_ambiguity')

    if side in {'read_only', 'query_like', 'S0_read_only', 'S1_query_like_post'}:
        score += 6.0
        signals.append('read_side_effect')
    elif side in {'state_changing', 'write', 'S2_state_changing'}:
        score -= 15.0
        signals.append('write_side_effect_penalty')

    if SENSITIVE_PATH_RE.search(path):
        score += 10.0
        signals.append('sensitive_business_path')

    if surface.get('pii_surface'):
        if surface.get('flow_kind') == 'read':
            score += 14.0
            signals.append('pii_read_surface')
            if surface.get('pii_params'):
                score += min(10.0, 3.0 * len(surface['pii_params']))
                signals.append('pii_params:' + ','.join(surface['pii_params'][:4]))
        elif surface.get('flow_kind') == 'write':
            score += 6.0
            signals.append('pii_write_surface')
        else:
            score += 10.0
            signals.append('pii_surface_unknown_flow')

    cp = crypto_profile or {}
    if cp.get('profile_id') and 'sign' in str(cp.get('profile_id', '')).lower():
        if identity_fields:
            score += 8.0
            signals.append('client_sign_with_identity_params')

    if _materialized_ok(materialized):
        score += 20.0
        signals.append('materialized_replay')
    elif ((card.get('replay') or {}).get('readiness') or {}).get('status') == 'ready':
        score += 5.0
        signals.append('replay_ready_static')

    if intake_anchor:
        score += 25.0
        signals.append('baseline_capture_anchor')

    oracle = ((card.get('replay') or {}).get('oracle_hints') or {}).get('confidence')
    if oracle is not None and float(oracle) < 0.65:
        score += 5.0
        signals.append('weak_oracle_hint')

    return round(max(score, 0.0), 2), signals, surface


def build_binding_risk_plan(
    pack_dir: Path,
    *,
    with_llm: bool = False,
    dry_run: bool = False,
    limit: int = 25,
    llm_top_n: int = 15,
) -> Dict[str, Any]:
    """Score all binding-relevant APIs; write binding_risk_candidates.json."""
    pack_dir = Path(pack_dir)
    pack = load_pack(pack_dir)
    erd_map = _erd_by_card(load_rule_erd(pack_dir))
    mat_map = _materialized_lookup(pack_dir)
    intake_paths = _intake_paths(pack_dir)
    crypto_profile = _load_json(pack_dir / 'crypto_static_profile.json') or {}

    candidates: List[Dict[str, Any]] = []
    excluded_external = 0
    for card in pack['cards']:
        path = _card_path(card)
        api_id = card.get('card_id') or ''
        if not path or not api_id:
            continue
        if is_external_sdk_path(path):
            excluded_external += 1
            continue

        erd_item = erd_map.get(api_id)
        mat = mat_map.get(api_id)
        cap_norm = normalize_api_path(path)
        rule_score, signals, surface = rule_binding_risk_score(
            card,
            erd_item,
            materialized=mat,
            intake_anchor=cap_norm in intake_paths,
            crypto_profile=crypto_profile,
        )
        if rule_score <= 0 and intent_not_binding(erd_item, card):
            continue

        mat_ok = _materialized_ok(mat)
        candidates.append({
            'api_id': api_id,
            'path': path,
            'method': _card_method(card),
            'priority_tier': (card.get('ranking') or {}).get('priority_tier'),
            'verification_intent': (erd_item or {}).get('verification_intent'),
            'rule_score': rule_score,
            'risk_signals': signals,
            'risk_surface': {
                'pii_surface': surface.get('pii_surface'),
                'pii_flow_kind': surface.get('flow_kind'),
                'probe_style': surface.get('probe_style'),
            },
            'materialized': mat_ok,
            'replay_ready': bool(mat and mat.get('replay_ready')),
            'intake_anchor': cap_norm in intake_paths,
            'probe_eligible': probe_eligible_for_candidate(card, materialized=mat, surface=surface),
        })

    candidates.sort(key=lambda c: c.get('rule_score', 0), reverse=True)
    top_rule = candidates[: max(limit, llm_top_n)]

    llm_meta: Dict[str, Any] = {'used_llm': False, 'status': 'skipped'}
    if with_llm and top_rule:
        try:
            from minidrifter.reasoning.binding_risk_auditor import rerank_binding_risk_batch
            llm_meta = rerank_binding_risk_batch(
                pack_dir, top_rule[:llm_top_n], pack['cards_by_id'], dry_run=dry_run,
            )
            boosts = {r['api_id']: float(r.get('llm_risk_boost') or 0) for r in llm_meta.get('results') or []}
            rationales = {r['api_id']: r.get('rationale') for r in llm_meta.get('results') or []}
            for c in candidates:
                aid = c.get('api_id')
                if aid in boosts:
                    c['llm_risk_boost'] = boosts[aid]
                    c['llm_rationale'] = rationales.get(aid)
                    c['combined_score'] = round(c.get('rule_score', 0) + boosts[aid], 2)
                else:
                    c['combined_score'] = c.get('rule_score', 0)
            candidates.sort(key=lambda x: x.get('combined_score', x.get('rule_score', 0)), reverse=True)
        except Exception as exc:
            llm_meta = {'used_llm': False, 'status': 'error', 'error': str(exc)}
            for c in candidates:
                c['combined_score'] = c.get('rule_score', 0)
    else:
        for c in candidates:
            c['combined_score'] = c.get('rule_score', 0)

    selected = candidates[:limit]
    risk_map = {c['api_id']: c.get('combined_score', 0) for c in selected if c.get('api_id')}

    try:
        from minidrifter.classification.api_plane_classifier import classify_api_card, write_api_plane_index
        for c in candidates:
            card = pack['cards_by_id'].get(c.get('api_id'))
            if not card:
                continue
            plane_row = classify_api_card(card)
            c['api_planes'] = plane_row.get('planes')
            c['primary_plane'] = plane_row.get('primary_plane')
            c['plane_sensitivity'] = plane_row.get('sensitivity_score')
        write_api_plane_index(pack_dir)
    except Exception:
        pass

    doc = {
        'schema_version': '1.1.0',
        'generated_at': _utc_now(),
        'pack_dir': str(pack_dir),
        'source': 'rule+llm_binding_risk_planner' if llm_meta.get('used_llm') else 'rule_binding_risk_planner',
        'summary': {
            'total_cards': len(pack['cards']),
            'candidates_scored': len(candidates),
            'external_excluded': excluded_external,
            'probe_eligible_count': sum(1 for c in selected if c.get('probe_eligible')),
            'pii_surface_count': sum(1 for c in selected if (c.get('risk_surface') or {}).get('pii_surface')),
            'pii_read_probe_eligible_count': sum(
                1 for c in selected
                if c.get('probe_eligible') and (c.get('risk_surface') or {}).get('pii_flow_kind') == 'read'
            ),
            'intake_anchor_count': sum(1 for c in selected if c.get('intake_anchor')),
            'top_score': selected[0].get('combined_score') if selected else 0,
        },
        'llm': llm_meta,
        'candidates': selected,
        'risk_score_by_api_id': risk_map,
    }
    write_json(pack_dir / 'binding_risk_candidates.json', doc)
    return doc


def intent_not_binding(erd_item: Optional[Dict[str, Any]], card: Dict[str, Any]) -> bool:
    intent = (erd_item or {}).get('verification_intent') or ''
    if intent in HIGH_RISK_INTENTS:
        return False
    if intent == INTENT_PII_SUBMIT:
        return False
    vv = (card.get('ranking') or {}).get('validation_value')
    if vv in {'high', 'medium'}:
        return False
    path = _card_path(card)
    if SENSITIVE_PATH_RE.search(path) or pii_path_match(path):
        return False
    surface = classify_sensitive_surface_from_card(card)
    return not surface.get('pii_surface')


def load_binding_risk_scores(pack_dir: Path) -> Dict[str, float]:
    doc = _load_json(Path(pack_dir) / 'binding_risk_candidates.json') or {}
    raw = doc.get('risk_score_by_api_id') or {}
    return {str(k): float(v) for k, v in raw.items()}


def risk_boost_for_api(pack_dir: Path, api_id: str, *, max_boost: float = 45.0) -> float:
    scores = load_binding_risk_scores(pack_dir)
    if not scores or api_id not in scores:
        return 0.0
    top = max(scores.values()) or 1.0
    return round(max_boost * (scores[api_id] / top), 2)
