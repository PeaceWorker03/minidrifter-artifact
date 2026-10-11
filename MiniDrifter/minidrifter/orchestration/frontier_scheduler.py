# -*- coding: utf-8
"""Frontier-driven campaign scheduler — consumes coverage_frontier unlocked chains."""
from __future__ import annotations

import json
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from minidrifter.business_chain.chain_run_context import load_chain_registry
from minidrifter.business_chain.chain_intake import validate_uploaded_material_against_chain
from minidrifter.business_chain.high_risk_api_chain_ranker import (
    domain_priority_score,
    field_priority_score,
    is_low_value_path,
    rank_object_flow_chain,
)
from minidrifter.core.utils import write_json
from minidrifter.graph.semantic_workflow_graph import infer_domain_from_path
from minidrifter.materials.intake_param_hints import normalize_api_path

SCHEMA_VERSION = '1.0.0'

HIGH_RISK_DOMAINS = frozenset({
    'order', 'payment', 'member', 'card', 'coupon', 'invoice',
    'address', 'deposit', 'task',
})
MEDIUM_RISK_DOMAINS = frozenset({'vehicle', 'store', 'dept'})
LOW_RISK_DOMAINS = frozenset({'city', 'config', 'banner', 'common', 'dict'})
HIGH_VALUE_ANCHORS = frozenset({
    'orderid', 'cardid', 'couponid', 'invoiceid', 'addressid', 'taskid',
    'memberid', 'paymentid', 'depositid', 'vehicleid',
})
ENVIRONMENT_ANCHORS = frozenset({
    'cityid', 'deptid', 'storeid', 'page', 'size', 'channel', 'channelid',
    'bucketid', 'lat', 'lon', 'version',
})
MAX_SAME_CONSUMER = 3


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _load_json(path: Path) -> Any:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding='utf-8'))


def primary_object_anchor(chain: Dict[str, Any]) -> str:
    of = chain.get('object_flow') or {}
    if of.get('object_field'):
        return str(of['object_field'])
    for f in chain.get('binding_fields') or chain.get('primary_mutation_targets') or []:
        if f and str(f).lower() not in ENVIRONMENT_ANCHORS:
            return str(f)
    for f in chain.get('binding_fields') or []:
        if f:
            return str(f)
    return 'unknown'


def chain_dedupe_key(chain: Dict[str, Any]) -> Tuple[str, str, str, str]:
    consumer = normalize_api_path(
        chain.get('target_path') or chain.get('consumer_api') or '',
    )
    anchor = primary_object_anchor(chain).lower()
    producer = chain.get('entry_path') or chain.get('producer_api') or ''
    producer_domain = chain.get('domain') or infer_domain_from_path(producer) or 'general'
    chain_source = chain.get('chain_source') or 'static_business_chain'
    return (consumer, anchor, producer_domain, chain_source)


def _object_anchor_score(chain: Dict[str, Any]) -> float:
    anchor = primary_object_anchor(chain)
    if str(anchor).lower() in ENVIRONMENT_ANCHORS:
        return 0.12
    return field_priority_score(anchor)


def _chain_source_score(chain: Dict[str, Any]) -> float:
    src = chain.get('chain_source') or ''
    if src == 'runtime_object_flow':
        return 1.0
    if src == 'static_business_chain' or src == 'static_page_event_flow':
        return 0.55
    return 0.25


def _high_risk_api_score(
    chain: Dict[str, Any],
    *,
    risk_by_path: Dict[str, float],
    high_risk_doc: Optional[Dict[str, Any]],
) -> float:
    target = normalize_api_path(chain.get('target_path') or '')
    score = float(risk_by_path.get(target) or 0.0) / 100.0
    if high_risk_doc:
        for row in high_risk_doc.get('chains') or high_risk_doc.get('items') or []:
            if row.get('chain_id') == chain.get('chain_id'):
                score = max(score, float(row.get('rank_score') or row.get('score') or 0) / 100.0)
                break
    tier = chain.get('binding_risk_tier') or ''
    if tier == 'high':
        score = max(score, 0.75)
    elif tier == 'medium':
        score = max(score, 0.45)
    return min(score, 1.0)


def _material_ready_score(pack_dir: Path, chain: Dict[str, Any]) -> float:
    cid = chain.get('chain_id')
    if not cid:
        return 0.0
    v = validate_uploaded_material_against_chain(pack_dir, chain_id=cid)
    if v.get('valid'):
        return 1.0
    if v.get('auth_ok') and not v.get('missing_binding'):
        return 0.65
    if chain.get('runtime_status') == 'runnable':
        return 0.55
    if chain.get('entry_runtime_replay_ready') and chain.get('consumer_runtime_replay_ready'):
        return 0.45
    return 0.2


def _domain_diversity_score(chain: Dict[str, Any]) -> float:
    dom = chain.get('domain') or infer_domain_from_path(chain.get('target_path') or '')
    if dom in HIGH_RISK_DOMAINS:
        return domain_priority_score(dom)
    if dom in MEDIUM_RISK_DOMAINS:
        return domain_priority_score(dom) * 0.65
    if dom in LOW_RISK_DOMAINS:
        return 0.08
    return domain_priority_score(dom) * 0.5


def _environment_field_penalty(chain: Dict[str, Any]) -> float:
    anchor = primary_object_anchor(chain).lower()
    if anchor in ENVIRONMENT_ANCHORS:
        return 3.5
    target = normalize_api_path(chain.get('target_path') or '')
    if is_low_value_path(target) and _object_anchor_score(chain) < 0.35:
        return 1.5
    return 0.0


def _high_value_anchor_bonus(chain: Dict[str, Any]) -> float:
    anchor = primary_object_anchor(chain).lower().replace('_', '')
    if anchor in HIGH_VALUE_ANCHORS:
        return 2.0
    if _object_anchor_score(chain) >= 0.7:
        return 1.2
    return 0.0


def _plane_sensitivity_bonus(pack_dir: Path, chain: Dict[str, Any]) -> Tuple[float, List[str]]:
    """Boost chains whose consumer hits high-sensitivity API planes (P4)."""
    try:
        from minidrifter.classification.api_plane_classifier import plane_sensitivity_for_path
        target = chain.get('target_path') or chain.get('consumer_api') or ''
        sens, planes = plane_sensitivity_for_path(target, pack_dir=pack_dir)
    except Exception:
        return 0.0, []
    bonus = 0.0
    tags: List[str] = []
    if sens >= 0.9:
        bonus = 1.8
        tags.append('plane_sensitivity_high')
    elif sens >= 0.75:
        bonus = 1.1
        tags.append('plane_sensitivity_medium')
    elif sens >= 0.55:
        bonus = 0.4
        tags.append('plane_sensitivity_low')
    for p in planes:
        if p in {
            'user_profile_personal_info', 'realname_verification',
            'account_state_wallet', 'contact_address_invoice',
        }:
            tags.append(f'plane:{p}')
            break
    return bonus, tags


def _safety_penalty(pack_dir: Path, chain: Dict[str, Any]) -> float:
    target = normalize_api_path(chain.get('target_path') or '')
    risk_doc = _load_json(pack_dir / 'binding_risk_candidates.json') or {}
    for row in risk_doc.get('candidates') or []:
        if normalize_api_path(row.get('path') or '') == target:
            if row.get('side_effect_level') in {'S3_destructive', 'S2_write'}:
                return 2.0
            break
    return 0.0


def compute_chain_priority(
    pack_dir: Path,
    chain: Dict[str, Any],
    *,
    risk_by_path: Dict[str, float],
    high_risk_doc: Optional[Dict[str, Any]],
    unverified_bonus: bool = True,
) -> Tuple[float, List[str]]:
    """Return (priority, reason tags) for frontier scheduling."""
    hr = _high_risk_api_score(chain, risk_by_path=risk_by_path, high_risk_doc=high_risk_doc)
    oa = _object_anchor_score(chain)
    mat = _material_ready_score(pack_dir, chain)
    dom = _domain_diversity_score(chain)
    unv = 0.8 if unverified_bonus and not chain.get('_retry_not_m7') else 0.2
    src = _chain_source_score(chain)
    dup_pen = 0.0
    env_pen = _environment_field_penalty(chain)
    safety = _safety_penalty(pack_dir, chain)
    hv_bonus = _high_value_anchor_bonus(chain)
    plane_bonus, plane_tags = _plane_sensitivity_bonus(pack_dir, chain)

    priority = (
        2.0 * hr
        + 1.5 * oa
        + 1.2 * mat
        + 1.0 * dom
        + unv
        + 0.6 * src
        + hv_bonus
        + plane_bonus
        - dup_pen
        - env_pen
        - safety
    )

    reasons: List[str] = []
    if hr >= 0.6:
        reasons.append('high_risk_api_score')
    if oa >= 0.5:
        reasons.append('high_risk_object_anchor')
    if mat >= 0.8:
        reasons.append('materialized')
    if unverified_bonus:
        reasons.append('unverified')
    if chain.get('chain_source') == 'runtime_object_flow':
        reasons.append('runtime_object_flow')
    dom_name = chain.get('domain') or infer_domain_from_path(chain.get('target_path') or '')
    anchor = primary_object_anchor(chain).lower().replace('_', '')
    if dom_name in HIGH_RISK_DOMAINS:
        reasons.append('domain_priority')
    if anchor in HIGH_VALUE_ANCHORS:
        reasons.append('high_value_object_anchor')
    if env_pen >= 2.0:
        reasons.append('environment_anchor_downrank')
    reasons.extend(plane_tags)
    return round(priority, 4), reasons


def _risk_by_path(pack_dir: Path) -> Dict[str, float]:
    doc = _load_json(pack_dir / 'binding_risk_candidates.json') or {}
    out: Dict[str, float] = {}
    for row in doc.get('candidates') or []:
        path = normalize_api_path(row.get('path') or '')
        if path:
            out[path] = max(out.get(path, 0), float(row.get('combined_score') or row.get('rule_score') or 0))
    return out


def _attempted_chain_ids(pack_dir: Path) -> Set[str]:
    batch = _load_json(pack_dir / 'chain_batch_report.json') or {}
    return {r.get('chain_id') for r in batch.get('chain_results') or [] if r.get('chain_id')}


def collect_frontier_candidates(pack_dir: Path) -> List[Dict[str, Any]]:
    """Gather unlocked / unscheduled chains from frontier + unlock matrix + rank plan."""
    pack_dir = Path(pack_dir)
    attempted = _attempted_chain_ids(pack_dir)
    registry = load_chain_registry(pack_dir)
    frontier_doc = _load_json(pack_dir / 'coverage_frontier.json') or {}
    unlock = _load_json(pack_dir / 'baseline_unlock_matrix.json') or {}
    rank_doc = _load_json(pack_dir / 'chain_rank_plan.json') or {}

    seen: Set[str] = set()
    out: List[Dict[str, Any]] = []

    def _add(chain: Dict[str, Any], *, source: str) -> None:
        cid = chain.get('chain_id')
        if not cid or cid in attempted or cid in seen:
            return
        full = dict(registry.get(cid) or chain)
        full.setdefault('chain_id', cid)
        full['_frontier_source'] = source
        seen.add(cid)
        out.append(full)

    for row in (frontier_doc.get('frontier') or {}).get('unlocked_unscheduled_chains') or []:
        _add(row, source='unlocked_unscheduled')

    for row in unlock.get('runnable_chains') or []:
        _add(row, source='baseline_unlock')

    for row in (rank_doc.get('top_chains') or [])[:80]:
        cid = row.get('chain_id')
        if cid and cid not in attempted:
            _add(dict(registry.get(cid) or row), source='rank_plan')

    batch = _load_json(pack_dir / 'chain_batch_report.json') or {}
    for row in batch.get('chain_results') or []:
        cid = row.get('chain_id')
        if not cid or row.get('reached_m7'):
            continue
        chain = dict(registry.get(cid) or {})
        if chain:
            chain['_retry_not_m7'] = True
            _add(chain, source='retry_not_m7')

    return out


def _apply_consumer_dedupe(
    scored: List[Tuple[float, Dict[str, Any], List[str]]],
    *,
    max_chains: int,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Dedupe by consumer+anchor+producer_domain+source; max MAX_SAME_CONSUMER per consumer."""
    consumer_counts: Dict[str, int] = {}
    seen_keys: Set[Tuple[str, str, str, str]] = set()
    selected: List[Dict[str, Any]] = []
    skipped: List[Dict[str, Any]] = []

    for priority, chain, reasons in scored:
        key = chain_dedupe_key(chain)
        consumer = key[0]
        if key in seen_keys:
            skipped.append({'chain_id': chain.get('chain_id'), 'reason': 'duplicate_dedupe_key'})
            continue
        if consumer_counts.get(consumer, 0) >= MAX_SAME_CONSUMER:
            skipped.append({'chain_id': chain.get('chain_id'), 'reason': 'duplicate_consumer_low_priority'})
            continue
        seen_keys.add(key)
        consumer_counts[consumer] = consumer_counts.get(consumer, 0) + 1
        row = dict(chain)
        row['priority'] = priority
        row['scheduler_reasons'] = reasons
        row['dedupe_key'] = {
            'consumer_path': key[0],
            'object_anchor': key[1],
            'producer_domain': key[2],
            'chain_source': key[3],
        }
        selected.append(row)
        if len(selected) >= max_chains:
            break

    return selected, skipped


def _quota_domain(chain: Dict[str, Any]) -> str:
    anchor = primary_object_anchor(chain).lower()
    if anchor in ENVIRONMENT_ANCHORS:
        return anchor.replace('id', '')
    dom = chain.get('domain') or infer_domain_from_path(chain.get('target_path') or '')
    if dom in LOW_RISK_DOMAINS:
        return dom
    return dom or 'general'


def _apply_domain_quota(
    scored: List[Tuple[float, Dict[str, Any], List[str]]],
    *,
    max_chains: int,
    max_domain_share: float = 0.3,
) -> List[Tuple[float, Dict[str, Any], List[str]]]:
    per_domain_cap = max(1, math.ceil(max_chains * max_domain_share))
    domain_counts: Dict[str, int] = {}
    reordered: List[Tuple[float, Dict[str, Any], List[str]]] = []
    deferred: List[Tuple[float, Dict[str, Any], List[str]]] = []

    for item in scored:
        dom = _quota_domain(item[1])
        if domain_counts.get(dom, 0) < per_domain_cap:
            reordered.append(item)
            domain_counts[dom] = domain_counts.get(dom, 0) + 1
        else:
            deferred.append(item)
    return reordered + deferred


def build_campaign_frontier_plan(
    pack_dir: Path,
    *,
    max_chains: int = 40,
    campaign_round: Optional[int] = None,
) -> Dict[str, Any]:
    pack_dir = Path(pack_dir)
    candidates = collect_frontier_candidates(pack_dir)
    risk_by_path = _risk_by_path(pack_dir)
    high_risk_doc = _load_json(pack_dir / 'high_risk_api_chains.json') or {}

    scored: List[Tuple[float, Dict[str, Any], List[str]]] = []
    for chain in candidates:
        pri, reasons = compute_chain_priority(
            pack_dir, chain, risk_by_path=risk_by_path, high_risk_doc=high_risk_doc,
        )
        scored.append((pri, chain, reasons))

    scored.sort(key=lambda x: x[0], reverse=True)
    scored = _apply_domain_quota(scored, max_chains=max_chains)
    selected, skipped = _apply_consumer_dedupe(scored, max_chains=max_chains)

    if campaign_round is None:
        prev = _load_json(pack_dir / 'campaign_frontier_plan.json') or {}
        campaign_round = int(prev.get('campaign_round') or 0) + 1

    plan_rows: List[Dict[str, Any]] = []
    for chain in selected:
        anchor = primary_object_anchor(chain)
        plan_rows.append({
            'chain_id': chain.get('chain_id'),
            'chain_source': chain.get('chain_source'),
            'domain': chain.get('domain') or infer_domain_from_path(chain.get('target_path') or ''),
            'consumer_api': chain.get('target_path') or chain.get('consumer_api'),
            'producer_api': chain.get('entry_path') or chain.get('producer_api'),
            'object_anchor': [anchor] if anchor != 'unknown' else chain.get('binding_fields') or [],
            'priority': chain.get('priority'),
            'reason': chain.get('scheduler_reasons') or [],
            'dedupe_key': chain.get('dedupe_key'),
            'frontier_source': chain.get('_frontier_source'),
            'campaign_phase': 'frontier',
        })

    doc = {
        'schema_version': SCHEMA_VERSION,
        'generated_at': _utc_now(),
        'campaign_round': campaign_round,
        'source': 'coverage_frontier',
        'candidate_chains': len(candidates),
        'selected_chains': plan_rows,
        'skipped_chains': skipped[:50],
        'scheduling_policy': {
            'dedupe_key': 'consumer_path+object_anchor+producer_domain+chain_source',
            'max_same_consumer': MAX_SAME_CONSUMER,
            'max_per_domain_share': 0.3,
            'max_chains': max_chains,
        },
    }
    return doc


def write_campaign_frontier_plan(pack_dir: Path, **kwargs: Any) -> Path:
    pack_dir = Path(pack_dir)
    doc = build_campaign_frontier_plan(pack_dir, **kwargs)
    path = pack_dir / 'campaign_frontier_plan.json'
    write_json(path, doc)
    return path


def select_chains_from_frontier_plan(
    pack_dir: Path,
    plan: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Resolve selected frontier plan rows to full chain documents."""
    pack_dir = Path(pack_dir)
    plan = plan or _load_json(pack_dir / 'campaign_frontier_plan.json') or build_campaign_frontier_plan(pack_dir)
    registry = load_chain_registry(pack_dir)
    out: List[Dict[str, Any]] = []
    for row in plan.get('selected_chains') or []:
        cid = row.get('chain_id')
        if not cid:
            continue
        chain = dict(registry.get(cid) or row)
        chain['campaign_phase'] = row.get('campaign_phase') or 'frontier'
        chain['priority'] = row.get('priority')
        chain['scheduler_reasons'] = row.get('reason')
        out.append(chain)
    return out
