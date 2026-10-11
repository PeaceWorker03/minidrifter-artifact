# -*- coding: utf-8
"""Rank business chains, entry APIs, and risky hops for single-account verification."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from minidrifter.business_chain.chain_semantic_scorer import (
    chain_semantic_penalties,
    count_entries,
    field_binding_risk_tier,
)
from minidrifter.business_chain.chain_templates import chain_type_label
from minidrifter.business_chain.schema import SCHEMA_VERSION
from minidrifter.materials.intake_param_hints import load_intake_report, normalize_api_path

_SAFE_TYPES = frozenset({'LIST_DETAIL', 'PROFILE_OBJECT', 'GENERAL'})


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _intake_paths(pack_dir: Optional[Path]) -> Set[str]:
    if not pack_dir:
        return set()
    report = load_intake_report(pack_dir) or {}
    out: Set[str] = set()
    for cap in report.get('captures') or []:
        norm = normalize_api_path(cap.get('path') or '')
        if norm and norm != '/':
            out.add(norm)
    return out


def _score_chain(
    chain: Dict[str, Any],
    templates_by_id: Dict[str, Dict[str, Any]],
    intake_paths: Set[str],
    *,
    entry_counts: Dict[str, int],
    total_chains: int,
) -> tuple[float, List[str]]:
    why: List[str] = []
    score = 0.0

    mut_n = int(chain.get('mutation_target_count') or len(chain.get('binding_fields') or []))
    score += min(0.20, mut_n * 0.06)
    if mut_n:
        why.append(f'{mut_n} mutation targets')

    if chain.get('entry_runtime_replay_ready'):
        score += 0.24
        why.append('entry runtime replay ready')
    elif chain.get('entry_request_template_ready'):
        score += 0.14
        why.append('entry request template ready')
    elif chain.get('entry_request_template_partial'):
        score += 0.05
        why.append('entry template partial only')
    elif chain.get('entry_static_constructible'):
        score += 0.03
        why.append('entry static constructible')

    if chain.get('consumer_runtime_replay_ready'):
        score += 0.12
        why.append('consumer runtime replay ready')
    elif chain.get('consumer_constructible'):
        score += 0.06
        why.append('consumer static constructible')

    risk_tier = chain.get('binding_risk_tier') or 'unknown'
    if risk_tier == 'high':
        score += 0.12
        why.append('high-risk binding fields')
    elif risk_tier == 'medium':
        score += 0.04
        why.append('medium-risk binding fields')
    elif risk_tier == 'low':
        score -= 0.08
        why.append('low-risk binding fields penalty')

    entry_path = chain.get('entry_path') or ''
    if normalize_api_path(entry_path) in intake_paths:
        score += 0.16
        why.append('entry has user capture')

    if chain.get('entry_page'):
        score += 0.10
        why.append('entry page evidence')
    elif float(chain.get('entry_page_confidence') or 0) >= 0.5:
        score += 0.05
        why.append('entry page token match')

    ctype = chain.get('chain_type') or ''
    if ctype == 'LIST_DETAIL':
        score += 0.14
        why.append('list-detail semantic chain')
    elif ctype in _SAFE_TYPES:
        score += 0.06
        why.append('read-only chain shape')

    missing = len(chain.get('missing_materials') or [])
    if missing and not chain.get('entry_seed_available'):
        score -= min(0.10, missing * 0.03)
        why.append(f'missing {missing} harvest fields')

    if not chain.get('safe_to_execute', True):
        score -= 0.18
        why.append('write/side-effect penalty')

    sem_delta, sem_why = chain_semantic_penalties(
        chain, entry_counts=entry_counts, total_chains=total_chains,
    )
    score += sem_delta
    why.extend(sem_why)

    score += float(chain.get('confidence') or 0) * 0.08
    return round(max(min(score, 1.0), 0.0), 3), why


def _dedupe_ranked(scored: List[Dict[str, Any]], limit: int) -> List[Dict[str, Any]]:
    seen: Set[str] = set()
    unique: List[Dict[str, Any]] = []
    for item in scored:
        cid = item.get('chain_id') or ''
        if not cid or cid in seen:
            continue
        seen.add(cid)
        unique.append(item)
        if len(unique) >= limit:
            break
    for i, item in enumerate(unique):
        item['rank'] = i + 1
    return unique


def rank_business_chains(
    chains_doc: Dict[str, Any],
    templates_by_id: Dict[str, Dict[str, Any]],
    *,
    pack_dir: Optional[Path] = None,
    cards_by_id: Optional[Dict[str, Dict[str, Any]]] = None,
    limit: int = 25,
) -> Dict[str, Any]:
    intake_paths = _intake_paths(pack_dir)
    all_chains = chains_doc.get('chains') or []
    entry_counts = count_entries(all_chains)
    total_chains = len(all_chains)
    scored: List[Dict[str, Any]] = []

    for chain in all_chains:
        sc, why = _score_chain(
            chain, templates_by_id, intake_paths,
            entry_counts=entry_counts, total_chains=total_chains,
        )
        scored.append({
            'rank': 0,
            'chain_id': chain.get('chain_id'),
            'chain_type': chain.get('chain_type'),
            'chain_type_label': chain_type_label(chain.get('chain_type') or ''),
            'domain': chain.get('domain'),
            'entry_api': chain.get('entry_api'),
            'entry_path': chain.get('entry_path'),
            'entry_page': chain.get('entry_page'),
            'entry_event': chain.get('entry_event'),
            'entry_materialized': chain.get('entry_runtime_replay_ready', False),
            'entry_runtime_replay_ready': chain.get('entry_runtime_replay_ready', False),
            'entry_request_template_ready': chain.get('entry_request_template_ready', False),
            'entry_request_template_partial': chain.get('entry_request_template_partial', False),
            'entry_static_constructible': chain.get('entry_static_constructible', False),
            'consumer_constructible': chain.get('consumer_constructible', False),
            'consumer_runtime_replay_ready': chain.get('consumer_runtime_replay_ready', False),
            'binding_risk_tier': chain.get('binding_risk_tier'),
            'mutation_target_count': chain.get('mutation_target_count', 0),
            'target_hop': chain.get('target_hop'),
            'target_path': chain.get('target_path'),
            'score': sc,
            'why': why,
            'risk_hops': chain.get('risk_hops') or [],
            'required_materials': chain.get('missing_materials') or [],
            'binding_fields': chain.get('binding_fields') or [],
            'recommended_action': 'provide_or_replay_entry',
            'safe_to_execute': chain.get('safe_to_execute', True),
        })

    scored.sort(key=lambda x: x.get('score', 0), reverse=True)
    top_chains = _dedupe_ranked(scored, limit)

    entry_index: Dict[str, Dict[str, Any]] = {}
    for item in top_chains:
        eid = item.get('entry_api')
        if not eid:
            continue
        rec = entry_index.setdefault(eid, {
            'api_id': eid,
            'path': item.get('entry_path'),
            'chain_count': 0,
            'max_score': 0.0,
            'risk_hops': 0,
            'chain_ids': [],
        })
        rec['chain_count'] += 1
        rec['max_score'] = max(rec['max_score'], item.get('score', 0))
        rec['risk_hops'] += len(item.get('risk_hops') or [])
        cid = item.get('chain_id')
        if cid and cid not in rec['chain_ids']:
            rec['chain_ids'].append(cid)

    top_entries = sorted(entry_index.values(), key=lambda x: x['max_score'], reverse=True)[:15]

    risky: List[Dict[str, Any]] = []
    seen_hops: Set[str] = set()
    for item in top_chains:
        for hid in item.get('risk_hops') or []:
            if hid in seen_hops:
                continue
            seen_hops.add(hid)
            risky.append({
                'api_id': hid,
                'chain_id': item.get('chain_id'),
                'score': item.get('score'),
                'binding_fields': item.get('binding_fields'),
                'binding_risk_tier': item.get('binding_risk_tier'),
            })
    risky.sort(key=lambda x: x.get('score', 0), reverse=True)

    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': _utc_now(),
        'verification_scope': 'single_account',
        'top_chains': top_chains,
        'top_entry_apis': top_entries,
        'top_risky_hops': risky[:20],
        'rank_deduped': True,
    }


def load_chain_priority_index(pack_dir: Path) -> Dict[str, Dict[str, Any]]:
    """Index entry_api → chain priority metadata for atomic scheduler."""
    import json
    path = Path(pack_dir) / 'chain_rank_plan.json'
    if not path.exists():
        return {}
    plan = json.loads(path.read_text(encoding='utf-8'))
    index: Dict[str, Dict[str, Any]] = {}
    for item in plan.get('top_chains') or []:
        entry = item.get('entry_api')
        if not entry:
            continue
        rec = index.setdefault(entry, {
            'chain_count': 0,
            'max_score': 0.0,
            'risk_hops': 0,
            'chain_ids': [],
        })
        rec['chain_count'] += 1
        rec['max_score'] = max(rec['max_score'], float(item.get('score') or 0))
        rec['risk_hops'] += len(item.get('risk_hops') or [])
        cid = item.get('chain_id')
        if cid and cid not in rec['chain_ids']:
            rec['chain_ids'].append(cid)
    return index
