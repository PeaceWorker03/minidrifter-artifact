# -*- coding: utf-8 -*-
"""Compress field requirements from target APIs into material packages."""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from minidrifter.core.runtime_taxonomy import is_deferred_obtainability, stage1_user_obtainability
from minidrifter.materials.material_units import (
    MATERIAL_UNITS,
    NEVER_REQUEST_STAGE1,
    material_candidates_for_field,
    stage1_material_priority,
)

SCHEMA_VERSION = '1.0.0'


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _collect_target_api_ids(
    acquisition_plan: Dict[str, Any],
    *,
    stage1_limit: int = 120,
) -> List[str]:
    ids: List[str] = []
    seen: Set[str] = set()
    for key in ('stage_1_target_apis', 'auto_discovery_apis'):
        for brief in acquisition_plan.get(key) or []:
            cid = brief.get('card_id')
            if cid and cid not in seen:
                seen.add(cid)
                ids.append(cid)
            if len(ids) >= stage1_limit and key == 'stage_1_target_apis':
                break
    return ids


def _field_aggregate_key(name: str) -> str:
    return (name or '').strip()


def compress_material_requirements(
    cards_by_id: Dict[str, Dict[str, Any]],
    erd_items: List[Dict[str, Any]],
    acquisition_plan: Dict[str, Any],
    domain_tree: Optional[Dict[str, Any]] = None,
    *,
    stage1_limit: int = 120,
) -> Dict[str, Any]:
    target_ids = _collect_target_api_ids(acquisition_plan, stage1_limit=stage1_limit)
    erd_by_id = {i['card_id']: i for i in erd_items}
    clf_by_id = (domain_tree or {}).get('by_card_id') or {}

    field_stats: Dict[str, Dict[str, Any]] = {}
    material_field_hits: Dict[str, Set[str]] = defaultdict(set)
    material_api_hits: Dict[str, Set[str]] = defaultdict(set)
    material_p0_p1: Dict[str, int] = Counter()

    for cid in target_ids:
        card = cards_by_id.get(cid)
        item = erd_by_id.get(cid) or {}
        if not card:
            continue
        sk = item.get('runtime_requirement_skeleton') or {}
        ranking = card.get('ranking') or {}
        tier = ranking.get('priority_tier') or ''
        domain = (clf_by_id.get(cid) or {}).get('business_domain') or 'unknown'

        for f in sk.get('required_fields') or []:
            fname = _field_aggregate_key(f.get('name'))
            if not fname:
                continue
            stat = field_stats.setdefault(fname, {
                'required_by': 0,
                'roles': set(),
                'obtainability': f.get('obtainability'),
                'domains': set(),
                'material_candidates': set(),
            })
            stat['required_by'] += 1
            stat['roles'].add(f.get('role'))
            stat['domains'].add(domain)
            stat['material_candidates'].update(f.get('material_candidates') or [])

            for mid in f.get('material_candidates') or material_candidates_for_field(
                fname, f.get('role', ''), f.get('obtainability', ''),
            ):
                material_field_hits[mid].add(fname)
                material_api_hits[mid].add(cid)
                if tier in {'P0', 'P1'}:
                    material_p0_p1[mid] += 1

                if tier in {'P0', 'P1'}:
                    material_p0_p1[mid] += 1

    # Boost from target paths, domains, and produces_fields
    for cid in target_ids:
        card = cards_by_id.get(cid) or {}
        path = ((card.get('static') or {}).get('endpoint') or {}).get('path') or ''
        low = path.lower()
        dom = (clf_by_id.get(cid) or {}).get('business_domain') or ''
        if ('device' in low and 'list' in low) or dom == 'device':
            mid = 'first_hop_response_device_list'
            material_api_hits[mid].add(cid)
            material_field_hits[mid].update({'DeviceId', 'TokenCode', 'DeviceName'})
        sk = (erd_by_id.get(cid) or {}).get('runtime_requirement_skeleton') or {}
        for pf in sk.get('produces_fields') or []:
            fname = pf.get('name')
            if not fname:
                continue
            for mid in material_candidates_for_field(
                fname, pf.get('role', ''), pf.get('obtainability', ''),
            ):
                material_field_hits[mid].add(fname)
                material_api_hits[mid].add(cid)

    # Serialize field_stats
    field_requirements = {}
    for fname, stat in sorted(field_stats.items(), key=lambda x: -x[1]['required_by']):
        field_requirements[fname] = {
            'required_by': stat['required_by'],
            'roles': sorted(stat['roles']),
            'obtainability': stat['obtainability'],
            'domains': sorted(stat['domains']),
            'material_candidates': sorted(stat['material_candidates']),
        }

    material_scores: Dict[str, Dict[str, Any]] = {}
    for mid, unit in MATERIAL_UNITS.items():
        covered_fields = material_field_hits.get(mid, set())
        if not covered_fields and unit.get('priority') != 'required':
            continue
        covered_api_count = len(material_api_hits.get(mid, set()))
        obs_levels = set()
        has_o4_o5 = False
        for fn in covered_fields:
            st = field_stats.get(fn) or {}
            obs = st.get('obtainability')
            if obs:
                obs_levels.add(obs)
            if is_deferred_obtainability(obs or ''):
                has_o4_o5 = True

        score = 0.0
        score += covered_api_count * 2
        score += material_p0_p1.get(mid, 0) * 3
        score += float(unit.get('reliability', 0.5)) * 10
        if covered_fields and all(stage1_user_obtainability(o) for o in obs_levels if o):
            score += 20
        if has_o4_o5:
            score -= 20
        if any(is_deferred_obtainability(o) and 'O5' in (o or '') for o in obs_levels):
            score -= 50

        priority = stage1_material_priority(mid)
        if has_o4_o5 and mid not in {
            'first_hop_response_order_list',
            'first_hop_response_address_list',
            'first_hop_response_invoice_list',
        }:
            priority = 'deferred'
        elif has_o4_o5:
            priority = 'deferred'
        elif score >= 40 and unit.get('priority') == 'required':
            priority = 'required'
        elif score >= 25:
            priority = 'recommended'
        else:
            priority = priority if covered_fields else 'deferred'

        material_scores[mid] = {
            'material_id': mid,
            'priority': priority,
            'score': round(score, 2),
            'covered_fields': sorted(covered_fields),
            'covered_api_count': covered_api_count,
            'covered_p0_p1_hits': material_p0_p1.get(mid, 0),
            'reliability': unit.get('reliability'),
            'accepted_formats': unit.get('accepted_formats'),
            'user_instruction': unit.get('user_instruction'),
        }

    buckets = {'required': [], 'recommended': [], 'deferred': []}
    for mid, rec in sorted(material_scores.items(), key=lambda x: -x[1]['score']):
        buckets[rec['priority']].append(rec)

    # Ensure core required materials if any target API needs auth
    if target_ids:
        for core in ('authenticated_request_sample', 'login_or_user_profile_response'):
            if core not in material_scores:
                unit = MATERIAL_UNITS[core]
                material_scores[core] = {
                    'material_id': core,
                    'priority': 'required',
                    'score': 50.0,
                    'covered_fields': unit['covers_fields'][:6],
                    'covered_api_count': len(target_ids),
                    'covered_p0_p1_hits': 0,
                    'reliability': unit['reliability'],
                    'accepted_formats': unit.get('accepted_formats'),
                    'user_instruction': unit.get('user_instruction'),
                }
                buckets['required'].append(material_scores[core])

    # Dedupe buckets
    for key in buckets:
        seen_m = set()
        deduped = []
        for m in buckets[key]:
            if m['material_id'] in seen_m:
                continue
            seen_m.add(m['material_id'])
            deduped.append(m)
        buckets[key] = sorted(deduped, key=lambda x: -x['score'])

    return {
        'schema_version': SCHEMA_VERSION,
        'pack_id': acquisition_plan.get('pack_id'),
        'generated_at': _utc_now(),
        'generator': {'tool': 'MiniDrifter', 'stage': 'material_requirement_compressor'},
        'target_api_count': len(target_ids),
        'target_api_ids': target_ids,
        'field_requirements': field_requirements,
        'material_packages': buckets,
        'never_request_in_stage1': list(NEVER_REQUEST_STAGE1),
        'summary': {
            'distinct_fields': len(field_requirements),
            'required_materials': len(buckets['required']),
            'recommended_materials': len(buckets['recommended']),
            'deferred_materials': len(buckets['deferred']),
        },
    }
