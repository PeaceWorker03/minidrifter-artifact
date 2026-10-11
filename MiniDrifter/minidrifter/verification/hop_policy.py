# -*- coding: utf-8 -*-
"""Hop execution policy — skip, param inheritance, material-backed passthrough."""
from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, List, Optional, Set, Set

from minidrifter.verification.chain_object_pool import GLOBAL_CONTEXT_FIELDS

HOP_SKIPPED = 'hop_skipped'
_PASSTHROUGH_OUTCOMES = frozenset({
    'business_state_blocked', 'validation_error', 'business_empty',
    'transport_success',
})
_MATERIAL_BACKED_OUTCOMES = frozenset({
    'business_empty', 'transport_success', 'business_state_blocked',
})

_FLOW_PARAM_HINTS = frozenset({
    'entrance', 'scenetype', 'cityid', 'deptbtnflag', 'hotcarsflag',
    'bucketidlist', 'pickupcityid', 'returncityid', 'pickupdeptid',
})


def _field_value(
    field: str,
    baseline_context: Dict[str, Any],
    intake_report: Optional[Dict[str, Any]],
) -> Optional[str]:
    agg = ((intake_report or {}).get('decrypted_fields_aggregate') or {}).get('fields') or {}
    if field in agg and agg[field] not in (None, ''):
        return str(agg[field])
    resolved = baseline_context.get('resolved_fields') or {}
    ent = resolved.get(field) or resolved.get(field.lower())
    if isinstance(ent, dict) and ent.get('value') not in (None, ''):
        return str(ent['value'])
    return None


def collect_baseline_business_fields(
    baseline_context: Dict[str, Any],
    intake_report: Optional[Dict[str, Any]] = None,
) -> Dict[str, str]:
    """All non-global business fields available from baseline captures."""
    out: Dict[str, str] = {}
    agg = ((intake_report or {}).get('decrypted_fields_aggregate') or {}).get('fields') or {}
    for k, v in agg.items():
        if v not in (None, '') and k.lower() not in GLOBAL_CONTEXT_FIELDS:
            out[k] = str(v)
    for k, ent in (baseline_context.get('resolved_fields') or {}).items():
        if k.lower() in GLOBAL_CONTEXT_FIELDS:
            continue
        if isinstance(ent, dict) and ent.get('value') not in (None, ''):
            out[k] = str(ent['value'])
    return out


def inherit_baseline_params(
    test_case: Dict[str, Any],
    hop: Dict[str, Any],
    *,
    baseline_context: Dict[str, Any],
    intake_report: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Overlay baseline capture fields onto request params missing from template."""
    tc = deepcopy(test_case)
    pool = collect_baseline_business_fields(baseline_context, intake_report)
    if not pool:
        return tc

    need: Set[str] = set(hop.get('consumes') or hop.get('requires') or [])
    for f in pool:
        if f.lower() in _FLOW_PARAM_HINTS:
            need.add(f)

    def _overlay(bag: Dict[str, Any]) -> Dict[str, Any]:
        out = dict(bag or {})
        for field in need:
            val = pool.get(field)
            if val is None:
                for pk, pv in pool.items():
                    if pk.lower() == field.lower():
                        val = pv
                        break
            if val is None:
                continue
            if field not in out:
                out[field] = val
                continue
            matched = next((k for k in out if k.lower() == field.lower()), None)
            if matched is None:
                out[field] = val
            elif str(out.get(matched) or '').startswith('$'):
                out[matched] = val
        return out

    tc['params'] = _overlay(tc.get('params') or {})
    tc['body_params'] = _overlay(tc.get('body_params') or {})
    tc['query_params'] = _overlay(tc.get('query_params') or {})
    tc['baseline_param_inherited'] = sorted(need & set(pool.keys()))
    return tc


def should_skip_hop(
    hop: Dict[str, Any],
    chain_pool: Any,
    chain_doc: Dict[str, Any],
    *,
    hop_index: int,
    total_hops: int,
    templates_by_id: Optional[Dict[str, Any]] = None,
) -> Optional[str]:
    """Skip non-mutating intermediate hops when object pool already satisfies consumes."""
    templates_by_id = templates_by_id or {}
    api_id = hop.get('api_id') or ''
    template = templates_by_id.get(api_id)

    if hop.get('role') == 'producer':
        binding = chain_doc.get('binding_fields') or chain_doc.get('objects') or []
        if binding and not chain_pool.missing_for_hop({'consumes': binding, 'requires': binding}):
            produces = hop.get('produces') or binding
            if all(_field_match(f, set(chain_pool.objects.keys())) for f in produces):
                if not template:
                    return 'baseline_seed_satisfies_producer'
                return None
        return None
    if hop.get('api_id') == chain_doc.get('target_hop'):
        return None
    if hop_index >= total_hops - 1:
        return None
    if hop.get('mutation_points'):
        return None
    if chain_pool.missing_for_hop(hop):
        return None
    return 'pool_satisfied_intermediate_skip'


def _field_match(required: str, available: Set[str]) -> bool:
    r = required.lower()
    for a in available:
        if a.lower() == r:
            return True
    return False


def skip_hop_result(
    hop: Dict[str, Any],
    *,
    hop_index: int,
    reason: str,
) -> Dict[str, Any]:
    return {
        'hop_index': hop_index,
        'api_id': hop.get('api_id'),
        'path': hop.get('path'),
        'role': hop.get('role'),
        'status': HOP_SKIPPED,
        'diagnosis': {'reason': reason, 'skipped': True},
        'executed': False,
        'harvested': [],
    }


def try_material_backed_hop(
    hop: Dict[str, Any],
    *,
    api_id: str,
    chain_pool: Any,
    baseline_context: Dict[str, Any],
    intake_report: Optional[Dict[str, Any]],
    material_validation: Optional[Dict[str, Any]],
    execution: Dict[str, Any],
    analysis: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    """Harvest from baseline when live hop returns empty/blocked but capture has fields."""
    if material_validation is not None and not material_validation.get('valid'):
        if hop.get('role') == 'producer':
            return None
    outcome = analysis.get('call_outcome') or execution.get('call_outcome')
    if outcome not in _MATERIAL_BACKED_OUTCOMES:
        return None

    produces = hop.get('produces') or []
    values: Dict[str, str] = {}
    for field in produces:
        v = _field_value(field, baseline_context, intake_report)
        if v:
            values[field] = v

    if hop.get('role') == 'producer' and produces and all(f in values for f in produces):
        chain_pool.harvest(api_id, produces, values)
        return {
            'material_backed': True,
            'material_source': 'baseline_intake',
            'harvested_fields': produces,
            'live_call_outcome': outcome,
        }

    if chain_pool.missing_for_hop(hop):
        return None
    if outcome in _PASSTHROUGH_OUTCOMES:
        return {
            'material_backed': True,
            'material_source': 'pool_satisfied_passthrough',
            'pool_fields': list(chain_pool.objects.keys()),
            'live_call_outcome': outcome,
        }
    return None


def is_success_status(status: str) -> bool:
    return status in {'business_success', HOP_SKIPPED}
