# -*- coding: utf-8
"""Bridge Universal IR ↔ legacy verification engine."""
from __future__ import annotations

from typing import Any, Dict, List, Optional, TYPE_CHECKING

from minidrifter.ir.converters import to_universal_chain_hypothesis, to_universal_failure
from minidrifter.ir.constants import LEGACY_FAILURE_MAP

if TYPE_CHECKING:
    from minidrifter.ir.loader import UniversalIRSession


def enrich_attribution(attribution: Dict[str, Any]) -> Dict[str, Any]:
    fc = attribution.get('failure_class') or 'unknown'
    attribution['universal_failure'] = to_universal_failure(
        fc,
        detail=attribution.get('diagnosis') or '',
        layer=attribution.get('layer') or '',
    )
    return attribution


def legacy_failure_to_universal(legacy_class: str) -> str:
    return LEGACY_FAILURE_MAP.get(legacy_class or '', 'USER_MATERIAL_REQUIRED')


def merge_ir_workflow_candidates(
    rule_result: Dict[str, Any],
    ir_session: Optional['UniversalIRSession'],
    *,
    domain: str,
    available_fields: set,
    templates_by_id: Dict[str, Any],
    exclude_apis: set,
) -> Dict[str, Any]:
    """Inject IR-suggested hops into workflow planner meta."""
    if not ir_session:
        return rule_result
    ir_cands = ir_session.ir_candidates_for_chain(
        domain=domain,
        available_fields=available_fields,
        templates_by_id=templates_by_id,
        exclude_apis=exclude_apis,
    )
    if not ir_cands:
        return rule_result
    existing = rule_result.get('ir_candidates') or []
    seen = {c.get('api_id') for c in existing}
    merged = list(existing)
    for c in ir_cands:
        if c.get('api_id') not in seen:
            merged.append(c)
            seen.add(c.get('api_id'))
    rule_result['ir_candidates'] = merged[:20]
    if rule_result.get('stop') and merged:
        rule_result['ir_frontier_hint'] = merged[0]
    return rule_result


def build_llm_chain_ir_context(
    ir_session: Optional['UniversalIRSession'],
    *,
    chain_id: str,
    seed_api_id: str,
    domain: str,
) -> Dict[str, Any]:
    if not ir_session:
        return {}
    hyp = ir_session.chain_hypothesis_for_seed(seed_api_id)
    card = ir_session.get_api(seed_api_id)
    return {
        'universal_ir': {
            'profile_id': ir_session.profile_id,
            'chain_hypothesis': hyp,
            'seed_api_card': {
                'api_role': (card or {}).get('api_role'),
                'runtime_tier': ((card or {}).get('runtime_tier') or {}).get('tier'),
                'business_domain': (card or {}).get('business_domain'),
            },
            'object_pool_hints': ir_session.object_pool_hints(),
            'open_tickets': len(ir_session.open_ticket_summary()),
        },
    }


def beam_chain_to_universal(chain: Dict[str, Any]) -> Dict[str, Any]:
    return to_universal_chain_hypothesis(
        {
            'chain_id': chain.get('chain_id'),
            'nodes': chain.get('nodes') or [],
            'missing_materials': chain.get('missing_materials') or [],
            'next_action': chain.get('next_action') or 'PROBE_PRODUCER',
            'confidence': chain.get('confidence') or 0.5,
            'status': chain.get('status'),
        },
        domain=chain.get('domain') or 'general',
    )
