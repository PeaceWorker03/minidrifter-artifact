# -*- coding: utf-8 -*-
"""Per-test feedback for search controller."""
from __future__ import annotations

from typing import Any, Dict, List


def build_test_feedback(
    test_case: Dict[str, Any],
    execution: Dict[str, Any],
    analysis: Dict[str, Any],
    signals: Dict[str, Any],
) -> Dict[str, Any]:
    useful: List[str] = []
    if analysis.get('call_outcome') == 'business_success':
        useful.append('expand_frontier')
    if signals.get('suspicious'):
        useful.append('depth_continue')
    if signals.get('harvest'):
        useful.append('pool_update')
    if analysis.get('failure_class') in {'auth_expired', 'validation_error'}:
        useful.append('material_repair')

    return {
        'test_id': test_case.get('test_id'),
        'api_id': test_case.get('api_id'),
        'path': test_case.get('path'),
        'seed_id': test_case.get('seed_id'),
        'chain_id': test_case.get('chain_id'),
        'mutation_type': test_case.get('mutation_type'),
        'layer': _infer_layer(analysis),
        'outcome': analysis.get('call_outcome'),
        'failure_class': analysis.get('failure_class'),
        'signals': signals,
        'harvest': analysis.get('produced_fields') or [],
        'useful_for': useful,
        'blockers': execution.get('errors') or [],
        'executed': execution.get('executed', True),
    }


def _infer_layer(analysis: Dict[str, Any]) -> str:
    fc = analysis.get('failure_class') or analysis.get('call_outcome')
    mapping = {
        'build_failed': 'L0_build',
        'transport_error': 'L1_transport',
        'transport_url_routing': 'L1_transport',
        'auth_expired': 'L4_credential',
        'validation_error': 'L3_params',
        'app_version_blocked': 'L5_business',
    }
    return mapping.get(fc or '', 'L5_business')
