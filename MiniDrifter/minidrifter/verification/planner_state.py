# -*- coding: utf-8 -*-
"""Campaign planner state — frontier, coverage, next actions."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import json
from pathlib import Path

from minidrifter.verification import SCHEMA_VERSION

_LADDER_PATH = Path(__file__).resolve().parent / 'packs' / 'replay_diagnostic_ladder.json'


def _load_diagnostic_ladder() -> Dict[str, Any]:
    if not _LADDER_PATH.exists():
        return {}
    return json.loads(_LADDER_PATH.read_text(encoding='utf-8'))


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def init_planner_state(
    campaign: Dict[str, Any],
    *,
    max_tests: int = 100,
) -> Dict[str, Any]:
    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': _utc_now(),
        'campaign_mode': campaign.get('campaign_mode') or 'normal',
        'pack_id': campaign.get('pack_id'),
        'confirmed_objects': {},
        'tested_apis': [],
        'successful_apis': [],
        'failed_apis': [],
        'frontier_apis': list(campaign.get('test_case_ids') or []),
        'blocked_apis': [],
        'findings': [],
        'coverage': {
            'api_tested': 0,
            'api_success': 0,
            'api_failed': 0,
            'domains_tested': [],
            'mutation_types': ['M0_baseline_replay'],
        },
        'budget': {
            'max_tests': max_tests,
            'used_tests': 0,
        },
    }


def update_planner_state(
    state: Dict[str, Any],
    test_case: Dict[str, Any],
    execution: Dict[str, Any],
    analysis: Dict[str, Any],
) -> Dict[str, Any]:
    api_id = test_case.get('api_id')
    test_id = test_case.get('test_id')
    domain = test_case.get('domain') or 'general'

    if api_id and api_id not in state['tested_apis']:
        state['tested_apis'].append(api_id)

    outcome = analysis.get('call_outcome')
    if outcome in {'business_success', 'dry_run_ok', 'transport_success'}:
        if api_id and api_id not in state['successful_apis']:
            state['successful_apis'].append(api_id)
    else:
        if api_id and api_id not in state['failed_apis']:
            state['failed_apis'].append(api_id)

    frontier = state.get('frontier_apis') or []
    if test_id in frontier:
        frontier.remove(test_id)
    state['frontier_apis'] = frontier

    cov = state.setdefault('coverage', {})
    cov['api_tested'] = len(state['tested_apis'])
    cov['api_success'] = len(state['successful_apis'])
    cov['api_failed'] = len(state['failed_apis'])
    domains = set(cov.get('domains_tested') or [])
    domains.add(domain)
    cov['domains_tested'] = sorted(domains)

    state['budget']['used_tests'] = int(state['budget'].get('used_tests') or 0) + 1
    state['generated_at'] = _utc_now()
    return state


def build_next_action_plan(
    state: Dict[str, Any],
    analyses: List[Dict[str, Any]],
    *,
    object_pool: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    actions: List[Dict[str, Any]] = []
    failure_hist: Dict[str, int] = {}
    for a in analyses:
        fc = a.get('failure_class') or a.get('call_outcome')
        if fc:
            failure_hist[fc] = failure_hist.get(fc, 0) + 1

    if failure_hist.get('auth_expired', 0) >= 2:
        actions.append({
            'action': 'refresh_baseline',
            'reason': 'auth_expired dominates results',
            'priority': 'P0',
        })

    if failure_hist.get('validation_error', 0) >= 2:
        actions.append({
            'action': 'schema_repair',
            'reason': 'validation_error dominates results',
            'priority': 'P1',
            'target_apis': [a.get('api_id') for a in analyses if a.get('failure_class') == 'validation_error'][:5],
        })

    ladder = _load_diagnostic_ladder()
    fc_to_layer = ladder.get('failure_class_to_layer') or {}
    layer_actions = {layer['id']: layer.get('actions') or [] for layer in (ladder.get('layers') or [])}

    version_blocked = sum(1 for a in analyses if a.get('failure_class') == 'app_version_blocked')
    if version_blocked >= 1:
        actions.insert(0, {
            'action': 'version_baseline_repair',
            'reason': 'server rejected AppVersion — refresh baseline capture from current mini-program',
            'priority': 'P0',
            'field': 'AppVersion',
            'checks': ['static_app_version', 'fresh_login_capture'],
        })

    transport_routing = sum(1 for a in analyses if a.get('failure_class') == 'transport_url_routing')
    if transport_routing >= 1:
        actions.insert(0, {
            'action': 'transport_url_repair',
            'reason': 'HTTP 404 — verify path query separator and encrypted blob placement',
            'priority': 'P0',
            'layer': 'L1_transport',
        })

    for fc, count in sorted(failure_hist.items(), key=lambda x: -x[1]):
        if count < 2 or fc in ('unknown_response', 'business_state_blocked'):
            continue
        layer_id = fc_to_layer.get(fc)
        if not layer_id:
            continue
        for act in layer_actions.get(layer_id) or []:
            if act not in {a.get('action') for a in actions}:
                actions.append({
                    'action': act,
                    'reason': f'{fc} observed {count}x (layer {layer_id})',
                    'priority': 'P1',
                    'layer': layer_id,
                })
                break

    harvest = []
    for a in analyses:
        if a.get('useful_for_next_step'):
            harvest.extend(a.get('next_unlocked_fields') or [])
    if harvest:
        actions.append({
            'action': 'expand_frontier',
            'reason': 'runtime fields harvested',
            'fields': sorted(set(harvest)),
            'priority': 'P1',
        })

    success_count = sum(1 for a in analyses if a.get('call_outcome') in {'business_success', 'dry_run_ok'})
    if success_count == 0 and analyses:
        actions.append({
            'action': 'diagnostic_mode',
            'reason': 'no successful calls in batch',
            'priority': 'P0',
            'checks': [
                'crypto_profile', 'baseline_freshness', 'host_base_url',
                'missing_slots', 'wrong_entry_apis',
            ],
        })

    if not actions:
        actions.append({
            'action': 'continue_campaign',
            'reason': 'frontier remaining',
            'remaining_frontier': len(state.get('frontier_apis') or []),
            'priority': 'P2',
        })

    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': _utc_now(),
        'campaign_mode': state.get('campaign_mode'),
        'recommended_actions': actions,
        'failure_histogram': failure_hist,
        'confirmed_fields': (object_pool or {}).get('confirmed_fields') or [],
    }
