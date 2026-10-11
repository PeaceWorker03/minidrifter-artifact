# -*- coding: utf-8 -*-
from __future__ import annotations
from typing import Any, Dict, List
from minidrifter.core.utils import stable_id


class ReplayContractBuilder:
    """Build request-replay contracts for later LLM/template PoC generation.

    A Replay Contract is not an exploit. It is a deterministic description of where cleartext
    parameters exist, where mutations should happen, and which crypto/header transforms must be
    recomputed before a non-destructive authorized replay.
    """

    def __init__(self, api_cards: List[Dict[str, Any]], crypto_cards: List[Dict[str, Any]], wrappers: List[Dict[str, Any]]):
        self.api_cards = api_cards
        self.crypto_cards = crypto_cards
        self.wrappers = wrappers

    def _runtime_requirements(self, card: Dict[str, Any]) -> List[Dict[str, Any]]:
        reqs = []
        for h in ['Token', 'Authorization', 'AppIdentity', 'TimeSpan']:
            if any(h.lower() in ' '.join(w.get('header_hints', [])).lower() for w in self.wrappers) or h in ['TimeSpan']:
                reqs.append({'name': h, 'source': 'project_request_wrapper_or_runtime_generated', 'required': h != 'Authorization'})
        for p in card.get('request_context', {}).get('params', []):
            if p.get('credential_role') in ['object_credential', 'subject_credential', 'capability_credential']:
                reqs.append({'name': p.get('name'), 'source': p.get('source_type', 'request_param'), 'required': True})
        # de-dup by name
        out, seen = [], set()
        for r in reqs:
            if r['name'] not in seen:
                seen.add(r['name']); out.append(r)
        return out

    def _mutation_points(self, card: Dict[str, Any]) -> List[Dict[str, Any]]:
        points = []
        for p in card.get('request_context', {}).get('params', []):
            role = p.get('credential_role')
            if role == 'object_credential':
                points.append({'field': p.get('name'), 'where': p.get('where'), 'role': role, 'mutation_strategy': 'replace_with_owned_account_B_corresponding_object_id', 'mutate_at_stage': 'plain_stage'})
            elif role == 'capability_credential':
                points.append({'field': p.get('name'), 'where': p.get('where'), 'role': role, 'mutation_strategy': 'replay_or_replace_only_with_owned_test_capability', 'mutate_at_stage': 'plain_stage'})
        return points

    def _transform_chain(self, direction: str) -> List[Dict[str, Any]]:
        chain = []
        for c in self.crypto_cards:
            if c.get('direction') not in [direction, 'unknown']:
                continue
            op = c.get('operation')
            if direction == 'request' and op == 'decrypt':
                continue
            if direction == 'response' and op in ['encrypt', 'sign_or_header_transform']:
                continue
            chain.append({
                'stage': c.get('stage'),
                'operation': c.get('operation'),
                'function': c.get('function'),
                'file': c.get('file'),
                'algorithm_hints': c.get('algorithm_hints'),
                'must_recompute_after_mutation': direction == 'request' and c.get('operation') in ['encrypt', 'sign_or_header_transform', 'crypto_related'],
                'crypto_id': c.get('crypto_id'),
            })
            if len(chain) >= 8:
                break
        return chain

    def run(self) -> List[Dict[str, Any]]:
        contracts = []
        for card in self.api_cards:
            if card.get('card_type') == 'dynamic_unknown':
                continue
            endpoint = card.get('endpoint', {})
            params = card.get('request_context', {}).get('params', [])
            contracts.append({
                'contract_id': stable_id('replay', card.get('api_id'), endpoint.get('resolved_url')),
                'api_id': card.get('api_id'),
                'card_type': card.get('card_type'),
                'endpoint': endpoint,
                'runtime_requirements': self._runtime_requirements(card),
                'plain_request_shape': {
                    'query_or_body_params': [{p.get('name'): f"<{p.get('credential_role')}>"} for p in params if p.get('where') != 'header'],
                    'headers': [{p.get('name'): f"<{p.get('credential_role')}>"} for p in params if p.get('where') == 'header'],
                    'notes': 'Mutation should happen in the plain stage. Recompute request transforms afterwards.',
                },
                'mutation_points': self._mutation_points(card),
                'request_transform_chain': self._transform_chain('request'),
                'response_transform_chain': self._transform_chain('response'),
                'suggested_replay_backend': 'node_bridge_reuse_original_js_first; python_port_after_transform_is_confirmed',
                'llm_usage_hint': 'Use this contract plus referenced source snippets to generate a conservative Node.js replay skeleton. Do not infer vulnerability without authorized A/B validation.',
                'safety_policy': {
                    'mode': 'authorized_non_destructive_validation',
                    'requires_owned_accounts': True,
                    'no_mass_enumeration': True,
                    'prefer_read_only_methods_first': True,
                    'do_not_execute_state_changing_calls_without_manual_confirmation': True,
                },
            })
        return contracts
