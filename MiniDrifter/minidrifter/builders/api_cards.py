# -*- coding: utf-8 -*-
from __future__ import annotations
from typing import Any, Dict, List
from minidrifter.analyzers.credential import classify_credential
from minidrifter.core.patterns import SENSITIVE_DOMAIN_KEYS
from minidrifter.core.utils import stable_id, tokenise_identifier


class APICardBuilder:
    def __init__(self, url_registry: Dict[str, Any], api_calls: List[Dict[str, Any]], dynamic_candidates: List[Dict[str, Any]], events: List[Dict[str, Any]], wrappers: List[Dict[str, Any]], crypto_cards: List[Dict[str, Any]]):
        self.url_registry = url_registry
        self.api_calls = api_calls
        self.dynamic_candidates = dynamic_candidates
        self.events = events
        self.wrappers = wrappers
        self.crypto_cards = crypto_cards

    def _risk_hints(self, url_key: str | None, resolved_url: str | None, params: List[Dict[str, Any]], card_type: str) -> List[str]:
        hints = []
        roles = {p['credential_role'] for p in params}
        if 'object_credential' in roles:
            hints.append('subject_object_binding_required')
            hints.append('object_id_replaceable_candidate')
        if 'capability_credential' in roles:
            hints.append('capability_credential_generation_or_consumption')
        if 'signature_or_crypto_material' in roles:
            hints.append('signature_or_crypto_replay_required')
        text = ' '.join([url_key or '', resolved_url or ''])
        if SENSITIVE_DOMAIN_KEYS.search(text):
            hints.append('sensitive_business_api')
        if card_type == 'registered_only':
            hints.extend(['orphan_registered_api', 'legacy_or_debug_api_candidate'])
        if card_type == 'dynamic_unknown':
            hints.append('dynamic_api_resolution_required')
        return sorted(set(hints))

    def _param_cards(self, call: Dict[str, Any]) -> List[Dict[str, Any]]:
        out = []
        for name in call.get('data_keys') or []:
            out.append({
                'name': name,
                'where': 'query_or_body',
                'value_expr': name,
                'source_type': 'unknown_static_expr',
                'credential_role': classify_credential(name),
            })
        for name in call.get('header_keys') or []:
            out.append({
                'name': name,
                'where': 'header',
                'value_expr': name,
                'source_type': 'header_expr',
                'credential_role': classify_credential(name),
            })
        return out

    def build_reached(self) -> List[Dict[str, Any]]:
        cards = []
        for call in self.api_calls:
            url_key = call.get('url_key')
            resolved = call.get('resolved_url')
            source_file = call.get('source', {}).get('file', '')
            if source_file.startswith('pages/'):
                card_type = 'page_reached'
            elif source_file.startswith('services/'):
                card_type = 'service_reached'
            else:
                card_type = 'code_reached'
            params = self._param_cards(call)
            text = ' '.join([url_key or '', resolved or '', call.get('description_arg') or ''])
            cards.append({
                'api_id': stable_id('api', call['api_call_id'], resolved or call.get('url_expr') or ''),
                'card_type': card_type,
                'endpoint': {
                    'method': call.get('method'),
                    'url_key': url_key,
                    'resolved_url': resolved,
                    'raw_url_expr': call.get('url_expr'),
                },
                'reachability': {
                    'level': 'R0' if card_type == 'page_reached' else 'R1',
                    'evidence': 'Recovered from concrete JS call site',
                },
                'page_context': {
                    'page_or_module': source_file.removesuffix('.js'),
                    'event_linkage': 'not_resolved_in_mvp',
                },
                'code_context': {
                    'callee': call.get('callee'),
                    'call_type': call.get('call_type'),
                    'description_arg': call.get('description_arg'),
                    'source': call.get('source'),
                },
                'request_context': {
                    'params': params,
                    'raw_args': call.get('args'),
                },
                'business_hints': {
                    'tokens': tokenise_identifier(text),
                    'sensitive_hint': bool(SENSITIVE_DOMAIN_KEYS.search(text)),
                },
                'crypto_context': {
                    'uses_project_http_crypto': bool(self.wrappers),
                    'crypto_context_confidence': 'project_default_wrapper_inferred' if self.wrappers else 'unknown',
                    'likely_wrapper_files': [w['file'] for w in self.wrappers[:5]],
                    'crypto_card_refs': [c['crypto_id'] for c in self.crypto_cards[:10]],
                },
                'risk_hints': self._risk_hints(url_key, resolved, params, card_type),
            })
        return cards

    def build_registered_only(self) -> List[Dict[str, Any]]:
        cards = []
        for key, entry in self.url_registry.get('entries', {}).items():
            if entry.get('reachability') != 'registered_only':
                continue
            text = ' '.join([key, entry.get('resolved_url','')])
            params = []
            # Weakly infer likely object params from URL path/key tokens; keep as hints only.
            for token in ['userId', 'orderId', 'phoneNo', 'invoiceId', 'deviceId', 'carId', 'targetUserId']:
                if token.lower().replace('id','') in text.lower() or token.lower() in text.lower():
                    params.append({'name': token, 'where': 'inferred_param', 'value_expr': '<unknown>', 'source_type': 'inferred_from_url_key_or_path', 'credential_role': classify_credential(token)})
            cards.append({
                'api_id': stable_id('regapi', key, entry.get('resolved_url')),
                'card_type': 'registered_only',
                'endpoint': {'method': 'UNKNOWN', 'url_key': key, 'resolved_url': entry.get('resolved_url'), 'raw_url_expr': entry.get('raw_expr')},
                'reachability': {'level': 'R2', 'evidence': 'Found in URL registry, no concrete call site recovered'},
                'request_context': {'params': params, 'raw_args': []},
                'business_hints': {'tokens': entry.get('key_tokens', []) + entry.get('path_tokens', []), 'sensitive_hint': bool(SENSITIVE_DOMAIN_KEYS.search(text))},
                'crypto_context': {
                    'uses_project_http_crypto': bool(self.wrappers),
                    'crypto_context_confidence': 'inferred_from_project_default_wrapper',
                    'likely_wrapper_files': [w['file'] for w in self.wrappers[:5]],
                    'crypto_card_refs': [c['crypto_id'] for c in self.crypto_cards[:10]],
                },
                'risk_hints': self._risk_hints(key, entry.get('resolved_url'), params, 'registered_only'),
                'source': entry.get('source'),
            })
        return cards

    def build_dynamic(self) -> List[Dict[str, Any]]:
        cards = []
        for call in self.dynamic_candidates:
            cards.append({
                'api_id': stable_id('dynapi', call.get('api_call_id')),
                'card_type': 'dynamic_unknown',
                'endpoint': {'method': call.get('method'), 'url_key': call.get('url_key'), 'resolved_url': None, 'raw_url_expr': call.get('url_expr')},
                'reachability': {'level': 'R3', 'evidence': 'Wrapper call recovered but URL could not be resolved statically'},
                'code_context': {'callee': call.get('callee'), 'call_type': call.get('call_type'), 'source': call.get('source')},
                'request_context': {'params': self._param_cards(call), 'raw_args': call.get('args')},
                'business_hints': {'tokens': tokenise_identifier(' '.join(call.get('args') or [])), 'sensitive_hint': False},
                'crypto_context': {'uses_project_http_crypto': bool(self.wrappers), 'crypto_context_confidence': 'project_default_wrapper_inferred'},
                'risk_hints': ['dynamic_api_resolution_required'],
            })
        return cards

    def run(self) -> Dict[str, Any]:
        reached = self.build_reached()
        registered = self.build_registered_only()
        dynamic = self.build_dynamic()
        return {
            'reached_api_cards': reached,
            'registered_only_api_cards': registered,
            'dynamic_api_cards': dynamic,
            'all_api_cards': reached + registered + dynamic,
        }
