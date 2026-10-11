# -*- coding: utf-8 -*-
from __future__ import annotations
from typing import Any, Dict, List
from minidrifter.core.patterns import CAP_KEYS, CRYPTO_KEYS, OBJECT_KEYS, SUBJECT_KEYS


def classify_credential(name: str) -> str:
    if not name:
        return 'unknown'
    if CRYPTO_KEYS.search(name):
        return 'signature_or_crypto_material'
    if SUBJECT_KEYS.search(name):
        return 'subject_credential'
    if CAP_KEYS.search(name):
        return 'capability_credential'
    if OBJECT_KEYS.search(name):
        return 'object_credential'
    return 'ordinary_or_unknown_param'


class CredentialFlowAnalyzer:
    def __init__(self, api_calls: List[Dict[str, Any]], url_registry: Dict[str, Any]):
        self.api_calls = api_calls
        self.url_registry = url_registry

    def run(self) -> Dict[str, Any]:
        candidates = []
        for call in self.api_calls:
            for field in call.get('data_keys') or []:
                role = classify_credential(field)
                if role != 'ordinary_or_unknown_param':
                    candidates.append({
                        'name': field,
                        'role': role,
                        'where': 'request.data_or_query',
                        'api_call_id': call['api_call_id'],
                        'url_key': call.get('url_key'),
                        'resolved_url': call.get('resolved_url'),
                        'source': call.get('source'),
                    })
            for field in call.get('header_keys') or []:
                role = classify_credential(field)
                if role != 'ordinary_or_unknown_param':
                    candidates.append({
                        'name': field,
                        'role': role,
                        'where': 'request.header',
                        'api_call_id': call['api_call_id'],
                        'url_key': call.get('url_key'),
                        'resolved_url': call.get('resolved_url'),
                        'source': call.get('source'),
                    })
        # also infer from registered-only URL keys/path tokens
        for key, entry in self.url_registry.get('entries', {}).items():
            role = classify_credential(key)
            if role != 'ordinary_or_unknown_param':
                candidates.append({
                    'name': key,
                    'role': role,
                    'where': 'url_registry_key',
                    'api_call_id': None,
                    'url_key': key,
                    'resolved_url': entry.get('resolved_url'),
                    'source': entry.get('source'),
                })
        # counts
        counts = {}
        for c in candidates:
            counts[c['role']] = counts.get(c['role'], 0) + 1
        return {'candidates': candidates, 'role_counts': counts}
