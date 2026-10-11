# -*- coding: utf-8 -*-
from __future__ import annotations
from pathlib import Path
from typing import Any, Dict, List, Set


class ReachabilityClassifier:
    def __init__(self, url_registry: Dict[str, Any], api_calls: List[Dict[str, Any]], events: List[Dict[str, Any]]):
        self.url_registry = url_registry
        self.api_calls = api_calls
        self.events = events

    def run(self) -> Dict[str, Any]:
        reached_keys: Set[str] = set()
        page_handlers = {e.get('handler') for e in self.events}
        for c in self.api_calls:
            key = c.get('url_key')
            if key:
                reached_keys.add(key)
        # update url entries in place copy
        entries = self.url_registry.get('entries', {})
        for k, e in entries.items():
            e['use_count'] = sum(1 for c in self.api_calls if c.get('url_key') == k)
            if e['use_count'] > 0:
                # precise page linkage is deferred, but file path helps distinguish service/page
                files = [c.get('source', {}).get('file','') for c in self.api_calls if c.get('url_key') == k]
                if any(f.startswith('pages/') for f in files):
                    e['reachability'] = 'page_or_page_module_reached'
                elif any(f.startswith('services/') for f in files):
                    e['reachability'] = 'service_reached'
                else:
                    e['reachability'] = 'code_reached'
            else:
                e['reachability'] = 'registered_only'
        registered_only = [e for k, e in entries.items() if e.get('reachability') == 'registered_only']
        reached = [e for k, e in entries.items() if e.get('reachability') != 'registered_only']
        return {
            'url_registry': self.url_registry,
            'reached_url_entries': reached,
            'registered_only_entries': registered_only,
            'counts': {
                'reached': len(reached),
                'registered_only': len(registered_only),
            }
        }
