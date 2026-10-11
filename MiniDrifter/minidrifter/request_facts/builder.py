# -*- coding: utf-8 -*-
"""Build per-request F_i facts from optimized operations + raw evidence."""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from minidrifter.analyzers.credential import classify_credential
from minidrifter.request_facts import SCHEMA_VERSION

_STORAGE_RE = re.compile(r'(?:get|set|remove)Storage(?:Sync)?\s*\(\s*[\'"]([^\'"]+)[\'"]', re.I)
_GLOBAL_RE = re.compile(r'(?:getApp\s*\(\s*\)\s*\.)?globalData\.([A-Za-z_$][\w$]*)', re.I)
_THIS_DATA_RE = re.compile(r'this\.data\.([A-Za-z_$][\w$]*)', re.I)
_AUTH_KEY_RE = re.compile(r'(token|jwt|session|auth|authorization|user|login)', re.I)


def _provenance_for_field(
    name: str,
    focused_text: str,
    *,
    identity_roots: Optional[Dict[str, Any]] = None,
    location: str = 'data_or_query',
) -> Dict[str, Any]:
    text = focused_text or ''
    nl = (name or '').lower()
    roots = identity_roots or {}

    # Wrapper-injected auth headers → map onto storage/global roots.
    if location == 'header' and _AUTH_KEY_RE.search(name or ''):
        for sk in roots.get('storage_keys') or []:
            if _AUTH_KEY_RE.search(sk):
                return {
                    'kind': 'persistent_storage',
                    'source_key': sk,
                    'confidence': 0.8,
                    'evidence': [f'wrapper_header:{name}', f'storage_root:{sk}'],
                }
        for gf in roots.get('global_fields') or []:
            if _AUTH_KEY_RE.search(gf) or 'token' in gf.lower():
                return {
                    'kind': 'global_state',
                    'source_key': gf,
                    'confidence': 0.75,
                    'evidence': [f'wrapper_header:{name}', f'globalData:{gf}'],
                }
        return {
            'kind': 'wrapper_injected',
            'source_key': name,
            'confidence': 0.7,
            'evidence': ['wrapper_injected_header'],
        }

    for m in _STORAGE_RE.finditer(text):
        key = m.group(1)
        if nl and (nl in key.lower() or key.lower() in nl or (_AUTH_KEY_RE.search(nl) and _AUTH_KEY_RE.search(key))):
            return {
                'kind': 'persistent_storage',
                'source_key': key,
                'confidence': 0.75,
                'evidence': [f'getStorage:{key}'],
            }

    for m in _GLOBAL_RE.finditer(text):
        key = m.group(1)
        if nl and (nl in key.lower() or key.lower() in nl or (_AUTH_KEY_RE.search(nl) and _AUTH_KEY_RE.search(key))):
            return {
                'kind': 'global_state',
                'source_key': key,
                'confidence': 0.7,
                'evidence': [f'globalData:{key}'],
            }

    for m in _THIS_DATA_RE.finditer(text):
        key = m.group(1)
        if nl and (nl in key.lower() or key.lower() in nl):
            return {
                'kind': 'page_state',
                'source_key': key,
                'confidence': 0.65,
                'evidence': [f'this.data:{key}'],
            }

    if name and re.search(rf'\b{re.escape(name)}\s*[:=]\s*[\'"`\d]', text):
        return {
            'kind': 'literal_or_local',
            'source_key': name,
            'confidence': 0.4,
            'evidence': ['local_assignment_pattern'],
        }

    # Field-name prior against project identity roots.
    if _AUTH_KEY_RE.search(name or ''):
        for sk in roots.get('storage_keys') or []:
            if _AUTH_KEY_RE.search(sk):
                return {
                    'kind': 'persistent_storage',
                    'source_key': sk,
                    'confidence': 0.55,
                    'evidence': [f'identity_root_prior:{sk}'],
                }

    # Present in statically recovered request schema, dataflow not proven.
    if name:
        # Prefer page-state if the name appears near this.data / setData in focused text.
        if re.search(rf'(this\.data\.|setData\s*\(.*)\b{re.escape(name)}\b', text, re.I):
            return {
                'kind': 'page_state',
                'source_key': name,
                'confidence': 0.5,
                'evidence': ['name_near_page_state'],
            }
        if re.search(rf'\b{re.escape(name)}\b', text):
            return {
                'kind': 'static_schema',
                'source_key': name,
                'confidence': 0.35,
                'evidence': ['name_in_focused_slice'],
            }
        return {
            'kind': 'static_schema',
            'source_key': name,
            'confidence': 0.3,
            'evidence': ['present_in_request_schema'],
        }

    return {
        'kind': 'unresolved',
        'source_key': None,
        'confidence': 0.0,
        'evidence': ['no_static_provenance'],
    }


def _bind_transforms(
    op: Dict[str, Any],
    crypto_cards: List[Dict[str, Any]],
    wrappers: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    bound: List[Dict[str, Any]] = []

    # Prefer explicit enricher hints.
    hints = op.get('transform_hints') or {}
    if hints.get('binding') == 'wrapper_default_chain':
        bound.append({
            'kind': 'request_wrapper_crypto_chain',
            'name': 'wrapper_default_chain',
            'binding': 'wrapper_default_chain',
            'algorithm_hints': hints.get('crypto_hints') or [],
            'header_hints': hints.get('header_hints') or [],
            'wrapper_files': hints.get('wrapper_files') or [],
        })

    sources = op.get('supporting_sources') or []
    files = {
        str((s or {}).get('file') or '').replace('\\', '/').lower()
        for s in sources if isinstance(s, dict)
    }
    wrapper_files = {
        str(w.get('file') or '').replace('\\', '/').lower()
        for w in (wrappers or []) if w.get('file')
    }

    for card in crypto_cards or []:
        if not isinstance(card, dict):
            continue
        src = card.get('source') or card.get('evidence') or {}
        cfile = str(card.get('file') or src.get('file') or '').replace('\\', '/').lower()
        algos = card.get('algorithm_hints') or []
        # Skip pure noise without algorithm / sign hints.
        if not algos and (card.get('operation') or '') == 'crypto_related':
            continue
        hit = False
        binding = 'unbound'
        if cfile and any(cfile.endswith(f.split('/')[-1]) or f.endswith(cfile.split('/')[-1]) for f in files if f):
            hit = True
            binding = 'callsite_or_file'
        elif cfile and cfile in wrapper_files:
            hit = True
            binding = 'wrapper_file'
        if hit:
            bound.append({
                'kind': card.get('operation') or card.get('kind') or 'crypto_or_sign',
                'name': card.get('function') or card.get('name'),
                'algorithm_hints': algos,
                'binding': binding,
                'source': {'file': card.get('file') or src.get('file'), 'line': src.get('line')},
            })
        if len(bound) >= 10:
            break

    if not bound and wrappers:
        w0 = wrappers[0]
        bound.append({
            'kind': 'request_wrapper',
            'name': w0.get('name') or w0.get('wrapper_id') or 'wrapper',
            'binding': 'wrapper_present',
            'note': 'wrapper present; crypto not uniquely bound',
        })
    elif not bound:
        bound.append({'kind': 'none', 'binding': 'unbound', 'note': 'no_transform_evidence'})
    return bound


def _invocation_context(op: Dict[str, Any], events: List[Dict[str, Any]]) -> Dict[str, Any]:
    sources = op.get('supporting_sources') or []
    src0 = sources[0] if sources else {}
    file = (src0 or {}).get('file')
    line = (src0 or {}).get('line')
    snippet = (src0 or {}).get('snippet') or ''
    event_linkage = 'not_resolved'
    linked_event = None
    handler_hit = re.search(r'\b(on[A-Z]\w+|handle\w+|bind\w+)\b', snippet)
    if handler_hit and events:
        hname = handler_hit.group(1)
        for ev in events[:800]:
            if (ev.get('handler') or ev.get('event_handler') or '') == hname:
                event_linkage = 'handler_name_match'
                linked_event = {
                    'handler': hname,
                    'page': ev.get('page') or ev.get('file'),
                    'event': ev.get('event') or ev.get('event_type'),
                }
                break
    # Fallback: page-file co-occurrence with any event on that page.
    if event_linkage == 'not_resolved' and file and events:
        f_norm = str(file).replace('\\', '/').lower()
        page_key = f_norm
        for suf in ('.js', '.ts', '.wxml'):
            if page_key.endswith(suf):
                page_key = page_key[: -len(suf)]
        for ev in events[:1200]:
            page = str(ev.get('page') or ev.get('file') or '').replace('\\', '/').lower()
            if page and (page in f_norm or page_key.endswith(page) or page.endswith(page_key.split('/')[-1])):
                event_linkage = 'page_cooccurrence'
                linked_event = {
                    'handler': ev.get('handler') or ev.get('event_handler'),
                    'page': ev.get('page') or ev.get('file'),
                    'event': ev.get('event') or ev.get('event_type'),
                }
                break
    return {
        'source_file': file,
        'source_line': line,
        'snippet': (snippet or '')[:500],
        'event_linkage': event_linkage,
        'linked_event': linked_event,
        'surface_types': dict(op.get('surface_types') or {}),
        'support_count': op.get('support_count'),
    }


def build_request_fact(
    op: Dict[str, Any],
    *,
    crypto_cards: Optional[List[Dict[str, Any]]] = None,
    wrappers: Optional[List[Dict[str, Any]]] = None,
    events: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    ep = op.get('endpoint') or {}
    identity_roots = op.get('identity_roots') or {}
    focused = ' '.join([
        str(s.get('snippet') or '')[:1000]
        for s in (op.get('supporting_sources') or [])
        if isinstance(s, dict)
    ])
    # Include wrapper evidence for provenance.
    for w in wrappers or []:
        focused += ' ' + str((w.get('evidence') or {}).get('snippet') or '')[:800]

    params: List[Dict[str, Any]] = []
    for name in sorted(set(op.get('param_schema') or [])):
        params.append({
            'name': name,
            'location': 'data_or_query',
            'credential_role_prior': classify_credential(name),
            'provenance': _provenance_for_field(name, focused, identity_roots=identity_roots),
        })
    for name in sorted(set(op.get('header_schema') or [])):
        params.append({
            'name': name,
            'location': 'header',
            'credential_role_prior': classify_credential(name),
            'provenance': _provenance_for_field(
                name, focused, identity_roots=identity_roots, location='header',
            ),
        })

    return {
        'schema_version': SCHEMA_VERSION,
        'operation_id': op.get('operation_id'),
        'endpoint': {
            'host': ep.get('host'),
            'path': ep.get('path'),
            'normalized_url': ep.get('normalized_url'),
            'endpoint_key': ep.get('endpoint_key'),
            'url_role': ep.get('url_role'),
            'query_schema': ep.get('query_schema') or [],
        },
        'method': {
            'value': op.get('method') or 'UNKNOWN',
            'source': op.get('method_source') or 'unresolved',
            'confidence': op.get('method_confidence') or 0.0,
        },
        'params': params,
        'provenance': {p['name']: p['provenance'] for p in params},
        'invocation_context': _invocation_context(op, events or []),
        'transforms': _bind_transforms(op, crypto_cards or [], wrappers or []),
        'url_classification': op.get('url_classification') or {},
        'host_resolution': op.get('host_resolution') or {},
        'identity_roots': identity_roots,
    }


def build_request_facts_pack(
    business_ops: List[Dict[str, Any]],
    *,
    crypto_cards: Optional[List[Dict[str, Any]]] = None,
    wrappers: Optional[List[Dict[str, Any]]] = None,
    events: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    facts = [
        build_request_fact(op, crypto_cards=crypto_cards, wrappers=wrappers, events=events)
        for op in business_ops
    ]
    method_counts: Dict[str, int] = {}
    prov_counts: Dict[str, int] = {}
    for f in facts:
        m = (f.get('method') or {}).get('value') or 'UNKNOWN'
        method_counts[m] = method_counts.get(m, 0) + 1
        for p in f.get('params') or []:
            kind = ((p.get('provenance') or {}).get('kind') or 'unresolved')
            prov_counts[kind] = prov_counts.get(kind, 0) + 1
    return {
        'schema_version': SCHEMA_VERSION,
        'fact_count': len(facts),
        'method_counts': method_counts,
        'provenance_kind_counts': prov_counts,
        'request_facts': facts,
    }
