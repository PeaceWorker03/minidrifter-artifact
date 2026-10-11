# -*- coding: utf-8
"""Extract business chains from API transitions (rule-based BFS)."""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from minidrifter.business_chain.chain_hop_enrichment import enrich_chain
from minidrifter.business_chain.chain_templates import classify_chain_type, is_safe_chain
from minidrifter.business_chain.field_role import binding_fields_from_list
from minidrifter.business_chain.schema import SCHEMA_VERSION
from minidrifter.business_chain.chain_run_context import make_chain_id, chain_path_signature
from minidrifter.graph.semantic_workflow_graph import infer_domain_from_path

MIN_DEPTH = 2
MAX_DEPTH = 4
MAX_CHAINS = 80


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _build_adjacency(transitions: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    adj: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for t in transitions:
        adj[t['from_api']].append(t)
    return adj


def _hop_doc(
    api_id: str,
    *,
    path: str,
    role: str,
    templates_by_id: Dict[str, Dict[str, Any]],
    business_graph: Dict[str, Any],
    cards_by_id: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    tpl = templates_by_id.get(api_id) or {}
    card = (cards_by_id or {}).get(api_id) or {}
    params = (tpl.get('plain_template') or {}).get('params') or {}
    if not params:
        raw_params = (card.get('bindings') or {}).get('params') or {}
        if isinstance(raw_params, dict):
            params = raw_params
        elif isinstance(raw_params, list):
            params = {str(p.get('name') or p.get('field') or ''): p for p in raw_params if isinstance(p, dict)}
    binding = binding_fields_from_list([k for k in params.keys() if k], path=path)
    produces: Set[str] = set()
    consumes: Set[str] = set()
    for e in business_graph.get('edges') or []:
        if e.get('from_api') != api_id:
            continue
        f = e.get('to_field')
        if not f:
            continue
        et = e.get('type') or ''
        if 'produces' in et:
            produces.add(f)
        if 'requires' in et:
            consumes.add(f)
    side = tpl.get('side_effect_level') or ''
    return {
        'api_id': api_id,
        'path': path,
        'role': role,
        'produces': sorted(produces),
        'requires': sorted(consumes),
        'consumes': sorted(consumes),
        'mutation_targets': binding,
        'side_effect': side,
        'materialized': tpl.get('status') in {'materialized_plain', 'materialized_with_crypto_profile'},
    }
    # binding from template params is provisional; enrich_chain() recomputes mutation_targets


def extract_business_chains(
    transitions_doc: Dict[str, Any],
    business_graph: Dict[str, Any],
    templates_by_id: Dict[str, Dict[str, Any]],
    *,
    cards_by_id: Optional[Dict[str, Dict[str, Any]]] = None,
    pack_dir: Optional[Path] = None,
    min_depth: int = MIN_DEPTH,
    max_depth: int = MAX_DEPTH,
    limit: int = MAX_CHAINS,
) -> Dict[str, Any]:
    transitions = transitions_doc.get('transitions') or []
    adj = _build_adjacency(transitions)
    api_paths = {n['id']: n.get('path') or '' for n in (business_graph.get('api_nodes') or []) if n.get('id')}

    # Entry APIs: producers with out-edges, prefer in-degree 0
    in_degree: Dict[str, int] = defaultdict(int)
    for t in transitions:
        in_degree[t['to_api']] += 1
    entries = sorted(
        {t['from_api'] for t in transitions},
        key=lambda aid: in_degree.get(aid, 0),
    )

    chains: List[Dict[str, Any]] = []
    seen_sigs: Set[str] = set()

    def _walk(entry: str, path_ids: List[str], depth: int) -> None:
        if depth > max_depth or len(chains) >= limit:
            return
        last = path_ids[-1]
        outs = adj.get(last, [])
        if not outs and len(path_ids) >= min_depth:
            _emit_chain(entry, path_ids)
            return
        if not outs:
            return
        for tr in outs[:12]:
            nxt = tr['to_api']
            if nxt in path_ids:
                continue
            new_path = path_ids + [nxt]
            if len(new_path) >= min_depth:
                _emit_chain(entry, new_path, partial=False)
            _walk(entry, new_path, depth + 1)

    def _emit_chain(entry: str, api_path: List[str], *, partial: bool = False) -> None:
        if len(api_path) < min_depth:
            return
        sig = '->'.join(api_path)
        if sig in seen_sigs:
            return
        hops = []
        for i, aid in enumerate(api_path):
            p = api_paths.get(aid) or ''
            role = 'producer' if i == 0 else ('consumer' if i == len(api_path) - 1 else 'hop')
            hops.append(_hop_doc(
                aid, path=p, role=role, templates_by_id=templates_by_id,
                business_graph=business_graph, cards_by_id=cards_by_id,
            ))
        if not is_safe_chain(hops):
            return
        objects = sorted({f for h in hops for f in (h.get('produces') or []) + (h.get('consumes') or [])})
        if not objects:
            return
        chain_type = classify_chain_type(hops)
        target = api_path[-1]
        domain = infer_domain_from_path(api_paths.get(entry) or '')
        seen_sigs.add(sig)
        draft = {
            'chain_type': chain_type,
            'domain': domain,
            'entry_api': entry,
            'entry_path': api_paths.get(entry) or '',
            'target_hop': target,
            'target_path': api_paths.get(target) or '',
            'hops': hops,
            'objects': objects,
            'capabilities': [f for f in objects if 'code' in f.lower() or 'ticket' in f.lower()],
            'confidence': round(sum(
                tr.get('confidence', 0.5) for tr in transitions
                if tr.get('from_api') in api_path and tr.get('to_api') in api_path
            ) / max(len(api_path) - 1, 1), 3),
            'evidence': [f'path_length:{len(api_path)}', f'chain_type:{chain_type}'],
            'safe_to_execute': is_safe_chain(hops),
        }
        enriched = enrich_chain(
            draft,
            cards_by_id=cards_by_id or {},
            templates_by_id=templates_by_id,
            pack_dir=pack_dir,
        )
        enriched['chain_id'] = make_chain_id(enriched)
        enriched['chain_path_signature'] = chain_path_signature(enriched)
        chains.append(enriched)

    for entry in entries[:40]:
        if len(chains) >= limit:
            break
        _walk(entry, [entry], 1)

    chains.sort(key=lambda c: (c.get('confidence', 0), len(c.get('risk_hops') or [])), reverse=True)
    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': _utc_now(),
        'chain_count': len(chains[:limit]),
        'chains': chains[:limit],
    }
