# -*- coding: utf-8 -*-
"""Evidence-driven RCR construction from request facts."""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from minidrifter.rcr import IDENTITY_UNRESOLVED, SCHEMA_VERSION
from minidrifter.rcr.evidence import (
    binding_use,
    build_field_evidence,
    business_credential_use,
    identity_anchor_use,
)


def canonical_identity(identity_fields: List[str], provenance_map: Dict[str, Any]) -> Optional[str]:
    """CanonicalIdentity — prefer auth-state-rooted token; else ⊥."""
    if not identity_fields:
        return IDENTITY_UNRESOLVED
    scored: List[tuple] = []
    for name in identity_fields:
        prov = (provenance_map or {}).get(name) or {}
        score = 0.0
        if re.search(r'(token|authorization|session|appidentity)', name, re.I):
            score += 3.0
        kind = prov.get('kind') or ''
        if kind in {'persistent_storage', 'global_state', 'wrapper_injected'}:
            score += 2.0
        if kind == 'page_state':
            score += 0.5
        scored.append((score, name))
    scored.sort(key=lambda x: (-x[0], x[1]))
    if scored and scored[0][0] >= 2.0:
        return scored[0][1]
    return IDENTITY_UNRESOLVED


def normalize_op(endpoint: Dict[str, Any], method: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    """NormalizeOp(e_i, m_i, κ_i) — frontend-visible operation label."""
    path = (endpoint or {}).get('path') or ''
    host = (endpoint or {}).get('host') or ''
    m = (method or {}).get('value') or 'UNKNOWN'
    parts = [p for p in str(path).split('/') if p]
    leaf = parts[-1] if parts else 'unknown'
    return {
        'method': m,
        'path': path,
        'host': host,
        'op_label': f'{m} {path}' if path else m,
        'leaf': leaf,
        'method_source': (method or {}).get('source'),
        'method_confidence': (method or {}).get('confidence'),
        'event_linkage': (context or {}).get('event_linkage'),
    }


def normalize_transforms(transforms: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """NormalizeTransforms(Θ_i) — keep frontend-recoverable transform refs only."""
    out: List[Dict[str, Any]] = []
    for t in transforms or []:
        if not isinstance(t, dict):
            continue
        if (t.get('kind') or '') == 'none':
            continue
        out.append({
            'kind': t.get('kind'),
            'name': t.get('name'),
            'binding': t.get('binding'),
            'algorithm_hints': t.get('algorithm_hints') or [],
        })
    return out


def construct_rcr(fact: Dict[str, Any]) -> Dict[str, Any]:
    """RCR Construction Procedure from F_i (paper: Reference Contract Representation)."""
    from minidrifter.runtime_trace.chain_composer import infer_binding_fields_from_path
    from minidrifter.rpgraph.schema import is_business_bind_field

    endpoint = fact.get('endpoint') or {}
    method = fact.get('method') or {}
    context = fact.get('invocation_context') or {}
    provenance_map = fact.get('provenance') or {}
    params = fact.get('params') or []
    path = (endpoint or {}).get('path') or ''

    evidence_list: List[Dict[str, Any]] = []
    identity_fields: List[str] = []
    business_fields: List[str] = []

    for p in params:
        name = p.get('name') or ''
        ev = build_field_evidence(name, p.get('provenance') or provenance_map.get(name), context)
        evidence_list.append(ev)
        if identity_anchor_use(ev):
            identity_fields.append(name)
        elif business_credential_use(ev):
            business_fields.append(name)

    bind_fields = [e['field'] for e in evidence_list if binding_use(e, evidence_list)]
    # Paper φ_i: also recover resource-reference candidates from path shape when
    # explicit params are sparse (ByTitle→title, Title/Detail→titleId, {houseId}).
    path_inferred = infer_binding_fields_from_path(path)
    for n in path_inferred:
        # Path-shape φ_i candidates are first-class even when role priors are weak.
        if n not in business_fields:
            business_fields.append(n)
        if n not in bind_fields:
            bind_fields.append(n)
            evidence_list.append(build_field_evidence(n, {'kind': 'path_shape_inference', 'path': path}, context))

    # Param names that look like object binders but missed binding_use.
    for name in list(business_fields):
        if name not in bind_fields and is_business_bind_field(name):
            bind_fields.append(name)

    a_i = canonical_identity(identity_fields, provenance_map)
    op_i = normalize_op(endpoint, method, context)
    gamma = normalize_transforms(fact.get('transforms') or [])

    r_i = {
        'identity_anchor': a_i,  # may be null (⊥)
        'credentials': sorted(set(identity_fields + business_fields + path_inferred)),
        'resource_reference_candidates': sorted(set(bind_fields)),  # φ_i candidates
        'operation': op_i,
    }

    return {
        'schema_version': SCHEMA_VERSION,
        'operation_id': fact.get('operation_id'),
        'endpoint': endpoint,
        'method': method,
        'request_semantics': r_i,
        'binding_credentials': sorted(set(bind_fields)),  # φ_i primary
        'evidence': evidence_list,
        'materialization': gamma,
        'notes': {
            'claims_backend_rho': False,
            'identity_unresolved': a_i is IDENTITY_UNRESOLVED,
            'path_inferred_binds': path_inferred,
        },
    }


def construct_rcr_pack(request_facts_doc: Dict[str, Any]) -> Dict[str, Any]:
    from minidrifter.optimizers.url_utils import is_engine_noise_path, is_frontend_route_path

    raw_facts = request_facts_doc.get('request_facts') or []
    facts = []
    for f in raw_facts:
        path = ((f.get('endpoint') or {}).get('path') or '')
        if is_frontend_route_path(path) or is_engine_noise_path(path):
            continue
        facts.append(f)
    rcrs = [construct_rcr(f) for f in facts]
    identity_resolved = sum(1 for c in rcrs if not (c.get('notes') or {}).get('identity_unresolved'))
    with_bind = sum(1 for c in rcrs if c.get('binding_credentials'))
    return {
        'schema_version': SCHEMA_VERSION,
        'representation': 'Reference Contract Representation (RCR)',
        'rcr_count': len(rcrs),
        'identity_resolved_count': identity_resolved,
        'identity_unresolved_count': len(rcrs) - identity_resolved,
        'with_binding_credentials': with_bind,
        # Paper key + legacy alias used by older pack readers
        'rcrs': rcrs,
        'ccrs': rcrs,
    }
