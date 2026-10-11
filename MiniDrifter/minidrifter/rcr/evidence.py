# -*- coding: utf-8 -*-
"""Evidence builders and closed-set semantic predicates for RCR."""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from minidrifter.analyzers.credential import classify_credential
from minidrifter.business_chain.field_role import (
    AUTH_MATERIAL,
    BINDING_HIGH_ROLES,
    BUSINESS_OBJECT_ID,
    CAPABILITY_CREDENTIAL,
    HOST_IDENTITY,
    SUBJECT_ID,
    infer_field_role,
)

_AUTH_FLOW_RE = re.compile(
    r'(login|auth|session|token|authorization|getStorage.*token|globalData\.(token|userInfo))',
    re.I,
)
_RESOURCE_CTX_RE = re.compile(
    r'(order|device|invoice|address|cart|goods|booking|reservation|qualify|member|customer)',
    re.I,
)


def build_field_evidence(
    name: str,
    provenance: Optional[Dict[str, Any]] = None,
    invocation_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """BuildEvidence(p, Π_i(p), κ_i) — frontend-visible only."""
    prov = provenance or {}
    ctx = invocation_context or {}
    role_prior = classify_credential(name)
    field_role = infer_field_role(name)
    predicates: List[str] = []
    snippet = str(ctx.get('snippet') or '')

    if role_prior == 'subject_credential' or field_role.get('role') in {SUBJECT_ID, HOST_IDENTITY}:
        predicates.append('subject_or_host_id_pattern')
    if role_prior == 'signature_or_crypto_material' or field_role.get('role') == AUTH_MATERIAL:
        predicates.append('auth_or_crypto_pattern')
    if field_role.get('role') in {BUSINESS_OBJECT_ID, CAPABILITY_CREDENTIAL}:
        predicates.append('business_object_or_capability_pattern')
    if (prov.get('kind') or '') == 'persistent_storage' and (
        re.search(r'(token|jwt|session|auth|user)', str(prov.get('source_key') or ''), re.I)
        or re.search(r'(token|authorization|jwt|session)', name, re.I)
    ):
        predicates.append('auth_storage_root')
    if (prov.get('kind') or '') in {'global_state', 'persistent_storage', 'wrapper_injected'} and re.search(
        r'(token|session|auth|authorization|appidentity)', name, re.I
    ):
        predicates.append('auth_state_root')
    if _RESOURCE_CTX_RE.search(name) or _RESOURCE_CTX_RE.search(snippet[:200]):
        predicates.append('resource_context_signal')
    if (prov.get('kind') or '') == 'unresolved':
        predicates.append('provenance_unresolved')
    if (prov.get('kind') or '') == 'static_schema':
        predicates.append('static_schema_field')

    return {
        'field': name,
        'provenance_kind': prov.get('kind') or 'unresolved',
        'provenance': prov,
        'credential_role_prior': role_prior,
        'field_role': field_role.get('role'),
        'binding_relevance_prior': field_role.get('binding_relevance'),
        'predicates': predicates,
        'event_linkage': ctx.get('event_linkage'),
    }


def identity_anchor_use(evidence: Dict[str, Any]) -> bool:
    """IdentityAnchorUse — rooted in application-side authentication state."""
    preds = set(evidence.get('predicates') or [])
    if 'auth_state_root' in preds or 'auth_storage_root' in preds:
        return True
    if evidence.get('field_role') == AUTH_MATERIAL:
        return True
    name = str(evidence.get('field') or '')
    if re.search(r'^(token|authorization|access_?token|session|appidentity)$', name, re.I):
        return True
    prov_kind = evidence.get('provenance_kind') or ''
    if prov_kind in {'persistent_storage', 'global_state', 'wrapper_injected'} and re.search(
        r'(token|authorization|jwt|session|auth)', name, re.I
    ):
        return True
    return False


def business_credential_use(evidence: Dict[str, Any]) -> bool:
    """BusinessCredentialUse — non-anchor ids/handles in business-object flows."""
    if identity_anchor_use(evidence):
        return False
    role = evidence.get('field_role')
    if role in {BUSINESS_OBJECT_ID, CAPABILITY_CREDENTIAL, SUBJECT_ID, HOST_IDENTITY}:
        return True
    if evidence.get('credential_role_prior') in {
        'object_credential', 'capability_credential', 'subject_credential',
    }:
        return True
    name = str(evidence.get('field') or '')
    # Avoid bare tokens like code/key/id — require compound names (orderId, authCode, ...).
    if re.search(r'^(code|key|id|no|token|sign)$', name, re.I):
        return False
    return bool(re.search(r'.+(id|no|code|handle)$', name, re.I) and len(name) >= 5)


def binding_use(evidence: Dict[str, Any], all_evidence: List[Dict[str, Any]]) -> bool:
    """BindingUse — credential selects/derives/addresses/propagates a resource context."""
    if identity_anchor_use(evidence):
        return False
    if not business_credential_use(evidence):
        return False
    role = evidence.get('field_role')
    if role in BINDING_HIGH_ROLES or evidence.get('binding_relevance_prior') == 'high':
        return True
    preds = set(evidence.get('predicates') or [])
    if 'resource_context_signal' in preds or 'business_object_or_capability_pattern' in preds:
        return True
    name = str(evidence.get('field') or '')
    if re.search(r'.+(id|no|code)$', name, re.I) and len(name) >= 5:
        return True
    if role == SUBJECT_ID and any(
        'resource_context_signal' in (e.get('predicates') or []) for e in all_evidence
    ):
        return True
    return False
