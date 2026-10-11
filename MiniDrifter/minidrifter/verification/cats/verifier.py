# -*- coding: utf-8 -*-
"""Plan verifier — reject hallucinated / unsafe LLM or rule plans before execution."""
from __future__ import annotations

from typing import Any, Dict, List, Set, Tuple

from minidrifter.materials.intake_param_hints import normalize_api_path
from minidrifter.verification.subject_override_fields import (
    FORBIDDEN_SUBJECT_FIELDS,
    field_allowed,
    norm_field,
)

ALLOWED_CANDIDATE_POLICIES = frozenset({
    'sibling_subject_value',
    'pool_alternate',
    'subject_pool',
    'har_pool',
    'authorized_seed',
    'numeric_far_jump_down',
    'numeric_far_jump_up',
    'numeric_increment',
    'numeric_decrement',
    'numeric_increment_legacy',
})

CRYPTO_MATERIAL_FIELDS = frozenset({
    'sign', 'signature', 'q', 'cid', 'timestamp', 'nonce', 'appsign', 'token',
})


def _template_fields(template: Dict[str, Any]) -> Set[str]:
    fields: Set[str] = set()
    plain = template.get('plain_template') or {}
    for bag in ('body_params', 'query_params', 'path_params', 'headers'):
        for k in (plain.get(bag) or {}):
            fields.add(norm_field(k))
    return fields


def verify_binding_test_plan(
    plan: Dict[str, Any],
    *,
    known_paths: Set[str],
    template: Dict[str, Any],
    identity_invariants: List[str],
) -> Tuple[bool, List[str]]:
    errors: List[str] = []
    target = normalize_api_path(plan.get('target_api') or '')
    if not target:
        errors.append('missing_target_api')
    elif known_paths and target not in known_paths:
        errors.append(f'unknown_target_api:{target}')

    mut_field = plan.get('mutation_field') or ''
    nf = norm_field(mut_field)
    if not mut_field:
        errors.append('missing_mutation_field')
    else:
        allowed, reason = field_allowed(mut_field)
        if not allowed:
            errors.append(f'forbidden_mutation_field:{reason}')
        if nf in {norm_field(x) for x in CRYPTO_MATERIAL_FIELDS}:
            errors.append('crypto_material_not_mutable')

    tmpl_fields = _template_fields(template)
    if tmpl_fields and nf and nf not in tmpl_fields:
        # encrypted body may not expose field in plain_template — allow path-inferred
        if not plan.get('path_inferred_subject'):
            errors.append('mutation_field_not_in_template')

    for inv in identity_invariants or plan.get('identity_invariant') or []:
        if norm_field(inv) == nf:
            errors.append(f'identity_invariant_mutated:{inv}')

    for policy in plan.get('candidate_policies') or []:
        if policy not in ALLOWED_CANDIDATE_POLICIES:
            errors.append(f'unknown_candidate_policy:{policy}')

    oracle = plan.get('oracle') or {}
    if oracle.get('type') not in (None, 'sensitive_content_fingerprint', 'subject_field_echo'):
        errors.append('unknown_oracle_type')

    return len(errors) == 0, errors
