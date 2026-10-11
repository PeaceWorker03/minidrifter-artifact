# -*- coding: utf-8 -*-
"""Generic signature recipe templates and verification helpers."""
from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from minidrifter.runtime.crypto.sign_engines import compute_sign


@dataclass
class SignatureRecipe:
    recipe_id: str
    algorithm: str
    param_order: str = 'lexicographic'
    exclude_fields: Tuple[str, ...] = ('signature', 'sign')
    nonce_field: str = 'nonce'
    timestamp_field: str = 'timestamp'
    signature_field: str = 'signature'
    path_mode: str = 'path_only'  # path_only | full_url
    input_template: str = 'method_path_sorted_brace_salt'
    salt_index_groups: Tuple[Tuple[int, ...], ...] = ()
    suffix_template: str = ''
    sign_method: Optional[str] = None
    extras: Dict[str, Any] = field(default_factory=dict)


def _sorted_kv_string(params: Dict[str, Any], exclude: Sequence[str]) -> str:
    parts: List[str] = []
    for key in sorted(params.keys()):
        if key in exclude:
            continue
        val = params[key]
        if val is None:
            continue
        if isinstance(val, (dict, list)):
            val = json.dumps(val, ensure_ascii=False, separators=(',', ':'))
        parts.append(f'{key}={val}&')
    return ''.join(parts)


def _salt_from_indices(secret: str, groups: Sequence[Sequence[int]]) -> str:
    out = ''
    for group in groups:
        out += ''.join(secret[i] for i in group if 0 <= i < len(secret))
    return out


def _normalize_path(path: str, *, strip_trailing_slash: bool = True) -> str:
    p = path.split('?', 1)[0]
    if strip_trailing_slash and p.endswith('/'):
        p = p[:-1]
    return p


def build_sign_input(
    recipe: SignatureRecipe,
    *,
    method: str,
    path: str,
    params: Dict[str, Any],
    secret: str,
    suffix_value: str = '',
) -> str:
    exclude = set(recipe.exclude_fields)
    body = _sorted_kv_string(params, exclude)
    salt = _salt_from_indices(secret, recipe.salt_index_groups) if recipe.salt_index_groups else secret
    suffix = recipe.suffix_template.replace('{suffix_value}', suffix_value)
    route = _normalize_path(path)
    if recipe.path_mode == 'full_url' and not route.startswith('http'):
        host = str(recipe.extras.get('host') or '')
        if host:
            route = f'{host.rstrip("/")}{route}'
    prefix = f'{method.upper()}{route}'

    if recipe.input_template == 'method_path_sorted_brace_salt':
        return f'{prefix}{body}{suffix}{{{salt}}}'
    if recipe.input_template == 'sorted_params_secret_append':
        return f'{body}{secret}'
    if recipe.input_template == 'method_path_sorted_secret_append':
        return f'{prefix}{body}{secret}'
    if recipe.input_template == 'sorted_params_only':
        return body.rstrip('&')
    raise ValueError(f'unknown input_template: {recipe.input_template}')


def compute_recipe_signature(
    recipe: SignatureRecipe,
    sign_input: str,
) -> str:
    algo = (recipe.algorithm or 'md5').lower()
    if algo == 'md5':
        if recipe.sign_method:
            return compute_sign(sign_input, method=recipe.sign_method)
        return hashlib.md5(sign_input.encode('utf-8')).hexdigest()
    if algo == 'hmac-sha256':
        secret = str(recipe.extras.get('hmac_secret') or '')
        return hmac.new(secret.encode('utf-8'), sign_input.encode('utf-8'), hashlib.sha256).hexdigest()
    raise ValueError(f'unknown algorithm: {recipe.algorithm}')


def verify_capture_against_recipe(
    recipe: SignatureRecipe,
    *,
    method: str,
    path: str,
    params: Dict[str, Any],
    expected_signature: str,
    secret: str,
    suffix_value: str = '',
) -> bool:
    sign_input = build_sign_input(
        recipe,
        method=method,
        path=path,
        params=params,
        secret=secret,
        suffix_value=suffix_value,
    )
    got = compute_recipe_signature(recipe, sign_input)
    return got.lower() == str(expected_signature).lower()


RECIPE_CATALOG: Dict[str, SignatureRecipe] = {
    'method_path_sorted_brace_salt_md5': SignatureRecipe(
        recipe_id='method_path_sorted_brace_salt_md5',
        algorithm='md5',
        input_template='method_path_sorted_brace_salt',
    ),
    'sorted_params_secret_append_md5': SignatureRecipe(
        recipe_id='sorted_params_secret_append_md5',
        algorithm='md5',
        input_template='sorted_params_secret_append',
    ),
    'method_path_sorted_secret_append_md5': SignatureRecipe(
        recipe_id='method_path_sorted_secret_append_md5',
        algorithm='md5',
        input_template='method_path_sorted_secret_append',
    ),
}


def clone_recipe(recipe: SignatureRecipe, **updates: Any) -> SignatureRecipe:
    data = recipe.__dict__.copy()
    data.update(updates)
    return SignatureRecipe(**data)
