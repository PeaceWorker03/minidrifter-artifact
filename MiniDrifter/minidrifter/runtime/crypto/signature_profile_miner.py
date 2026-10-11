# -*- coding: utf-8 -*-
"""P5 — synthesize signature_profile.json from static mining + capture verification."""
from __future__ import annotations

import itertools
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from minidrifter.core.utils import write_json
from minidrifter.materials.intake_param_hints import load_intake_report
from minidrifter.runtime.crypto.signature_recipes import (
    RECIPE_CATALOG,
    SignatureRecipe,
    build_sign_input,
    clone_recipe,
    compute_recipe_signature,
    verify_capture_against_recipe,
)
from minidrifter.runtime.crypto.signature_static_mine import mine_signature_static_evidence

SIGNATURE_FIELD_NAMES = frozenset({'signature', 'sign'})


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _parse_capture_wire(capture: Dict[str, Any]) -> Tuple[str, str, Dict[str, str], str]:
    method = str(capture.get('method') or 'GET').upper()
    path = str(capture.get('path') or '')
    proc = capture.get('crypto_processing') or {}
    resolved = proc.get('resolved_fields') or {}
    decrypted = proc.get('decrypted') or {}
    query = decrypted.get('query') if isinstance(decrypted.get('query'), dict) else {}
    body = decrypted.get('body_form')
    params: Dict[str, str] = {}
    if isinstance(query, dict):
        params.update({str(k): str(v) for k, v in query.items() if v is not None})
    if isinstance(body, str) and body.strip().startswith('{'):
        try:
            parsed = json.loads(body)
            if isinstance(parsed, dict):
                params.update({str(k): str(v) for k, v in parsed.items() if v is not None})
        except json.JSONDecodeError:
            pass
    if not params:
        params.update({str(k): str(v) for k, v in resolved.items() if v not in (None, '')})
    sig = ''
    for key in SIGNATURE_FIELD_NAMES:
        if key in params:
            sig = str(params[key])
            break
    return method, path, params, sig


def _collect_signature_samples(pack_dir: Path, *, limit: int = 24) -> List[Dict[str, Any]]:
    report = load_intake_report(pack_dir)
    samples: List[Dict[str, Any]] = []
    for capture in report.get('captures') or []:
        method, path, params, sig = _parse_capture_wire(capture)
        if not sig or not path:
            continue
        unsigned = {k: v for k, v in params.items() if k not in SIGNATURE_FIELD_NAMES}
        samples.append({
            'capture_index': capture.get('capture_index'),
            'method': method,
            'path': path,
            'host': capture.get('host'),
            'params': unsigned,
            'expected_signature': sig,
        })
        if len(samples) >= limit:
            break
    return samples


def _infer_covered_fields(samples: Sequence[Dict[str, Any]]) -> List[str]:
    keys = set()
    for sample in samples:
        keys.update(sample.get('params') or {})
    return sorted(keys)


def _secret_candidates(
    samples: Sequence[Dict[str, Any]],
    static_evidence: Dict[str, Any],
    baseline_pool: Optional[Dict[str, str]] = None,
) -> List[Tuple[str, str]]:
    pool = dict(baseline_pool or {})
    for sample in samples:
        for k, v in (sample.get('params') or {}).items():
            pool.setdefault(k, v)
    vals = [v for v in pool.values() if v]
    hosts = sorted({str(s.get('host') or '') for s in samples if s.get('host')})
    if hosts:
        vals.extend(hosts)
        vals.extend(f'https://{h}' for h in hosts if h and not str(h).startswith('http'))
    for lit in static_evidence.get('literal_secrets') or []:
        vals.append(str(lit))
    vals = [v for v in vals if v]
    out: List[Tuple[str, str]] = []
    seen = set()
    for v in vals:
        if v not in seen:
            seen.add(v)
            out.append(('literal', v))
    for r in range(2, min(5, len(vals) + 1)):
        for perm in itertools.permutations(vals, r):
            joined = ''.join(perm)
            if joined not in seen and len(joined) >= 16:
                seen.add(joined)
                out.append(('perm_join', joined))
    return out[:500]


def _suffix_candidates(pool: Dict[str, str]) -> List[str]:
    base = ['', '&', pool.get('apiToken', ''), f'&apiToken={pool.get("apiToken", "")}']
    for key in ('userId', 'appletId', 'apiToken', 'server'):
        val = pool.get(key)
        if val:
            base.extend([val, f'&{val}', f'&{key}={val}'])
    return list(dict.fromkeys(x for x in base if x is not None))


def _recipe_variants(static_evidence: Dict[str, Any]) -> List[SignatureRecipe]:
    groups = static_evidence.get('salt_index_groups') or []
    variants: List[SignatureRecipe] = []
    if groups:
        tuples = tuple(tuple(int(x) for x in g) for g in groups[:3])
        variants.append(clone_recipe(
            RECIPE_CATALOG['method_path_sorted_brace_salt_md5'],
            salt_index_groups=tuples,
        ))
        variants.append(clone_recipe(
            RECIPE_CATALOG['method_path_sorted_brace_salt_md5'],
            salt_index_groups=tuples,
            path_mode='full_url',
        ))
    variants.extend([
        clone_recipe(RECIPE_CATALOG['sorted_params_secret_append_md5']),
        clone_recipe(RECIPE_CATALOG['method_path_sorted_secret_append_md5']),
        clone_recipe(RECIPE_CATALOG['method_path_sorted_brace_salt_md5']),
    ])
    return variants


def _fit_recipe(
    samples: Sequence[Dict[str, Any]],
    recipes: Sequence[SignatureRecipe],
    secret_candidates: Sequence[Tuple[str, str]],
    *,
    suffix_candidates: Sequence[str],
) -> Optional[Dict[str, Any]]:
    if not samples:
        return None
    best: Optional[Dict[str, Any]] = None
    for recipe in recipes:
        for src, secret in secret_candidates:
            if recipe.salt_index_groups:
                max_idx = max(i for grp in recipe.salt_index_groups for i in grp)
                if len(secret) <= max_idx:
                    continue
            suffix_opts = suffix_candidates if recipe.input_template.endswith('brace_salt') else ['']
            for suffix in suffix_opts:
                matched = 0
                for sample in samples:
                    host = sample.get('host')
                    r = clone_recipe(recipe, extras={**recipe.extras, 'host': f'https://{host}' if host else ''})
                    if verify_capture_against_recipe(
                        r,
                        method=sample['method'],
                        path=sample['path'],
                        params=sample['params'],
                        expected_signature=sample['expected_signature'],
                        secret=secret,
                        suffix_value=suffix,
                    ):
                        matched += 1
                if matched == 0:
                    continue
                confidence = matched / len(samples)
                row = {
                    'recipe': recipe,
                    'secret': secret,
                    'secret_source': src,
                    'suffix_value': suffix,
                    'matched': matched,
                    'total': len(samples),
                    'confidence': round(confidence, 4),
                }
                if best is None or row['confidence'] > best['confidence'] or (
                    row['confidence'] == best['confidence'] and row['matched'] > best['matched']
                ):
                    best = row
    return best


def mine_signature_profile(
    pack_dir: Path,
    *,
    source_dir: Optional[Path] = None,
    baseline_pool: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    pack_dir = Path(pack_dir)
    static_evidence = mine_signature_static_evidence(pack_dir=pack_dir, source_dir=source_dir)
    samples = _collect_signature_samples(pack_dir)
    covered_fields = _infer_covered_fields(samples)
    pool = dict(baseline_pool or {})
    for sample in samples:
        pool.update(sample.get('params') or {})

    secret_candidates = _secret_candidates(samples, static_evidence, pool)
    recipes = _recipe_variants(static_evidence)
    fit = _fit_recipe(samples, recipes, secret_candidates, suffix_candidates=_suffix_candidates(pool))

    profile: Dict[str, Any] = {
        'schema_version': '1.0.0',
        'generated_at': _utc_now(),
        'pack_dir': str(pack_dir),
        'source_dir': str(source_dir) if source_dir else None,
        'signature_profile_id': None,
        'algorithm': 'md5',
        'param_order': 'lexicographic',
        'covered_fields': covered_fields,
        'sign_fields': {
            'signature': 'signature',
            'nonce': 'nonce',
            'timestamp': 'timestamp',
        },
        'secret_source': None,
        'can_recompute_signature': False,
        'confidence': 0.0,
        'verification': {
            'sample_count': len(samples),
            'matched_count': 0,
            'exact_replay_consistent': False,
        },
        'static_evidence': static_evidence,
        'recipe': None,
        'reason': 'no_verified_recipe',
    }

    if static_evidence.get('salt_index_groups'):
        profile['signature_profile_id'] = 'method_path_sorted_brace_salt_md5'
        profile['recipe'] = {
            'recipe_id': 'method_path_sorted_brace_salt_md5',
            'input_template': 'method_path_sorted_brace_salt',
            'salt_index_groups': static_evidence['salt_index_groups'],
            'path_mode': 'path_only',
        }

    if fit and fit['confidence'] >= 1.0:
        recipe: SignatureRecipe = fit['recipe']
        profile.update({
            'signature_profile_id': recipe.recipe_id,
            'algorithm': recipe.algorithm,
            'param_order': recipe.param_order,
            'secret_source': fit['secret_source'],
            'can_recompute_signature': True,
            'confidence': fit['confidence'],
            'verification': {
                'sample_count': fit['total'],
                'matched_count': fit['matched'],
                'exact_replay_consistent': fit['matched'] == fit['total'],
                'suffix_value': fit['suffix_value'],
            },
            'recipe': {
                'recipe_id': recipe.recipe_id,
                'input_template': recipe.input_template,
                'path_mode': recipe.path_mode,
                'salt_index_groups': [list(g) for g in recipe.salt_index_groups],
                'suffix_template': recipe.suffix_template or fit['suffix_value'],
                'exclude_fields': list(recipe.exclude_fields),
            },
            'reason': 'verified_against_baseline_captures',
        })
        if fit['secret_source'] != 'literal' or len(fit['secret']) <= 64:
            profile['secret_preview'] = fit['secret'][:8] + '…' if len(fit['secret']) > 8 else fit['secret']
    elif static_evidence.get('function_hits'):
        profile['reason'] = 'static_signature_logic_found_secret_unresolved'
        profile['confidence'] = 0.35 if static_evidence.get('salt_index_groups') else 0.2
    elif samples:
        profile['reason'] = 'captures_have_signature_static_logic_missing'
        profile['confidence'] = 0.1

    return profile


def emit_signature_profile(
    pack_dir: Path,
    *,
    source_dir: Optional[Path] = None,
    baseline_pool: Optional[Dict[str, str]] = None,
) -> Path:
    doc = mine_signature_profile(pack_dir, source_dir=source_dir, baseline_pool=baseline_pool)
    out = Path(pack_dir) / 'signature_profile.json'
    write_json(out, doc)
    return out


def recompute_signature_for_request(
    profile: Dict[str, Any],
    *,
    method: str,
    path: str,
    params: Dict[str, Any],
    secret: str,
    suffix_value: str = '',
) -> Optional[str]:
    if not profile.get('can_recompute_signature'):
        return None
    recipe_doc = profile.get('recipe') or {}
    groups = tuple(tuple(int(x) for x in g) for g in recipe_doc.get('salt_index_groups') or [])
    recipe = SignatureRecipe(
        recipe_id=str(recipe_doc.get('recipe_id') or profile.get('signature_profile_id') or 'custom'),
        algorithm=str(profile.get('algorithm') or 'md5'),
        param_order=str(profile.get('param_order') or 'lexicographic'),
        input_template=str(recipe_doc.get('input_template') or 'method_path_sorted_brace_salt'),
        path_mode=str(recipe_doc.get('path_mode') or 'path_only'),
        salt_index_groups=groups,
        suffix_template=str(recipe_doc.get('suffix_template') or suffix_value),
        exclude_fields=tuple(recipe_doc.get('exclude_fields') or ('signature', 'sign')),
    )
    sign_input = build_sign_input(
        recipe,
        method=method,
        path=path,
        params=params,
        secret=secret,
        suffix_value=suffix_value or str((profile.get('verification') or {}).get('suffix_value') or ''),
    )
    return compute_recipe_signature(recipe, sign_input)
