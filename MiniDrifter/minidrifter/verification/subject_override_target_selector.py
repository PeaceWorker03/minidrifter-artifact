# -*- coding: utf-8 -*-
"""P4-fix-5 — select wire-level subject fields for sensitive API override tests."""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set

from minidrifter.business_chain.chain_run_context import load_json
from minidrifter.classification.api_plane_classifier import (
    classify_path_to_plane_entry,
    plane_index_by_path,
)
from minidrifter.materials.intake_param_hints import normalize_api_path
from minidrifter.verification.binding_diff_exporter import (
    CREDENTIAL_PARAM_KEYS,
    _all_request_params,
)
from minidrifter.verification.sensitive_replay_context_builder import lookup_replay_context
from minidrifter.verification.template_registry import build_templates_index, resolve_template
from minidrifter.verification.subject_override_fields import (
    ALLOWED_SUBJECT_FIELDS,
    CAUTIOUS_PHONE_FIELDS,
    CRYPTO_TRANSPORT_FIELDS,
    FORBIDDEN_SUBJECT_FIELDS,
    SUBJECT_PRIORITY,
    field_allowed as _field_allowed,
    infer_subject_fields_from_path,
    norm_field as _norm_field,
)

PILOT_PATH_MARKERS = (
    'getuserinfo',
    'personal/info',
    'memberidentityinfo',
    'personaldata',
    'identitycard',
    'byuserid',
    'device/list',
    'invoiceablelist',
)


def _param_locations(template: Dict[str, Any]) -> Dict[str, str]:
    loc: Dict[str, str] = {}
    plain = template.get('plain_template') or {}
    for k in (plain.get('body_params') or {}):
        loc[str(k)] = 'body'
    for k in (plain.get('params') or {}):
        loc[str(k)] = 'query'
    return loc


def _candidate_fields_from_sources(
    template: Dict[str, Any],
    *,
    test_case: Optional[Dict[str, Any]] = None,
    execution: Optional[Dict[str, Any]] = None,
    replay_ctx: Optional[Dict[str, Any]] = None,
    aggregate: Optional[Dict[str, Any]] = None,
    m0_wire_only: bool = False,
) -> List[Dict[str, Any]]:
    locs = _param_locations(template)
    seen: Set[str] = set()
    candidates: List[Dict[str, Any]] = []

    def _add(field: str, value: Any, source: str, location: str) -> None:
        nf = _norm_field(field)
        if not nf or nf in seen:
            return
        if nf in {_norm_field(k) for k in CREDENTIAL_PARAM_KEYS}:
            return
        allowed, reason = _field_allowed(field, value=str(value) if value is not None else None)
        if not allowed:
            return
        seen.add(nf)
        candidates.append({
            'field': field,
            'normalized_field': nf,
            'value': value,
            'source': source,
            'location': location,
            'allowed': True,
            'reason': reason,
        })

    if test_case:
        params = _all_request_params(test_case, execution)
        for k, v in params.items():
            if v is None or str(v).startswith('$'):
                continue
            if _norm_field(k) in {_norm_field(x) for x in CREDENTIAL_PARAM_KEYS}:
                continue
            _add(k, v, 'm0_wire', locs.get(k, 'body' if test_case.get('body_params') else 'query'))

    if m0_wire_only:
        return candidates

    plain = template.get('plain_template') or {}
    for bag_name, bag in (('body', plain.get('body_params')), ('query', plain.get('params'))):
        if isinstance(bag, dict):
            for k, v in bag.items():
                _add(k, v, 'template', bag_name)

    inner = (replay_ctx or {}).get('replay_context') or {}
    for k, v in (inner.get('pool') or {}).items():
        _add(k, v, 'replay_context', 'pool')

    for k, v in (aggregate or {}).get('fields', {}).items():
        _add(k, v, 'aggregate', 'pool')

    return candidates


def _pick_field(candidates: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not candidates:
        return None
    by_norm = {_norm_field(c['field']): c for c in candidates}
    for pref in SUBJECT_PRIORITY:
        c = by_norm.get(_norm_field(pref))
        if c:
            return c
    return candidates[0]


def is_pilot_subject_override_path(path: str) -> bool:
    norm = normalize_api_path(path).lower()
    return any(marker in norm for marker in PILOT_PATH_MARKERS)


def select_subject_override_target(
    path: str,
    *,
    pack_dir,
    template: Dict[str, Any],
    sensitive_read_row: Optional[Dict[str, Any]] = None,
    test_case: Optional[Dict[str, Any]] = None,
    execution: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    """Build one subject override target descriptor for a sensitive API."""
    from pathlib import Path

    pack_dir = Path(pack_dir)
    norm = normalize_api_path(path)
    if not test_case and not is_pilot_subject_override_path(path):
        return None

    idx = plane_index_by_path(pack_dir)
    entry = idx.get(norm) or classify_path_to_plane_entry(path)
    replay_ctx = lookup_replay_context(pack_dir, path)
    aggregate = load_json(pack_dir / 'aggregate_materials.json') or {}

    candidates = _candidate_fields_from_sources(
        template,
        test_case=test_case,
        execution=execution,
        replay_ctx=replay_ctx if not test_case else None,
        aggregate=aggregate if not test_case else None,
        m0_wire_only=bool(test_case),
    )
    selected = _pick_field(candidates)
    if not selected:
        return None

    reasons = ['subject_identifier']
    if sensitive_read_row and sensitive_read_row.get('live_sensitive_read_m0_success'):
        reasons.append('live_m0_success')
    if sensitive_read_row and sensitive_read_row.get('sensitive_read_m0_success'):
        reasons.append('sensitive_read_success')
    if test_case:
        reasons.append('m0_wire_subject_field')

    return {
        'api': path,
        'api_id': template.get('api_id'),
        'plane': entry.get('primary_plane'),
        'campaign_role': entry.get('recommended_campaign_role'),
        'candidate_subject_fields': [c['field'] for c in candidates],
        'selected_field': selected['field'],
        'selected_value': selected.get('value'),
        'source': selected.get('location', 'body'),
        'field_source': selected.get('source'),
        'allowed': True,
        'reason': reasons,
    }


def select_subject_override_targets(
    pack_dir,
    sensitive_read_results: List[Dict[str, Any]],
    *,
    templates_by_id: Dict[str, Dict[str, Any]],
    max_targets: int = 3,
    use_mined_candidates: bool = True,
) -> List[Dict[str, Any]]:
    """Pick subject override targets — prefer mined wire-subject candidates (P4-fix-5.1)."""
    from pathlib import Path

    pack_dir = Path(pack_dir)
    out: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    sens_by_path = {
        normalize_api_path(r.get('path') or ''): r
        for r in sensitive_read_results
        if r.get('path')
    }

    if use_mined_candidates:
        from minidrifter.classification.subject_wire_candidate_miner import load_subject_wire_candidates

        mined = load_subject_wire_candidates(pack_dir)
        for cand in mined.get('candidates') or []:
            path = cand.get('path') or cand.get('api') or ''
            norm = normalize_api_path(path)
            if not path or norm in seen:
                continue
            mutable = [
                f for f in (cand.get('wire_subject_fields') or [])
                if f.get('mutation_allowed')
            ]
            if not mutable:
                continue
            api_id = cand.get('api_id') or ''
            tpl, resolved_id = resolve_template(
                build_templates_index(templates_by_id),
                api_id=api_id,
                path=path,
            )
            if not tpl:
                continue
            api_id = resolved_id or api_id
            if not templates_by_id.get(api_id):
                templates_by_id[api_id] = tpl
            sens_row = sens_by_path.get(norm)
            if sens_row and not sens_row.get('live_sensitive_read_m0_success'):
                if not sens_row.get('sensitive_read_m0_success'):
                    continue
            seen.add(norm)
            best = mutable[0]
            for pref in SUBJECT_PRIORITY:
                for f in mutable:
                    if _norm_field(f.get('field') or '') == _norm_field(pref):
                        best = f
                        break
            out.append({
                'api': path,
                'api_id': api_id,
                'plane': cand.get('plane'),
                'campaign_role': cand.get('campaign_role'),
                'selected_field': best.get('field'),
                'selected_value': None,
                'source': best.get('location'),
                'field_source': 'subject_wire_candidate_miner',
                'allowed': True,
                'reason': list(cand.get('reason') or []) + ['mined_wire_subject_field'],
                'sensitive_read_row': sens_row,
                'wire_candidate': cand,
                'priority': cand.get('priority'),
                'candidate_source': cand.get('source'),
            })

    _SOURCE_RANK = {
        'baseline_capture': 3,
        'sensitive_replay_context': 2,
        'gap_plan_synthetic': 1,
    }
    out.sort(
        key=lambda t: (
            _SOURCE_RANK.get(str(t.get('candidate_source') or ''), 0),
            1 if 'subject_binding_path_shape' in (
                ((t.get('wire_candidate') or {}).get('reason')) or []
            ) else 0,
            float(t.get('priority') or 0),
        ),
        reverse=True,
    )
    if len(out) > max_targets:
        out = out[:max_targets]

    if len(out) < max_targets:
        gap_doc = load_json(pack_dir / 'subject_wire_gap_plan.json') or {}
        for gap in sorted(
            gap_doc.get('gaps') or [],
            key=lambda g: -float(g.get('priority') or 0),
        ):
            path = gap.get('path') or gap.get('api') or ''
            norm = normalize_api_path(path)
            if not path or norm in seen:
                continue
            api_id = gap.get('api_id') or ''
            tpl, resolved_id = resolve_template(
                build_templates_index(templates_by_id),
                api_id=api_id,
                path=path,
            )
            if not tpl:
                continue
            api_id = resolved_id or api_id
            fields = list(gap.get('static_subject_fields') or [])
            for inf in infer_subject_fields_from_path(path):
                if inf not in fields:
                    fields.append(inf)
            if not fields:
                continue
            best_field = fields[0]
            for pref in SUBJECT_PRIORITY:
                for f in fields:
                    if _norm_field(f) == _norm_field(pref):
                        best_field = f
                        break
            sens_row = sens_by_path.get(norm)
            seen.add(norm)
            out.append({
                'api': path,
                'api_id': api_id,
                'plane': gap.get('plane'),
                'campaign_role': gap.get('campaign_role'),
                'selected_field': best_field,
                'selected_value': None,
                'source': 'body',
                'field_source': 'subject_wire_gap_plan',
                'allowed': True,
                'reason': ['gap_plan_static_subject_field', *(gap.get('why_useful') or [])[:2]],
                'sensitive_read_row': sens_row,
                'priority': gap.get('priority'),
            })
            if len(out) >= max_targets:
                return out

    for row in sensitive_read_results:
        path = row.get('path') or ''
        norm = normalize_api_path(path)
        if not path or norm in seen:
            continue
        if not is_pilot_subject_override_path(path):
            continue
        if not row.get('live_sensitive_read_m0_success'):
            continue
        api_id = row.get('api_id') or ''
        template = templates_by_id.get(api_id)
        if not template:
            continue
        entry = classify_path_to_plane_entry(path)
        seen.add(norm)
        out.append({
            'api': path,
            'api_id': api_id,
            'plane': row.get('primary_plane') or entry.get('primary_plane'),
            'campaign_role': entry.get('recommended_campaign_role'),
            'sensitive_read_row': row,
        })

    return out[:max_targets]
