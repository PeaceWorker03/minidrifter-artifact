# -*- coding: utf-8 -*-
"""P4-fix-5.1 — mine sensitive APIs with real subject identifiers on request wire."""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from minidrifter.business_chain.chain_run_context import load_json
from minidrifter.classification.api_plane_classifier import (
    classify_path_to_plane_entry,
    plane_index_by_path,
)
from minidrifter.core.utils import write_json
from minidrifter.materials.intake_param_hints import normalize_api_path
from minidrifter.verification.binding_diff_exporter import CREDENTIAL_PARAM_KEYS
from minidrifter.verification.sensitive_api_oracle import analyze_sensitive_response
from minidrifter.verification.subject_override_fields import (
    CAUTIOUS_PHONE_FIELDS,
    CRYPTO_TRANSPORT_FIELDS,
    FORBIDDEN_SUBJECT_FIELDS,
    field_allowed,
    infer_subject_fields_from_path,
    norm_field as _norm_field,
    pool_value_for_subject_field,
)

SCHEMA_VERSION = '1.0.0'

SENSITIVE_PLANES = frozenset({
    'user_profile_personal_info',
    'realname_verification',
    'account_state_wallet',
    'contact_address_invoice',
    'business_object',
})

SENSITIVE_ROLES = frozenset({
    'read_sensitive_state',
    'account_state_probe',
    'verification_state_probe',
})

PRIMARY_SUBJECT_FIELDS = frozenset({
    'memberid', 'customerid', 'logincustomerid', 'userid', 'accountid', 'subjectid', 'personid',
})

SECONDARY_SUBJECT_FIELDS = frozenset({
    'openid', 'unionid',
})

LOGIN_PATH_RE = re.compile(r'login|federated|openid|bindphone|bind.?phone', re.I)
WRITE_PATH_RE = re.compile(
    r'(create|update|delete|save|submit|bind|unbind|modify|set|add|remove|cancel|pay|refund)',
    re.I,
)

OUTER_TRANSPORT_KEYS = frozenset({
    'cid', 'q', 'sign', 'signature', 'uid', 'token', 'nonce', 'timestamp', 'timespan', 'host',
})


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _redact_sample(value: Any) -> str:
    s = str(value or '')
    if len(s) <= 4:
        return '***'
    if len(s) <= 8:
        return f'{s[:2]}***'
    return f'{s[:3]}***{s[-2:]}'


def _parse_json_obj(raw: Any) -> Optional[Dict[str, Any]]:
    if isinstance(raw, dict):
        return raw
    if not isinstance(raw, str) or not raw.strip():
        return None
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return obj if isinstance(obj, dict) else None


def _iter_kv(obj: Any, *, location: str, source: str) -> List[Tuple[str, Any, str, str]]:
    out: List[Tuple[str, Any, str, str]] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if v is None or isinstance(v, (dict, list)):
                continue
            out.append((str(k), v, location, source))
    return out


def _wire_fields_from_capture(cap: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract request wire fields from one intake capture (never response-only)."""
    rows: List[Dict[str, Any]] = []
    seen: Set[str] = set()

    def _add(field: str, value: Any, location: str, source: str) -> None:
        nf = _norm_field(field)
        if not nf or nf in seen:
            return
        if nf in CRYPTO_TRANSPORT_FIELDS and location in {'form_body', 'outer_form', 'body_form'}:
            return
        seen.add(nf)
        rows.append({
            'field': field,
            'location': location,
            'value': value,
            'source': source,
        })

    for layer in cap.get('field_layers') or []:
        loc = str(layer.get('location') or '')
        name = layer.get('name')
        val = layer.get('value')
        if not name or val is None:
            continue
        wire_loc = {
            'query': 'query_params',
            'body': 'body_form',
            'header': 'header',
        }.get(loc, loc)
        _add(name, val, wire_loc, 'field_layers')

    qf = cap.get('query_fields')
    if isinstance(qf, dict):
        for k, v in qf.items():
            _add(k, v, 'query_params', 'query_fields')
    elif isinstance(qf, list):
        for item in qf:
            if isinstance(item, dict):
                _add(item.get('name') or item.get('field'), item.get('value'), 'query_params', 'query_fields')

    crypto = cap.get('crypto_processing') or {}
    resolved = crypto.get('resolved_fields') or {}
    decrypted = crypto.get('decrypted') or {}

    q_raw = decrypted.get('query')
    if isinstance(q_raw, dict):
        for k, v, loc, src in _iter_kv(q_raw, location='query_params', source='baseline_capture'):
            _add(k, v, loc, src)
    elif isinstance(q_raw, str) and q_raw.strip():
        from minidrifter.runtime.crypto.common import parse_kv_string
        for k, v in parse_kv_string(q_raw).items():
            _add(k, v, 'query_params', 'baseline_capture')

    for blob_key in ('body_form', 'body'):
        inner = _parse_json_obj(decrypted.get(blob_key))
        if inner:
            for k, v, loc, src in _iter_kv(inner, location='body_form', source='baseline_capture'):
                _add(k, v, loc, src)

    for k, v in resolved.items():
        nk = _norm_field(k)
        if nk in OUTER_TRANSPORT_KEYS and nk not in PRIMARY_SUBJECT_FIELDS | SECONDARY_SUBJECT_FIELDS:
            continue
        loc = 'body_form' if nk not in OUTER_TRANSPORT_KEYS else 'outer_form'
        _add(k, v, loc, 'baseline_capture_resolved')

    transport = cap.get('transport_snapshot') or {}
    for k, v in transport.items():
        if _norm_field(k) in OUTER_TRANSPORT_KEYS:
            continue
        _add(k, v, 'outer_form', 'transport_snapshot')

    return rows


def _wire_fields_from_replay_entry(entry: Dict[str, Any]) -> List[Dict[str, Any]]:
    ctx = entry.get('replay_context') or {}
    rows: List[Dict[str, Any]] = []
    seen: Set[str] = set()

    def _add(field: str, value: Any, location: str) -> None:
        nf = _norm_field(field)
        if not nf or nf in seen or value is None:
            return
        seen.add(nf)
        rows.append({
            'field': field,
            'location': location,
            'value': value,
            'source': 'sensitive_replay_context',
        })

    for k, v in (ctx.get('query') or {}).items():
        _add(k, v, 'query')
    for k, v in (ctx.get('body') or {}).items():
        _add(k, v, 'json_body')
    return rows


def _classify_wire_subject_field(
    field: str,
    value: Any,
    *,
    location: str,
    path: str,
) -> Optional[Dict[str, Any]]:
    allowed, reason = field_allowed(field, value=str(value) if value is not None else None)
    if not allowed:
        return None
    nf = _norm_field(field)
    if nf in FORBIDDEN_SUBJECT_FIELDS:
        return None
    if nf in {_norm_field(k) for k in CREDENTIAL_PARAM_KEYS} and location in {'outer_form', 'form_body'}:
        return None
    if nf in CAUTIOUS_PHONE_FIELDS:
        sv = str(value or '')
        if '*' not in sv and '****' not in sv:
            return None
        reason = 'masked_phone_in_request'

    mutation_allowed = True
    if nf in SECONDARY_SUBJECT_FIELDS and LOGIN_PATH_RE.search(path or ''):
        mutation_allowed = False
        reason = f'{reason};login_bootstrap_deferred'
    if nf == 'uid' and location in {'outer_form', 'form_body'}:
        mutation_allowed = False
        reason = f'{reason};credential_uid_outer_form'

    field_type = 'subject_identifier'
    if nf in CAUTIOUS_PHONE_FIELDS:
        field_type = 'masked_phone'

    return {
        'field': field,
        'location': location,
        'value_sample': _redact_sample(value),
        'field_type': field_type,
        'mutation_allowed': mutation_allowed,
        'signature_covered': 'unknown',
        'classification_reason': reason,
    }


def _is_sensitive_api(
    path: str,
    entry: Dict[str, Any],
    *,
    sensitive_response_fields: List[str],
    live_m0: bool,
    risk_paths: Set[str],
    wire_subject_fields: Optional[List[Dict[str, Any]]] = None,
    has_response_body: bool = False,
) -> Tuple[bool, List[str]]:
    reasons: List[str] = []
    planes = set(entry.get('planes') or [])
    role = entry.get('recommended_campaign_role') or ''
    wire_subject_fields = wire_subject_fields or []
    mutable_wire = any(f.get('mutation_allowed') for f in wire_subject_fields)
    if planes & SENSITIVE_PLANES:
        reasons.append('sensitive_plane')
    if role in SENSITIVE_ROLES:
        reasons.append('sensitive_campaign_role')
    if sensitive_response_fields:
        reasons.append('sensitive_response_fields')
    if live_m0:
        reasons.append('m0_sensitive_read_success')
    norm = normalize_api_path(path)
    if norm in risk_paths:
        reasons.append('high_risk_api_chain')
    if mutable_wire and infer_subject_fields_from_path(path):
        reasons.append('subject_binding_path_shape')
    if mutable_wire and has_response_body:
        reasons.append('wire_subject_with_response_body')
    return bool(reasons), reasons


def _priority_score(
    *,
    entry: Dict[str, Any],
    path: str,
    wire_fields: List[Dict[str, Any]],
    sensitive_response_fields: List[str],
    live_m0: bool,
    materialized: bool,
) -> float:
    score = 0.0
    planes = set(entry.get('planes') or [])
    if planes & SENSITIVE_PLANES:
        score += 0.35
    if entry.get('recommended_campaign_role') in SENSITIVE_ROLES:
        score += 0.15
    if live_m0:
        score += 0.25
    if sensitive_response_fields:
        score += min(0.2, 0.05 * len(sensitive_response_fields))
    if materialized:
        score += 0.1

    for wf in wire_fields:
        nf = _norm_field(wf.get('field') or '')
        if nf in PRIMARY_SUBJECT_FIELDS and wf.get('mutation_allowed'):
            score += 0.35
        elif nf in SECONDARY_SUBJECT_FIELDS and wf.get('mutation_allowed'):
            score += 0.1

    if infer_subject_fields_from_path(path):
        score += 0.25

    if LOGIN_PATH_RE.search(path or ''):
        score -= 0.25
    side = entry.get('side_effect') or ''
    if side in {'S2_state_changing', 'S3_destructive', 'state_changing', 'write'}:
        score -= 0.3
    elif WRITE_PATH_RE.search(path or ''):
        score -= 0.15

    if any(_norm_field(wf.get('field') or '') in FORBIDDEN_SUBJECT_FIELDS for wf in wire_fields):
        score -= 1.0

    return round(max(0.0, score), 3)


def _sensitive_read_index(pack_dir: Path) -> Dict[str, Dict[str, Any]]:
    doc = load_json(pack_dir / 'sensitive_read_report.json') or {}
    out: Dict[str, Dict[str, Any]] = {}
    for row in doc.get('results') or []:
        p = normalize_api_path(row.get('path') or '')
        if p:
            out[p] = row
    return out


def _risk_api_paths(pack_dir: Path) -> Set[str]:
    cov = load_json(pack_dir / 'binding_coverage_report.json') or {}
    risk = cov.get('risk_coverage') or {}
    paths: Set[str] = set()
    for key in ('covered_paths', 'attempted_paths', 'uncovered_paths', 'probe_eligible_paths'):
        for p in risk.get(key) or []:
            paths.add(normalize_api_path(p))
    batch = load_json(pack_dir / 'chain_batch_report.json') or {}
    for row in batch.get('chain_results') or []:
        if row.get('target_path'):
            paths.add(normalize_api_path(row['target_path']))
    return paths


def _materialized_paths(pack_dir: Path) -> Dict[str, str]:
    doc = load_json(pack_dir / 'materialized_api_templates.json') or {}
    out: Dict[str, str] = {}
    for t in doc.get('templates') or []:
        p = normalize_api_path(t.get('path') or '')
        if p and t.get('api_id'):
            out[p] = str(t['api_id'])
    return out


def _merge_gap_plan_synthetic_candidates(
    pack_dir: Path,
    *,
    by_path: Dict[str, Dict[str, Any]],
    merge_fn,
    plane_idx: Dict[str, Any],
    sens_read: Dict[str, Dict[str, Any]],
    risk_paths: Set[str],
    mat_paths: Dict[str, str],
    intake: Dict[str, Any],
) -> None:
    """Synthesize wire-subject rows from gap plan + baseline pool (no capture required)."""
    gap_doc = load_json(pack_dir / 'subject_wire_gap_plan.json') or {}
    aggregate = load_json(pack_dir / 'aggregate_materials.json') or {}
    baseline = load_json(pack_dir / 'baseline_runtime_context.json') or {}
    pool: Dict[str, str] = {}
    for k, v in (aggregate.get('fields') or {}).items():
        if v not in (None, ''):
            pool[str(k)] = str(v)
    for k, v in (baseline.get('resolved_fields') or {}).items():
        if isinstance(v, dict) and v.get('value') not in (None, ''):
            pool[str(k)] = str(v['value'])

    tpl_by_path: Dict[str, Dict[str, Any]] = {}
    for tpl in (load_json(pack_dir / 'materialized_api_templates.json') or {}).get('templates') or []:
        p = normalize_api_path(tpl.get('path') or '')
        if p:
            tpl_by_path[p] = tpl

    for gap in gap_doc.get('gaps') or []:
        path = gap.get('path') or gap.get('api') or ''
        norm = normalize_api_path(path)
        if not norm:
            continue
        static_fields = list(gap.get('static_subject_fields') or [])
        for inf in infer_subject_fields_from_path(path):
            if inf not in static_fields:
                static_fields.append(inf)
        if not static_fields:
            continue

        template = tpl_by_path.get(norm)
        plain = (template or {}).get('plain_template') or {}
        method = str(plain.get('method') or gap.get('method') or 'POST').upper()
        default_loc = 'query_params' if method == 'GET' else 'decrypted_body'

        wire_rows: List[Dict[str, Any]] = []
        for field in static_fields:
            val = pool_value_for_subject_field(field, pool)
            if not val:
                continue
            loc = default_loc
            for bag_name, bag in (('decrypted_body', plain.get('body_params')), ('query_params', plain.get('params'))):
                if isinstance(bag, dict):
                    for k in bag:
                        if _norm_field(k) == _norm_field(field):
                            loc = bag_name
                            field = str(k)
                            break
            wire_rows.append({
                'field': field,
                'value': val,
                'location': loc,
                'source': 'gap_plan_pool',
            })
        if wire_rows:
            merge_fn(
                path,
                source='gap_plan_synthetic',
                capture_index=None,
                wire_rows=wire_rows,
            )


def mine_subject_wire_candidates(
    pack_dir: Path,
    *,
    write: bool = True,
) -> Dict[str, Any]:
    """Scan intake / replay context for sensitive APIs with wire-level subject fields."""
    pack_dir = Path(pack_dir)
    intake = load_json(pack_dir / 'baseline_intake_report.json') or {}
    plane_idx = plane_index_by_path(pack_dir)
    sens_read = _sensitive_read_index(pack_dir)
    risk_paths = _risk_api_paths(pack_dir)
    mat_paths = _materialized_paths(pack_dir)
    replay_doc = load_json(pack_dir / 'sensitive_replay_context.json') or {}

    by_path: Dict[str, Dict[str, Any]] = {}

    def _merge_candidate(
        path: str,
        *,
        source: str,
        capture_index: Optional[int],
        wire_rows: List[Dict[str, Any]],
    ) -> None:
        norm = normalize_api_path(path)
        if not norm or not wire_rows:
            return

        subject_fields: List[Dict[str, Any]] = []
        for row in wire_rows:
            classified = _classify_wire_subject_field(
                row['field'], row['value'], location=row['location'], path=path,
            )
            if classified:
                subject_fields.append(classified)
        if not subject_fields:
            return

        entry = plane_idx.get(norm) or classify_path_to_plane_entry(path)
        resp_body = None
        if capture_index is not None:
            for cap in intake.get('captures') or []:
                if cap.get('capture_index') == capture_index:
                    proc = cap.get('response_crypto_processing') or {}
                    resp_body = proc.get('body_json')
                    break
        sens = analyze_sensitive_response(path=path, body=resp_body) if resp_body else {'sensitive_fields': []}
        sens_fields = list(sens.get('sensitive_fields') or [])
        live_m0 = bool((sens_read.get(norm) or {}).get('live_sensitive_read_m0_success'))
        eligible, elig_reasons = _is_sensitive_api(
            path, entry,
            sensitive_response_fields=sens_fields,
            live_m0=live_m0,
            risk_paths=risk_paths,
            wire_subject_fields=subject_fields,
            has_response_body=isinstance(resp_body, dict) and bool(resp_body),
        )
        if not eligible:
            return

        reasons = ['wire_subject_field_present', *elig_reasons]
        priority = _priority_score(
            entry=entry,
            path=path,
            wire_fields=subject_fields,
            sensitive_response_fields=sens_fields,
            live_m0=live_m0,
            materialized=norm in mat_paths,
        )
        cand = {
            'api': path,
            'path': path,
            'api_id': entry.get('api_id') or mat_paths.get(norm),
            'plane': entry.get('primary_plane'),
            'campaign_role': entry.get('recommended_campaign_role'),
            'source': source,
            'capture_index': capture_index,
            'wire_subject_fields': subject_fields,
            'sensitive_response_fields': sens_fields[:12],
            'm0_live_success': live_m0,
            'materialized': norm in mat_paths,
            'priority': priority,
            'reason': reasons,
        }
        prev = by_path.get(norm)
        if not prev or priority > float(prev.get('priority') or 0):
            by_path[norm] = cand

    for cap in intake.get('captures') or []:
        path = cap.get('path') or ''
        if not path:
            continue
        wire_rows = _wire_fields_from_capture(cap)
        _merge_candidate(
            path,
            source='baseline_capture',
            capture_index=cap.get('capture_index'),
            wire_rows=wire_rows,
        )

    for entry in replay_doc.get('entries') or []:
        path = entry.get('api') or entry.get('path') or ''
        if not path:
            continue
        wire_rows = _wire_fields_from_replay_entry(entry)
        _merge_candidate(
            path,
            source='sensitive_replay_context',
            capture_index=entry.get('capture_index'),
            wire_rows=wire_rows,
        )

    seen_replay = {
        normalize_api_path(e.get('api') or e.get('path') or '')
        for e in (replay_doc.get('entries') or [])
    }
    for path_key, entry in (replay_doc.get('by_path') or {}).items():
        path = entry.get('api') or entry.get('path') or path_key
        norm = normalize_api_path(path)
        if not path or norm in seen_replay:
            continue
        wire_rows = _wire_fields_from_replay_entry(entry)
        _merge_candidate(
            path,
            source='sensitive_replay_context',
            capture_index=entry.get('capture_index'),
            wire_rows=wire_rows,
        )

    _merge_gap_plan_synthetic_candidates(
        pack_dir,
        by_path=by_path,
        merge_fn=_merge_candidate,
        plane_idx=plane_idx,
        sens_read=sens_read,
        risk_paths=risk_paths,
        mat_paths=mat_paths,
        intake=intake,
    )

    candidates = sorted(by_path.values(), key=lambda c: -float(c.get('priority') or 0))
    mutable = [c for c in candidates if any(f.get('mutation_allowed') for f in c.get('wire_subject_fields') or [])]

    doc = {
        'schema_version': SCHEMA_VERSION,
        'generated_at': _utc_now(),
        'pack_dir': str(pack_dir),
        'summary': {
            'captures_scanned': len(intake.get('captures') or []),
            'replay_entries_scanned': len(replay_doc.get('entries') or []),
            'candidates_total': len(candidates),
            'candidates_mutation_allowed': len(mutable),
            'credential_bound_sensitive_reads': sum(
                1 for row in sens_read.values()
                if row.get('live_sensitive_read_m0_success')
                and normalize_api_path(row.get('path') or '') not in by_path
            ),
        },
        'candidates': candidates,
    }
    if write:
        write_json(pack_dir / 'subject_wire_candidates.json', doc)
    return doc


def load_subject_wire_candidates(pack_dir: Path) -> Dict[str, Any]:
    pack_dir = Path(pack_dir)
    path = pack_dir / 'subject_wire_candidates.json'
    if path.exists():
        return load_json(path) or {}
    return mine_subject_wire_candidates(pack_dir, write=True)
