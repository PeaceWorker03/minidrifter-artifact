# -*- coding: utf-8
"""Export M0/M7 request-response diff packs for binding drift findings."""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from minidrifter.core.utils import write_json
from minidrifter.verification.redactor import redact_dict, redact_headers

SCHEMA_VERSION = '1.0.0'

OWNER_FIELD_CANDIDATES = (
    'memberId', 'MemberId', 'customerId', 'CustomerId', 'userId', 'UserId',
    'openId', 'OpenId', 'unionId', 'UnionId', 'accountId', 'AccountId',
    'loginCustomerId', 'platformUserId', 'orderOwner', 'createdBy',
    'tenantUserId', 'phone', 'mobile', 'memberNo', 'customerNo',
)

CREDENTIAL_PARAM_KEYS = frozenset({
    'token', 'authorization', 'uid', 'sign', 'signature', 'cid', 'nonce',
    'timestamp', 'timespan', 'appidentity', 'cookie', 'session',
})

SENSITIVE_OBJECT_FIELDS = frozenset({
    'orderid', 'orderno', 'invoiceid', 'paymentid', 'memberid', 'cardid',
    'taskid', 'couponid', 'addressid', 'deviceid', 'vehicleid',
})


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _norm(field: str) -> str:
    return re.sub(r'[_\-\s]', '', (field or '')).lower()


def _wire_param_source(test_case: Dict[str, Any]) -> Dict[str, Any]:
    """Mirror request_builder param source selection for diff extraction."""
    body = dict(test_case.get('body_params') or {})
    params = dict(test_case.get('params') or {})
    method = (test_case.get('method') or 'GET').upper()
    style = test_case.get('transport_style') or ''
    use_form_body = (
        bool(body)
        and method in {'POST', 'PUT', 'PATCH'}
        and (
            style in {'form_urlencoded', 'form_cid_q_sign', 'form_encrypted_body'}
            or test_case.get('body_params')
        )
    )
    if use_form_body:
        return body
    return params or body


def _all_request_params(test_case: Dict[str, Any], execution: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    wire_source = _wire_param_source(test_case)
    out.update(wire_source)
    for bag in (
        (test_case.get('query_params') or {}),
        (test_case.get('body_params') or {}),
        (test_case.get('params') or {}),
    ):
        if isinstance(bag, dict):
            out.update(bag)
    preview = (execution or {}).get('request_preview_redacted') or {}
    resolved = preview.get('params_resolved') or {}
    if isinstance(resolved, dict):
        # Wire payload from execution preview overrides template/test-case bags.
        out.update(resolved)
    qplain = preview.get('query_plain')
    if isinstance(qplain, str):
        try:
            parsed = json.loads(qplain)
            if isinstance(parsed, dict):
                out.update(parsed)
        except json.JSONDecodeError:
            pass
    return out


def _credential_snapshot(test_case: Dict[str, Any], execution: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    preview = (execution or {}).get('request_preview_redacted') or {}
    headers = redact_headers(preview.get('headers') or {})
    body_form = preview.get('body_form') or {}
    cred_params = {
        k: ('***' if k.lower() in CREDENTIAL_PARAM_KEYS else v)
        for k, v in body_form.items()
        if k.lower() in CREDENTIAL_PARAM_KEYS
    }
    return {
        'headers_redacted': headers,
        'credential_params_redacted': cred_params,
        'uid': cred_params.get('uid') or headers.get('uid'),
    }


def _flatten(obj: Any, prefix: str = '', out: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    out = out or {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f'{prefix}.{k}' if prefix else str(k)
            if isinstance(v, (dict, list)):
                _flatten(v, key, out)
            else:
                out[key] = v
    elif isinstance(obj, list):
        for i, v in enumerate(obj[:30]):
            _flatten(v, f'{prefix}[{i}]', out)
    return out


def _response_summary(
    analysis: Dict[str, Any],
    execution: Dict[str, Any],
    *,
    anchor_field: str,
) -> Dict[str, Any]:
    produced = analysis.get('produced_values') or execution.get('produces_fields_hint') or {}
    body = execution.get('body_json') or {}
    flat = _flatten(body)
    sensitive = sorted({
        k for k in (analysis.get('produced_fields') or list(produced.keys()))
        if _norm(k) in SENSITIVE_OBJECT_FIELDS or k.lower().endswith('id')
    })
    anchor_norm = _norm(anchor_field)
    returned_anchor = None
    for k, v in produced.items():
        if _norm(k) == anchor_norm:
            returned_anchor = v
            break
    if returned_anchor is None:
        for k, v in flat.items():
            if _norm(k.split('.')[-1]) == anchor_norm:
                returned_anchor = v
                break
    return {
        'business_success': analysis.get('call_outcome') == 'business_success',
        'call_outcome': analysis.get('call_outcome'),
        f'returned_{anchor_field}': returned_anchor,
        'returned_values': {k: produced.get(k) for k in sensitive if k in produced},
        'sensitive_fields': sensitive,
        'response_hash': execution.get('response_hash'),
        'response_size': execution.get('response_size'),
    }


def _extract_owner_evidence(
    m0_summary: Dict[str, Any],
    m7_summary: Dict[str, Any],
    execution_m0: Dict[str, Any],
    execution_m7: Dict[str, Any],
    *,
    credential_owner: Optional[str],
) -> Dict[str, Any]:
    owners: Dict[str, Any] = {}
    for label, ex, summ in (
        ('m0', execution_m0, m0_summary),
        ('m7', execution_m7, m7_summary),
    ):
        flat = _flatten(ex.get('body_json') or {})
        for cand in OWNER_FIELD_CANDIDATES:
            if cand in flat:
                owners[f'{label}_owner_{cand}'] = flat[cand]
            for fk, fv in flat.items():
                if fk.split('.')[-1] == cand:
                    owners[f'{label}_owner_{cand}'] = fv
    explicit = False
    response_owner_field = None
    m0_owner = m7_owner = None
    for cand in OWNER_FIELD_CANDIDATES:
        m0v = owners.get(f'm0_owner_{cand}')
        m7v = owners.get(f'm7_owner_{cand}')
        if m0v is not None or m7v is not None:
            response_owner_field = cand
            m0_owner = m0v
            m7_owner = m7v
            break
    if m0_owner is not None and m7_owner is not None and str(m0_owner) != str(m7_owner):
        explicit = True
    if credential_owner and m7_owner and str(credential_owner) != str(m7_owner):
        explicit = True
    return {
        'response_owner_field': response_owner_field,
        'm0_owner': m0_owner,
        'm7_owner': m7_owner,
        'credential_owner': credential_owner,
        'explicit_mismatch': explicit,
        'owner_fields_seen': {k: v for k, v in owners.items() if v is not None},
    }


def _request_diff(
    m0_tc: Dict[str, Any],
    m7_tc: Dict[str, Any],
    m0_ex: Dict[str, Any],
    m7_ex: Dict[str, Any],
    *,
    anchor_field: str,
) -> Dict[str, Any]:
    m0_params = _all_request_params(m0_tc, m0_ex)
    m7_params = _all_request_params(m7_tc, m7_ex)
    anchor_norm = _norm(anchor_field)
    m0_anchor = m7_anchor = None
    for k, v in m0_params.items():
        if _norm(k) == anchor_norm:
            m0_anchor = v
    for k, v in m7_params.items():
        if _norm(k) == anchor_norm:
            m7_anchor = v
    changed = []
    for k in set(m0_params) | set(m7_params):
        if k.lower() in CREDENTIAL_PARAM_KEYS:
            continue
        if str(m0_params.get(k)) != str(m7_params.get(k)):
            changed.append(k)
    cred0 = _credential_snapshot(m0_tc, m0_ex)
    cred7 = _credential_snapshot(m7_tc, m7_ex)
    credential_same = (
        cred0.get('uid') == cred7.get('uid')
        and cred0.get('credential_params_redacted') == cred7.get('credential_params_redacted')
    )
    return {
        'object_anchor': anchor_field,
        'mutation_field': anchor_field,
        'm0_request': {anchor_field: m0_anchor},
        'm7_request': {anchor_field: m7_anchor},
        'm0_request_params': {k: v for k, v in m0_params.items() if k.lower() not in CREDENTIAL_PARAM_KEYS},
        'm7_request_params': {k: v for k, v in m7_params.items() if k.lower() not in CREDENTIAL_PARAM_KEYS},
        'changed_fields': sorted(changed),
        'credential_anchor_same': credential_same,
        'unchanged_credential_fields': sorted(CREDENTIAL_PARAM_KEYS & {k.lower() for k in m0_params}),
    }


def _response_diff(
    req_diff: Dict[str, Any],
    m0_summary: Dict[str, Any],
    m7_summary: Dict[str, Any],
    *,
    anchor_field: str,
) -> Dict[str, Any]:
    anchor = anchor_field
    m0_val = req_diff.get('m0_request', {}).get(anchor)
    m7_val = req_diff.get('m7_request', {}).get(anchor)
    m0_ret = m0_summary.get(f'returned_{anchor}') or m0_summary.get('returned_values', {}).get(anchor)
    m7_ret = m7_summary.get(f'returned_{anchor}') or m7_summary.get('returned_values', {}).get(anchor)
    mutated_in_request = m0_val is not None and m7_val is not None and str(m0_val) != str(m7_val)
    same_object_returned = m0_ret is not None and m7_ret is not None and str(m0_ret) == str(m7_ret)
    mutated_object_returned = (
        mutated_in_request and m7_ret is not None and str(m7_ret) == str(m7_val)
    )
    anchor_mutation_ignored = (
        mutated_in_request and m7_summary.get('business_success')
        and m0_ret is not None and m7_ret is not None and str(m0_ret) == str(m7_ret)
        and str(m7_ret) == str(m0_val)
    )
    sensitive_after = bool(m7_summary.get('sensitive_fields')) and m7_summary.get('business_success')
    wrapper_only = m7_summary.get('business_success') and not m7_summary.get('sensitive_fields')
    return {
        'same_object_returned': same_object_returned,
        'mutated_object_returned': mutated_object_returned,
        'anchor_mutation_ignored': anchor_mutation_ignored,
        'sensitive_data_returned_after_mutation': sensitive_after,
        'business_success_wrapper_only': wrapper_only,
        'm0_returned_anchor': m0_ret,
        'm7_returned_anchor': m7_ret,
    }


def classify_binding_status_from_diff(diff_doc: Dict[str, Any]) -> str:
    """Layered binding status — diff-driven, conservative on explicit mismatch."""
    owner = diff_doc.get('ownership_evidence') or {}
    rd = diff_doc.get('response_diff') or {}
    m0s = diff_doc.get('m0_response_summary') or {}
    m7s = diff_doc.get('m7_response_summary') or {}
    req = diff_doc.get('request_diff') or {}
    anchor_field = diff_doc.get('object_anchor') or req.get('object_anchor') or 'orderId'

    if owner.get('explicit_mismatch'):
        return 'explicit_subject_object_mismatch'
    if (
        not req.get('changed_fields')
        and diff_doc.get('m7_test_id')
        and not rd.get('anchor_mutation_ignored')
        and not (
            rd.get('same_object_returned')
            and m0s.get('business_success')
            and m7s.get('business_success')
        )
    ):
        return 'invalid_test'
    if rd.get('anchor_mutation_ignored'):
        return 'credential_bound_clean'
    if (
        not req.get('changed_fields')
        and rd.get('same_object_returned')
        and m0s.get('business_success')
        and m7s.get('business_success')
    ):
        return 'credential_bound_clean'
    if (
        req.get('changed_fields')
        and m0s.get('business_success')
        and not m7s.get('business_success')
    ):
        return 'anchor_mutation_accepted'
    if (
        req.get('changed_fields')
        and str(req.get('m0_request', {}).get(anchor_field))
        == str(req.get('m7_request', {}).get(anchor_field))
        and rd.get('same_object_returned')
    ):
        return 'credential_bound_clean'
    if rd.get('business_success_wrapper_only'):
        return 'inconclusive'
    if not (m0s.get('business_success') and m7s.get('business_success')):
        return 'unknown'
    if req.get('credential_anchor_same') and rd.get('sensitive_data_returned_after_mutation'):
        if rd.get('mutated_object_returned'):
            return 'likely_binding_drift'
        if _norm(req.get('mutation_field') or '') and req.get('changed_fields'):
            return 'anchor_mutation_accepted'
        return 'object_data_returned'
    return 'unknown'


def _format_http(execution: Dict[str, Any]) -> str:
    preview = execution.get('request_preview_redacted') or {}
    method = preview.get('method') or 'POST'
    url = preview.get('url') or preview.get('path') or ''
    headers = preview.get('headers') or {}
    body = preview.get('body') or ''
    lines = [f'{method} {url}', '']
    for k, v in headers.items():
        lines.append(f'{k}: {v}')
    lines.append('')
    if body:
        lines.append(str(body))
    return '\n'.join(lines)


def _render_diff_md(diff_doc: Dict[str, Any]) -> str:
    fid = diff_doc.get('finding_id') or ''
    chain = diff_doc.get('chain_id') or ''
    api = diff_doc.get('consumer_api') or ''
    anchor = diff_doc.get('object_anchor') or ''
    status = diff_doc.get('binding_status') or 'unknown'
    req = diff_doc.get('request_diff') or {}
    rd = diff_doc.get('response_diff') or {}
    owner = diff_doc.get('ownership_evidence') or {}
    lines = [
        f'# Binding Evidence Diff — {fid}',
        '',
        f'- **Chain**: `{chain}`',
        f'- **Consumer API**: `{api}`',
        f'- **Object anchor**: `{anchor}`',
        f'- **Binding status (diff-derived)**: `{status}`',
        '',
        '## Request diff',
        '',
        f'- M0 `{anchor}`: `{req.get("m0_request", {}).get(anchor)}`',
        f'- M7 `{anchor}`: `{req.get("m7_request", {}).get(anchor)}`',
        f'- Changed fields: `{req.get("changed_fields")}`',
        f'- Credential anchor same: **{req.get("credential_anchor_same")}**',
        '',
        '## Response diff',
        '',
        f'- M0 returned anchor: `{rd.get("m0_returned_anchor")}`',
        f'- M7 returned anchor: `{rd.get("m7_returned_anchor")}`',
        f'- Same object returned: **{rd.get("same_object_returned")}**',
        f'- Mutated object returned: **{rd.get("mutated_object_returned")}**',
        f'- Anchor mutation ignored (Case A): **{rd.get("anchor_mutation_ignored")}**',
        f'- Sensitive data after M7: **{rd.get("sensitive_data_returned_after_mutation")}**',
        '',
        '## Ownership evidence',
        '',
        f'- Owner field: `{owner.get("response_owner_field")}`',
        f'- Explicit mismatch: **{owner.get("explicit_mismatch")}**',
        '',
        '## Interpretation',
        '',
        diff_doc.get('interpretation') or '_See summary.json_',
        '',
    ]
    return '\n'.join(lines)


def _interpretation_text(diff_doc: Dict[str, Any]) -> str:
    status = diff_doc.get('binding_status') or 'unknown'
    rd = diff_doc.get('response_diff') or {}
    if status == 'credential_bound_clean':
        return (
            'M7 did not change the object anchor on the wire, or the server returned the same object as M0. '
            'This suggests credential-bound fallback or anchor mutation ignored — not confirmed binding drift.'
        )
    if status == 'object_data_returned':
        return (
            'M7 returned business-success with object fields, but request/response diff did not confirm '
            'anchor mutation or object swap. Treat as weak signal pending manual review.'
        )
    if status == 'anchor_mutation_accepted':
        return (
            'Anchor mutation reached the server under the same credential context, but M7 did not '
            'return business-success with object data. The server likely rejected or blocked the '
            'mutated anchor — binding enforcement rather than confirmed drift.'
        )
    if status == 'likely_binding_drift':
        return (
            'Under the same credential context, M7 mutated the object anchor and the server '
            'returned business-success with order-level sensitive fields. '
            'Explicit owner mismatch was not confirmed from response owner fields.'
        )
    if status == 'explicit_subject_object_mismatch':
        return 'Response owner/object evidence indicates explicit subject-object mismatch.'
    if rd.get('business_success_wrapper_only'):
        return 'M7 returned business-success wrapper without sensitive object fields — inconclusive.'
    return 'Insufficient diff evidence for stronger binding status classification.'


def build_binding_diff_document(
    finding: Dict[str, Any],
    *,
    m0_test_case: Dict[str, Any],
    m7_test_case: Dict[str, Any],
    m0_execution: Dict[str, Any],
    m7_execution: Dict[str, Any],
    m0_analysis: Dict[str, Any],
    m7_analysis: Dict[str, Any],
    chain_doc: Optional[Dict[str, Any]] = None,
    baseline_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    anchor = (
        (finding.get('evidence_bundle') or {}).get('target_field')
        or (chain_doc or {}).get('primary_mutation_targets', [None])[0]
        or (chain_doc or {}).get('binding_fields', [None])[0]
        or 'orderId'
    )
    pool = {
        k: (v.get('value') if isinstance(v, dict) else v)
        for k, v in ((baseline_context or {}).get('resolved_fields') or {}).items()
    }
    credential_owner = pool.get('UserId') or pool.get('userId') or pool.get('loginCustomerId') or pool.get('customerId')

    req_diff = _request_diff(m0_test_case, m7_test_case, m0_execution, m7_execution, anchor_field=anchor)
    m0_summary = _response_summary(m0_analysis, m0_execution, anchor_field=anchor)
    m7_summary = _response_summary(m7_analysis, m7_execution, anchor_field=anchor)
    resp_diff = _response_diff(req_diff, m0_summary, m7_summary, anchor_field=anchor)
    owner = _extract_owner_evidence(m0_summary, m7_summary, m0_execution, m7_execution, credential_owner=credential_owner)

    doc = {
        'schema_version': SCHEMA_VERSION,
        'generated_at': _utc_now(),
        'finding_id': finding.get('finding_id'),
        'chain_id': finding.get('chain_id') or (chain_doc or {}).get('chain_id'),
        'consumer_api': finding.get('api_path') or m7_test_case.get('path'),
        'object_anchor': anchor,
        'mutation_field': anchor,
        'm0_test_id': m0_test_case.get('test_id'),
        'm7_test_id': m7_test_case.get('test_id'),
        'request_diff': req_diff,
        'm0_response_summary': m0_summary,
        'm7_response_summary': m7_summary,
        'response_diff': resp_diff,
        'ownership_evidence': owner,
    }
    doc['binding_status'] = classify_binding_status_from_diff(doc)
    doc['interpretation'] = _interpretation_text(doc)
    return doc


def export_binding_evidence_diff(
    pack_dir: Path,
    finding: Dict[str, Any],
    *,
    m0_test_case: Dict[str, Any],
    m7_test_case: Dict[str, Any],
    m0_execution: Dict[str, Any],
    m7_execution: Dict[str, Any],
    m0_analysis: Dict[str, Any],
    m7_analysis: Dict[str, Any],
    chain_doc: Optional[Dict[str, Any]] = None,
    baseline_context: Optional[Dict[str, Any]] = None,
) -> Path:
    pack_dir = Path(pack_dir)
    fid = finding.get('finding_id') or 'finding_unknown'
    out_dir = pack_dir / 'binding_evidence_diff' / fid
    out_dir.mkdir(parents=True, exist_ok=True)

    diff_doc = build_binding_diff_document(
        finding,
        m0_test_case=m0_test_case,
        m7_test_case=m7_test_case,
        m0_execution=m0_execution,
        m7_execution=m7_execution,
        m0_analysis=m0_analysis,
        m7_analysis=m7_analysis,
        chain_doc=chain_doc,
        baseline_context=baseline_context,
    )

    write_json(out_dir / 'summary.json', diff_doc)
    write_json(out_dir / 'diff.json', {
        'request_diff': diff_doc.get('request_diff'),
        'm0_response_summary': diff_doc.get('m0_response_summary'),
        'm7_response_summary': diff_doc.get('m7_response_summary'),
        'response_diff': diff_doc.get('response_diff'),
        'ownership_evidence': diff_doc.get('ownership_evidence'),
        'binding_status': diff_doc.get('binding_status'),
    })
    (out_dir / 'diff.md').write_text(_render_diff_md(diff_doc), encoding='utf-8')
    (out_dir / 'm0_request.http').write_text(_format_http(m0_execution), encoding='utf-8')
    (out_dir / 'm7_request.http').write_text(_format_http(m7_execution), encoding='utf-8')
    write_json(out_dir / 'm0_response.json', redact_dict(m0_execution.get('body_json') or {}))
    write_json(out_dir / 'm7_response.json', redact_dict(m7_execution.get('body_json') or {}))

    _apply_diff_to_finding(finding, diff_doc, out_dir)
    return out_dir


def _apply_diff_to_finding(finding: Dict[str, Any], diff_doc: Dict[str, Any], out_dir: Path) -> None:
    status = diff_doc.get('binding_status') or 'unknown'
    finding['binding_status'] = status
    finding['evidence_diff_path'] = str(out_dir)
    es = finding.setdefault('evidence_summary', {})
    es['binding_status'] = status
    es['diff_binding_status'] = status
    es['anchor_mutation_ignored'] = (diff_doc.get('response_diff') or {}).get('anchor_mutation_ignored')
    eb = finding.setdefault('evidence_bundle', {})
    eb['binding_status'] = status
    eb['binding_diff_path'] = str(out_dir)
    eb['response_diff'] = diff_doc.get('response_diff')
    eb['ownership_evidence'] = diff_doc.get('ownership_evidence')
    eb['interpretation'] = diff_doc.get('interpretation')
    if status == 'credential_bound_clean':
        finding['status'] = 'signal'
        finding['evidence_grade'] = 'D_signal'
        eb['evidence_grade'] = 'D_signal'
    elif status == 'object_data_returned':
        finding['evidence_grade'] = finding.get('evidence_grade') or 'C_hypothesis'
        eb['evidence_grade'] = finding['evidence_grade']
    elif status == 'invalid_test':
        finding['status'] = 'rejected'
        finding['evidence_grade'] = 'invalid_test'
        eb['evidence_grade'] = 'invalid_test'
    elif status == 'anchor_mutation_accepted':
        finding['status'] = 'signal'
        finding['evidence_grade'] = 'D_signal'
        eb['evidence_grade'] = 'D_signal'
    elif status == 'explicit_subject_object_mismatch':
        finding['evidence_grade'] = 'A_confirmed'
        eb['evidence_grade'] = 'A_confirmed'
    elif status == 'likely_binding_drift' and finding.get('evidence_grade', '').startswith('C'):
        finding['evidence_grade'] = 'B_likely'
        eb['evidence_grade'] = 'B_likely'


def export_m0_m7_diffs_from_executions(
    pack_dir: Path,
    *,
    test_cases: List[Dict[str, Any]],
    executions: List[Dict[str, Any]],
    analyses: List[Dict[str, Any]],
    chain_doc: Optional[Dict[str, Any]] = None,
    baseline_context: Optional[Dict[str, Any]] = None,
    findings: Optional[List[Dict[str, Any]]] = None,
) -> List[Path]:
    """Export M0/M7 diff packs for chain_strict runs even when adjudicator emits no finding."""
    from minidrifter.core.utils import stable_id

    tc_by_id = {t['test_id']: t for t in test_cases if t.get('test_id')}
    ex_by_id = {e['test_id']: e for e in executions if e.get('test_id')}
    an_by_id = {a['test_id']: a for a in analyses if a.get('test_id')}

    m0_by_api: Dict[str, str] = {}
    m7_by_api: Dict[str, str] = {}
    for tc in test_cases:
        api_id = tc.get('api_id') or ''
        stage = tc.get('test_stage') or ''
        mut = tc.get('mutation_type') or ''
        if stage.endswith('_m0') or mut in {'', 'M0', 'M0_baseline_replay'}:
            m0_by_api[api_id] = tc.get('test_id') or ''
        if stage.endswith('_m7') or str(mut).startswith('M7'):
            m7_by_api[api_id] = tc.get('test_id') or ''

    finding_by_m7: Dict[str, Dict[str, Any]] = {}
    for f in findings or []:
        m7_id = f.get('test_id') or (f.get('evidence_test_ids') or [None])[0]
        if m7_id:
            finding_by_m7[m7_id] = f

    paths: List[Path] = []
    for api_id, m7_id in m7_by_api.items():
        m0_id = m0_by_api.get(api_id)
        if not m0_id or m7_id not in tc_by_id or m0_id not in ex_by_id or m7_id not in ex_by_id:
            continue
        m7_tc = tc_by_id[m7_id]
        finding = finding_by_m7.get(m7_id) or {
            'finding_id': stable_id('fd', 'chain_consumer_binding_drift', m7_id),
            'finding_type': 'chain_consumer_binding_drift',
            'finding_tier': 'F2_chain_consumer_binding_drift',
            'is_primary_chain_finding': True,
            'chain_id': (chain_doc or {}).get('chain_id'),
            'api_id': api_id,
            'api_path': m7_tc.get('path'),
            'test_id': m7_id,
            'evidence_bundle': {'target_field': m7_tc.get('target_field') or 'orderId'},
        }
        try:
            fp = export_binding_evidence_diff(
                pack_dir, finding,
                m0_test_case=tc_by_id[m0_id],
                m7_test_case=m7_tc,
                m0_execution=ex_by_id[m0_id],
                m7_execution=ex_by_id[m7_id],
                m0_analysis=an_by_id.get(m0_id) or {},
                m7_analysis=an_by_id.get(m7_id) or {},
                chain_doc=chain_doc,
                baseline_context=baseline_context,
            )
            paths.append(fp)
        except Exception:
            continue
    return paths


def export_diffs_for_findings(
    pack_dir: Path,
    findings: List[Dict[str, Any]],
    *,
    test_cases: List[Dict[str, Any]],
    executions: List[Dict[str, Any]],
    analyses: List[Dict[str, Any]],
    chain_doc: Optional[Dict[str, Any]] = None,
    baseline_context: Optional[Dict[str, Any]] = None,
) -> List[Path]:
    tc_by_id = {t['test_id']: t for t in test_cases if t.get('test_id')}
    ex_by_id = {e['test_id']: e for e in executions if e.get('test_id')}
    an_by_id = {a['test_id']: a for a in analyses if a.get('test_id')}

    m0_by_api: Dict[str, str] = {}
    for tc in test_cases:
        if (tc.get('mutation_type') or 'M0') in {'', 'M0'} or tc.get('test_stage', '').endswith('_m0'):
            m0_by_api[tc.get('api_id') or ''] = tc.get('test_id') or ''

    paths: List[Path] = []
    for finding in findings:
        if not finding.get('is_primary_chain_finding') and finding.get('finding_tier') not in {
            'F2_chain_consumer_binding_drift', 'F3_capability_consumer_binding_drift',
        }:
            continue
        m7_id = finding.get('test_id') or (finding.get('evidence_test_ids') or [None])[0]
        if not m7_id or m7_id not in tc_by_id:
            continue
        m7_tc = tc_by_id[m7_id]
        api_id = m7_tc.get('api_id') or finding.get('api_id') or ''
        m0_id = m0_by_api.get(api_id)
        if not m0_id or m0_id not in ex_by_id:
            continue
        try:
            fp = export_binding_evidence_diff(
                pack_dir, finding,
                m0_test_case=tc_by_id[m0_id],
                m7_test_case=m7_tc,
                m0_execution=ex_by_id[m0_id],
                m7_execution=ex_by_id[m7_id],
                m0_analysis=an_by_id.get(m0_id) or {},
                m7_analysis=an_by_id.get(m7_id) or {},
                chain_doc=chain_doc,
                baseline_context=baseline_context,
            )
            paths.append(fp)
        except Exception:
            continue
    return paths
