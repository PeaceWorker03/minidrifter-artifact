# -*- coding: utf-8 -*-
"""Approach §3 RR-Drift dynamic probe: materialize W_t^A, evaluate drift plans, ConfirmRRDrift."""
from __future__ import annotations

import json
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlparse

from minidrifter.core.utils import write_json
from minidrifter.materials.har_sequence import looks_like_har, looks_like_burp_xml, parse_burp_xml, parse_har_sequence

SCHEMA_VERSION = '1.0.0'
PATH_CONTEXT = '__resource_ctx__'


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _load(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding='utf-8'))


def find_trace_har(project_dir: Path, subject: str = 'A') -> Optional[Path]:
    trace = project_dir / 'CRBD_validation' / 'trace' / f'subject_{subject}'
    if not trace.is_dir():
        return None
    preferred = [
        trace / f'full_session_{subject}.har',
        trace / 'full_session.har',
        trace / f'capture_{subject}.har',
    ]
    for p in preferred:
        if p.exists() and p.stat().st_size > 0:
            return p
    hars = sorted(trace.glob('*.har'), key=lambda x: -x.stat().st_size)
    for p in hars:
        if '.bak' in p.name or p.name.startswith('_'):
            continue
        return p
    return None


def _flatten_json(obj: Any, prefix: str = '', out: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    out = out if out is not None else {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f'{prefix}.{k}' if prefix else str(k)
            if isinstance(v, (dict, list)):
                _flatten_json(v, key, out)
            else:
                out[key] = v
                out[str(k)] = v  # also bare key (last wins)
    elif isinstance(obj, list):
        for i, v in enumerate(obj[:30]):
            _flatten_json(v, f'{prefix}[{i}]' if prefix else f'[{i}]', out)
    return out


def _collect_values_from_request(req: Dict[str, Any]) -> Dict[str, List[str]]:
    bags: Dict[str, List[str]] = defaultdict(list)

    def _add(k: Any, v: Any) -> None:
        if v is None or isinstance(v, (dict, list)):
            return
        ks = str(k)
        vs = str(v)
        if not ks or vs == '':
            return
        bags[ks].append(vs)
        bags[ks.lower()].append(vs)

    for k, v in (req.get('query') or {}).items():
        if isinstance(v, list):
            for x in v:
                _add(k, x)
        else:
            _add(k, v)
    for k, v in (req.get('headers') or {}).items():
        _add(k, v)
    body = req.get('body_json')
    if isinstance(body, dict):
        for k, v in _flatten_json(body).items():
            if '.' not in k:  # prefer bare keys
                _add(k, v)
    for k, v in (req.get('body_form') or {}).items():
        _add(k, v)
    return bags


def _path_match(a: str, b: str) -> bool:
    a = (a or '').rstrip('/').lower()
    b = (b or '').rstrip('/').lower()
    if not a or not b:
        return False
    return a == b or a.endswith(b) or b.endswith(a)


def load_trace_index(har_path: Path) -> Dict[str, Any]:
    text = har_path.read_text(encoding='utf-8', errors='replace')
    if looks_like_har(text):
        har = json.loads(text)
    elif looks_like_burp_xml(text):
        har = parse_burp_xml(text)
    else:
        return {'ok': False, 'error': 'not_har', 'path': str(har_path)}
    seq = parse_har_sequence(har, api_only=True)
    by_path: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    field_values: Dict[str, Set[str]] = defaultdict(set)
    identity_headers: Dict[str, Set[str]] = defaultdict(set)
    for item in seq:
        req = item.get('request') or {}
        path = req.get('path') or urlparse(req.get('url') or '').path or '/'
        by_path[path].append(item)
        bags = _collect_values_from_request(req)
        for k, vals in bags.items():
            for v in vals:
                field_values[k].add(v)
                if re.search(r'^(authorization|token|cookie|session)$', k, re.I):
                    identity_headers[k.lower()].add(v)
        # response-produced fields
        resp = item.get('response_body')
        if isinstance(resp, (dict, list)):
            for k, v in _flatten_json(resp).items():
                if '.' in k:
                    continue
                if v is None or isinstance(v, (dict, list)):
                    continue
                field_values[str(k)].add(str(v))
                field_values[str(k).lower()].add(str(v))
    return {
        'ok': True,
        'path': str(har_path),
        'entry_count': len(seq),
        'unique_paths': len(by_path),
        'sequence': seq,
        'by_path': dict(by_path),
        'field_values': {k: sorted(v)[:40] for k, v in field_values.items()},
        'identity_headers': {k: sorted(v)[:5] for k, v in identity_headers.items()},
    }


def materialize_workflow_from_trace(
    workflow: Dict[str, Any],
    ccr_by_oid: Dict[str, Dict[str, Any]],
    trace: Dict[str, Any],
) -> Dict[str, Any]:
    """Build W_t^A skeleton by aligning workflow operations to τ_A HAR entries."""
    seq = trace.get('sequence') or []
    by_path: Dict[str, List[Dict[str, Any]]] = trace.get('by_path') or {}
    realized = []
    missing = []
    for oid in workflow.get('operations') or []:
        RCR = ccr_by_oid.get(oid) or {}
        path = ((RCR.get('endpoint') or {}).get('path') or '')
        hits = by_path.get(path) or []
        if not hits:
            # soft path match
            for p, items in by_path.items():
                if _path_match(p, path):
                    hits = items
                    break
        if not hits:
            missing.append({'operation_id': oid, 'path': path})
            continue
        # Prefer successful responses
        chosen = None
        for h in hits:
            if int(h.get('response_status') or 0) in range(200, 300):
                chosen = h
                break
        chosen = chosen or hits[0]
        realized.append({
            'operation_id': oid,
            'path': path,
            'method': (RCR.get('method') or {}).get('value') or (chosen.get('request') or {}).get('method'),
            'har_index': chosen.get('har_index'),
            'response_status': chosen.get('response_status'),
            'url': (chosen.get('request') or {}).get('url'),
            'accepted': int(chosen.get('response_status') or 0) in range(200, 300),
        })
    target = workflow.get('target') or {}
    target_hit = any(r.get('operation_id') == target.get('operation_id') for r in realized)
    return {
        'workflow_id': workflow.get('workflow_id'),
        'target': target,
        'realized_steps': realized,
        'missing_operations': missing,
        'coverage': (len(realized) / max(len(workflow.get('operations') or []), 1)),
        'target_reached_in_trace': target_hit,
        'legitimate_success': target_hit and all(r.get('accepted') for r in realized if r.get('operation_id') == target.get('operation_id')),
    }


def _field_alts(trace: Dict[str, Any], field: str) -> List[str]:
    if not field or field == PATH_CONTEXT:
        return []
    fv = trace.get('field_values') or {}
    vals = list(fv.get(field) or fv.get(field.lower()) or [])
    # also camel/snake soft
    snake = re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', field).lower()
    for k, vs in fv.items():
        if k.lower() == field.lower() or k.lower().replace('_', '') == field.lower().replace('_', '') or k.lower() == snake:
            for v in vs:
                if v not in vals:
                    vals.append(v)
    return vals


def evaluate_confirm_crbd(
    *,
    plan: Dict[str, Any],
    workflow: Dict[str, Any],
    wt_a: Dict[str, Any],
    trace_a: Dict[str, Any],
    trace_b: Optional[Dict[str, Any]],
    live: Optional[Dict[str, Any]] = None,
    self_verify: bool = False,
) -> Dict[str, Any]:
    """Offline(+optional live) ConfirmRRDrift predicate evaluation.

    self_verify: same-subject mode (τ_A only). Does not emit paper ConfirmRRDrift.
    """
    target = workflow.get('target') or {}
    cred = target.get('credential') or ''
    # Parse drift source credential from node id oid::field
    src_node = plan.get('drift_source') or ''
    src_field = src_node.split('::', 1)[1] if '::' in src_node else cred

    id_a = (trace_a.get('identity_headers') or {})
    id_b = (trace_b or {}).get('identity_headers') or {}
    # IdInv: A identity present; B must not replace A if both present
    idinv = bool(id_a)
    idinv_detail = 'identity_present_in_tau_A' if idinv else 'identity_missing_in_tau_A'
    if id_a and id_b:
        shared = False
        for k, vs in id_a.items():
            bvs = set(id_b.get(k) or [])
            if set(vs) & bvs:
                shared = True
        if shared:
            idinv_detail = 'A_and_B_share_identity_header_values'
        else:
            idinv_detail = 'A_B_identity_distinct_ok'

    # Realize: target reached in legitimate materialization
    realize = bool(wt_a.get('target_reached_in_trace'))
    # Drift candidate: distinct donor value for source credential
    alts_a = _field_alts(trace_a, src_field)
    alts_b = _field_alts(trace_b, src_field) if trace_b else []
    donor_vals = [v for v in alts_b if v not in alts_a[:1]] if alts_b else []
    same_trace_alts = alts_a[1:] if len(alts_a) > 1 else []
    donor_source = None
    donor_value = None
    if donor_vals:
        donor_source = 'tau_B'
        donor_value = donor_vals[0]
    elif same_trace_alts:
        donor_source = 'tau_A_multi_resource'
        donor_value = same_trace_alts[0]

    drift_possible = donor_value is not None and src_field != PATH_CONTEXT
    accept = bool(wt_a.get('legitimate_success') or (live or {}).get('accept'))
    # SEffect: sensitive path in target + successful response in trace
    seffect_re = (
        r'(order|pay|upload|verify|idcard|bind|detail|member|invoice|userinfo|cert|rentuser)'
        if self_verify
        else r'(order|pay|upload|verify|idcard|bind|detail|member|invoice)'
    )
    seffect = bool(
        realize
        and target.get('path')
        and re.search(seffect_re, target.get('path') or '', re.I)
    )
    # Out-of-scope donor resource proof
    donor_scope_ok = False
    unresolved_reasons = []
    if not trace_b and not self_verify:
        unresolved_reasons.append('missing_tau_B_donor_trace')
    if donor_source == 'tau_A_multi_resource' and not self_verify:
        unresolved_reasons.append('donor_from_same_subject_trace_not_cross_subject')
    if not drift_possible and not self_verify:
        unresolved_reasons.append('no_alternate_binding_value_for_drift_source')
    if not realize:
        unresolved_reasons.append('target_not_realized_in_tau_A')
    if live and live.get('subject_changed'):
        idinv = False
        idinv_detail = 'live_subject_changed'

    live_confirmed = bool((live or {}).get('confirmed'))
    # Formal ConfirmRRDrift (strict): needs cross-subject donor + all predicates
    strict_ok = bool(
        idinv and realize and drift_possible and accept and seffect
        and donor_source == 'tau_B' and not unresolved_reasons
    )
    # Probe-level: can machinery exercise drift?
    probe_ok = bool(idinv and realize and drift_possible and accept)
    self_ok = bool(
        self_verify and idinv and realize and accept
        and (seffect or realize)
    )

    if live_confirmed and idinv and not self_verify:
        verdict = 'Confirmed'
    elif self_verify and self_ok:
        verdict = 'SelfVerified' if (drift_possible or seffect) else 'LikelyCRBD-Candidate'
    elif unresolved_reasons and not live_confirmed:
        verdict = 'Unresolved'
    elif probe_ok and not strict_ok:
        verdict = 'NotConfirmed'  # machinery ready but RR-Drift not formally established
    elif strict_ok:
        verdict = 'Confirmed'
    else:
        verdict = 'NotConfirmed'

    return {
        'verdict': verdict,
        'predicates': {
            'IdInv': idinv,
            'Realize': realize,
            'Drift': drift_possible,
            'Accept': accept,
            'SEffect': seffect,
            'donor_scope_ok': donor_scope_ok,
        },
        'idinv_detail': idinv_detail,
        'drift_source_field': src_field,
        'donor_source': donor_source,
        'donor_value_present': donor_value is not None,
        'unresolved_reasons': unresolved_reasons,
        'strict_confirm_crbd': strict_ok,
        'self_verify': self_verify,
        'probe_executable': probe_ok,
        'live': live or {},
        'coverage': wt_a.get('coverage'),
    }


def _run_light_live(
    *,
    project_dir: Path,
    pack: Path,
    har_a: Path,
    live_mode: str,
) -> Dict[str, Any]:
    """Lightweight live path: HAR intake (no crypto rescan) → materialize → closed-loop verify."""
    from minidrifter.materials.intelligent_intake import run_intelligent_baseline_intake
    from minidrifter.orchestration.account_closed_loop import run_account_closed_loop

    raw = har_a.read_text(encoding='utf-8', errors='replace')
    intake = run_intelligent_baseline_intake(
        pack,
        raw,
        source_dir=project_dir,
        source_label=str(har_a),
        source_path=har_a,
        import_after=True,
        materialize_after=True,
        materialize_limit=80,
        refresh_crypto=False,
    )
    loop = run_account_closed_loop(
        pack_dir=pack,
        project_root=project_dir,
        capture_file=None,  # context already written
        source_dir=project_dir,
        skip_analyze=True,
        mode=live_mode,
        max_http=40 if live_mode == 'execute' else 10,
        max_chains=8,
        materialize=True,
        verify=True,
        verify_mode='campaign',
        force_materialize=False,
    )
    return {
        'status': loop.get('status') or intake.get('status'),
        'loop_state': loop.get('loop_state'),
        'verdict': loop.get('verdict'),
        'stages': loop.get('stages') or [],
        'intake': {
            'status': intake.get('status'),
            'capture_count': intake.get('capture_count'),
            'verdict': intake.get('verdict'),
            'fields': (intake.get('baseline') or {}).get('field_count'),
        },
        'campaign': loop.get('campaign') or loop.get('verify'),
        'binding_coverage_report': loop.get('binding_coverage_report'),
    }


def _har_aligned_workflows(
    ccrs: List[Dict[str, Any]],
    trace_a: Dict[str, Any],
    *,
    max_n: int = 20,
) -> List[Dict[str, Any]]:
    """Build short same-subject workflows from CCRs whose path appears in τ_A."""
    by_path: Dict[str, List[Dict[str, Any]]] = trace_a.get('by_path') or {}
    out: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    for c in ccrs:
        if not isinstance(c, dict):
            continue
        ep = c.get('endpoint') or {}
        path = (ep.get('path') if isinstance(ep, dict) else '') or c.get('path') or ''
        oid = c.get('operation_id')
        if not path or not oid:
            continue
        hit = False
        for p in by_path:
            if _path_match(p, path):
                hit = True
                break
        if not hit:
            continue
        key = path.rstrip('/').lower()
        if key in seen:
            continue
        seen.add(key)
        binds = c.get('binding_credentials') or []
        cred = ''
        if binds:
            x = binds[0]
            cred = str(x.get('name') if isinstance(x, dict) else x or '')
        if not cred:
            cred = 'userId'
        out.append({
            'workflow_id': f'self:{oid}',
            'target': {
                'target_node_id': f'{oid}::{cred}',
                'operation_id': oid,
                'credential': cred,
                'path': path,
            },
            'operations': [oid],
        })
        if len(out) >= max_n:
            break
    return out


def probe_project(
    project_dir: Path,
    *,
    pack_dir: Optional[Path] = None,
    max_workflows: int = 20,
    max_plans: int = 40,
    run_live: bool = False,
    live_mode: str = 'dry-run',
    self_verify: bool = False,
) -> Dict[str, Any]:
    project_dir = Path(project_dir).resolve()
    pack = Path(pack_dir).resolve() if pack_dir else project_dir / 'OUTPUT'
    har_a = find_trace_har(project_dir, 'A')
    har_b = find_trace_har(project_dir, 'B')

    report: Dict[str, Any] = {
        'schema_version': SCHEMA_VERSION,
        'generated_at': _utc_now(),
        'project': project_dir.name,
        'project_dir': str(project_dir),
        'pack_dir': str(pack),
        'tau_A': str(har_a) if har_a else None,
        'tau_B': str(har_b) if har_b else None,
        'approach': (
            '§3 same-subject self-verification (τ_A only; not paper ConfirmRRDrift)'
            if self_verify
            else '§3 Identity-Preserving Stateful Validation (probe)'
        ),
        'self_verify': self_verify,
    }
    if not har_a:
        report['status'] = 'blocked'
        report['error'] = 'missing_tau_A'
        write_json(project_dir / 'CRBD_validation' / 'crbd_probe_report.json', report)
        write_json(pack / 'crbd_probe_report.json', report)
        return report

    # Ensure workflows exist
    if not (pack / 'workflows.json').exists() and (pack / 'rcr_pack.json').exists():
        from minidrifter.rpgraph.export import write_rpgraph_pack
        write_rpgraph_pack(pack)

    ccrs = (_load(pack / 'rcr_pack.json').get('ccrs') or [])
    ccr_by_oid = {c.get('operation_id'): c for c in ccrs if c.get('operation_id')}
    workflows = (_load(pack / 'workflows.json').get('workflows') or [])
    plans = (_load(pack / 'drift_plans.json').get('drift_plans') or [])
    plan_by_wf: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for p in plans:
        plan_by_wf[p.get('workflow_id') or ''].append(p)

    trace_a = load_trace_index(har_a)
    trace_b = load_trace_index(har_b) if har_b else None
    if not trace_a.get('ok'):
        report['status'] = 'blocked'
        report['error'] = trace_a.get('error')
        write_json(project_dir / 'CRBD_validation' / 'crbd_probe_report.json', report)
        return report

    if self_verify:
        har_wfs = _har_aligned_workflows(ccrs, trace_a, max_n=max_workflows)
        ranked = []
        har_paths = set(trace_a.get('by_path') or {})
        for w in workflows:
            tp = ((w.get('target') or {}).get('path') or '')
            if any(_path_match(p, tp) for p in har_paths):
                ranked.append(w)
        workflows = (har_wfs + ranked)[:max_workflows]
    else:
        workflows = workflows[:max_workflows]

    # Sync capture into baseline path for legacy closed-loop consumers
    baseline_dir = project_dir / 'baseline'
    baseline_dir.mkdir(parents=True, exist_ok=True)
    dest = baseline_dir / 'full_session_A.har'
    if not dest.exists() or dest.stat().st_mtime < har_a.stat().st_mtime:
        dest.write_bytes(har_a.read_bytes())

    live_summary: Dict[str, Any] = {}
    if run_live:
        try:
            live_summary = _run_light_live(
                project_dir=project_dir,
                pack=pack,
                har_a=har_a,
                live_mode=live_mode,
            )
        except Exception as exc:
            live_summary = {'status': 'error', 'error': f'{type(exc).__name__}: {exc}'}

    live_confirmed = False
    live_verdict = (live_summary or {}).get('verdict') or ''
    if str(live_verdict).lower() in {'confirmed', 'likely', 'chain_binding_drift'}:
        live_confirmed = True
    # dig into nested campaign results
    for key in ('campaign', 'verify', 'binding_coverage_report'):
        blob = live_summary.get(key) if isinstance(live_summary, dict) else None
        if isinstance(blob, dict):
            v = str(blob.get('verdict') or blob.get('top_verdict') or '').lower()
            if v in {'confirmed', 'likely'}:
                live_confirmed = True

    evaluations = []
    counts = defaultdict(int)
    for wf in workflows:
        wt_a = materialize_workflow_from_trace(wf, ccr_by_oid, trace_a)
        wf_plans = (plan_by_wf.get(wf.get('workflow_id') or '') or [])[: max(1, max_plans // max(len(workflows), 1))]
        if not wf_plans:
            # synthetic no-drift plan for coverage reporting
            wf_plans = [{
                'plan_id': f"synth:{wf.get('workflow_id')}",
                'workflow_id': wf.get('workflow_id'),
                'drift_source': (wf.get('target') or {}).get('target_node_id'),
                'target': (wf.get('target') or {}).get('target_node_id'),
                'dependent_nodes': [(wf.get('target') or {}).get('target_node_id')],
            }]
        for plan in wf_plans[:3]:
            ev = evaluate_confirm_crbd(
                plan=plan,
                workflow=wf,
                wt_a=wt_a,
                trace_a=trace_a,
                trace_b=trace_b if (trace_b and trace_b.get('ok')) else None,
                live={
                    'confirmed': live_confirmed,
                    'accept': bool(wt_a.get('legitimate_success') or live_summary.get('status') == 'ok'),
                    'verdict': live_verdict,
                    'subject_changed': False,
                },
                self_verify=self_verify,
            )
            evaluations.append({
                'workflow_id': wf.get('workflow_id'),
                'plan_id': plan.get('plan_id'),
                'target_path': (wf.get('target') or {}).get('path'),
                'materialization': {
                    'coverage': wt_a.get('coverage'),
                    'target_reached_in_trace': wt_a.get('target_reached_in_trace'),
                    'missing_count': len(wt_a.get('missing_operations') or []),
                },
                'confirm_crbd': ev,
            })
            counts[ev['verdict']] += 1

    confirmed_n = counts.get('Confirmed', 0)
    unresolved_n = counts.get('Unresolved', 0)
    not_n = counts.get('NotConfirmed', 0)
    self_n = counts.get('SelfVerified', 0) + counts.get('LikelyCRBD-Candidate', 0)
    mat_ok = sum(1 for e in evaluations if (e.get('materialization') or {}).get('target_reached_in_trace'))
    probe_exec = sum(1 for e in evaluations if (e.get('confirm_crbd') or {}).get('probe_executable'))

    report.update({
        'status': 'ok',
        'tau_A_entries': trace_a.get('entry_count'),
        'tau_B_entries': (trace_b or {}).get('entry_count') if trace_b else 0,
        'workflows_probed': len(workflows),
        'evaluations': evaluations[:80],
        'evaluation_count': len(evaluations),
        'verdict_counts': dict(counts),
        'summary': {
            'crbd_confirmed_count': confirmed_n,
            'self_verified_count': counts.get('SelfVerified', 0),
            'likely_candidate_count': counts.get('LikelyCRBD-Candidate', 0),
            'unresolved_count': unresolved_n,
            'not_confirmed_count': not_n,
            'materialized_targets_in_trace': mat_ok,
            'probe_executable_plans': probe_exec,
            'can_detect_crbd_now': confirmed_n > 0,
            'can_self_verify_now': self_verify and self_n > 0,
            'blocking_factors': _blocking_factors(
                har_b is not None, confirmed_n, unresolved_n, live_summary, self_verify=self_verify,
            ),
            'live_loop_status': (live_summary or {}).get('status'),
            'live_loop_state': (live_summary or {}).get('loop_state'),
            'live_verdict': live_verdict,
        },
        'live_closed_loop': {
            'ran': run_live,
            'mode': live_mode if run_live else None,
            'status': (live_summary or {}).get('status'),
            'loop_state': (live_summary or {}).get('loop_state'),
            'verdict': live_verdict,
            'stages': [
                {'stage': s.get('stage'), 'status': s.get('status')}
                for s in ((live_summary or {}).get('stages') or [])[:20]
            ],
        },
    })
    out1 = project_dir / 'CRBD_validation' / 'crbd_probe_report.json'
    out2 = pack / 'crbd_probe_report.json'
    write_json(out1, report)
    write_json(out2, report)
    # update manifest status
    man = pack.parent / 'CRBD_validation' / 'manifest.json'
    # actually project_dir/CRBD_validation
    man = project_dir / 'CRBD_validation' / 'manifest.json'
    if man.exists():
        try:
            m = json.loads(man.read_text(encoding='utf-8'))
            m['status'] = 'tau_A_present_probed'
            m['last_probe_at'] = _utc_now()
            m['last_probe_summary'] = report.get('summary')
            write_json(man, m)
        except Exception:
            pass
    return report


def _blocking_factors(
    has_b: bool,
    confirmed: int,
    unresolved: int,
    live: Dict[str, Any],
    *,
    self_verify: bool = False,
) -> List[str]:
    factors = []
    if not has_b and not self_verify:
        factors.append('missing_tau_B')
    if confirmed == 0:
        factors.append('no_strict_ConfirmRRDrift')
    if unresolved:
        factors.append('donor_scope_or_material_unresolved')
    if (live or {}).get('status') in {'blocked', 'error'}:
        factors.append(f"live_loop_{(live or {}).get('status')}")
    if (live or {}).get('loop_state'):
        ls = live.get('loop_state')
        if ls and 'blocked' in str(ls):
            factors.append(f'live_{ls}')
    return factors


def probe_workspace(
    workspace: Path | str,
    *,
    only: Optional[str] = None,
    max_workflows: int = 20,
    run_live: bool = False,
    live_mode: str = 'dry-run',
    self_verify: bool = False,
) -> Dict[str, Any]:
    from minidrifter.runtime.workspace_paths import list_workspace_projects

    workspace = Path(workspace).resolve()
    projects = [p for _, p in list_workspace_projects(workspace)]
    if only:
        projects = [p for p in projects if only.lower() in p.name.lower()]
    rows = []
    for proj in projects:
        print(f'\n===== RR-Drift PROBE: {proj.name} =====', flush=True)
        try:
            r = probe_project(
                proj,
                max_workflows=max_workflows,
                run_live=run_live,
                live_mode=live_mode,
                self_verify=self_verify,
            )
            s = r.get('summary') or {}
            rows.append({
                'project': proj.name,
                'status': r.get('status'),
                'tau_A': bool(r.get('tau_A')),
                'tau_B': bool(r.get('tau_B')),
                'can_detect_crbd_now': s.get('can_detect_crbd_now'),
                'verdict_counts': r.get('verdict_counts'),
                'summary': s,
                'report': str(proj / 'CRBD_validation' / 'crbd_probe_report.json'),
            })
            print(
                f"[{r.get('status')}] confirmed={s.get('crbd_confirmed_count')} "
                f"unresolved={s.get('unresolved_count')} "
                f"can_detect={s.get('can_detect_crbd_now')} "
                f"blockers={s.get('blocking_factors')}",
                flush=True,
            )
        except Exception as exc:
            rows.append({
                'project': proj.name,
                'status': 'error',
                'error': f'{type(exc).__name__}: {exc}',
                'can_detect_crbd_now': False,
            })
            print(f'[ERROR] {proj.name}: {exc}', flush=True)

    doc = {
        'schema_version': SCHEMA_VERSION,
        'generated_at': _utc_now(),
        'workspace': str(workspace),
        'run_live': run_live,
        'live_mode': live_mode if run_live else None,
        'project_count': len(rows),
        'crbd_detectable_count': sum(1 for r in rows if r.get('can_detect_crbd_now')),
        'projects': rows,
        'conclusion': (
            'CURRENT_STACK_CAN_CONFIRM_CRBD'
            if any(r.get('can_detect_crbd_now') for r in rows)
            else 'CURRENT_STACK_CANNOT_CONFIRM_CRBD'
        ),
    }
    write_json(workspace / 'crbd_dynamic_probe_report.json', doc)
    return doc
