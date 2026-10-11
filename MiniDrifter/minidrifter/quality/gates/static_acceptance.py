# -*- coding: utf-8 -*-
"""Static acceptance gates for F_i / RCR / host / URL role."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List

from minidrifter.optimizers.url_utils import is_excluded_business_host, is_frontend_route_path
from minidrifter.quality.models import QualityReport, StaticIssue
from minidrifter.quality.resolvers.url_role import is_third_party_sdk_host

_SENSITIVE_PATH_RE = re.compile(
    r'(order|pay|invoice|device|member|user|balance|coupon|address|booking)',
    re.I,
)


def gate_static_acceptance(pack_dir: Path, report: QualityReport) -> Dict[str, Any]:
    """Run acceptance checks and append issues; return structured acceptance dict."""
    pack_dir = Path(pack_dir)
    gates: List[Dict[str, Any]] = []

    def _add(gate_id: str, ok: bool, severity: str, message: str, evidence: Dict[str, Any] | None = None) -> None:
        gates.append({
            'gate_id': gate_id,
            'ok': ok,
            'severity': severity,
            'message': message,
            'evidence': evidence or {},
        })
        if ok:
            return
        # Map to issue codes used by taxonomy / quality report.
        code = gate_id
        report.add(StaticIssue(
            code=code,
            message=message,
            artifact=str(pack_dir.name),
            severity=severity if severity in {'error', 'warning', 'info'} else 'warning',
            evidence=evidence or {},
        ))

    host_doc: Dict[str, Any] = {}
    hp = pack_dir / 'host_resolution.json'
    if hp.exists():
        host_doc = json.loads(hp.read_text(encoding='utf-8'))
    default_host = host_doc.get('default_business_host') or ''
    noise = bool(default_host and (is_excluded_business_host(default_host) or is_third_party_sdk_host(default_host)))
    _add(
        'HOST_DEFAULT_IS_NOISE',
        not noise,
        'error',
        f'default_business_host={default_host or "(empty)"}',
        {'default_business_host': default_host},
    )

    # Detect api_base overriding a clearly higher observed score (informational/warning).
    pools = (host_doc.get('host_pools') or {}).get('business_explicit') or []
    if pools and host_doc.get('host_resolution_strategy') == 'api_base_config':
        best = pools[0]
        best_score = float(best.get('score') or 0)
        cfg = next(
            (h for h in pools if any((e or {}).get('source') == 'api_base_config' for e in (h.get('evidence') or []))),
            None,
        )
        if cfg and cfg.get('host') != best.get('host') and best_score > float(cfg.get('score') or 0) * 1.15:
            _add(
                'HOST_API_BASE_OVERRIDES_HIGHER_SCORE',
                False,
                'warning',
                f'api_base={cfg.get("host")} overrides higher-score {best.get("host")}',
                {'best': best, 'api_base': cfg},
            )
        else:
            _add('HOST_API_BASE_OVERRIDES_HIGHER_SCORE', True, 'info', 'no harmful api_base override')
    else:
        _add('HOST_API_BASE_OVERRIDES_HIGHER_SCORE', True, 'info', 'n/a')

    try:
        from minidrifter.optimizers.postprocess import repair_business_api_pool
        repair_business_api_pool(pack_dir)
    except Exception:
        pass

    business_ops: List[Dict[str, Any]] = []
    bpath = pack_dir / 'business_api_operations.json'
    if bpath.exists():
        business_ops = json.loads(bpath.read_text(encoding='utf-8'))
    pageish = [
        op for op in business_ops
        if is_frontend_route_path(((op.get('endpoint') or {}).get('path') or ''))
        or ((op.get('url_classification') or {}).get('url_type') == 'frontend_route')
    ]
    _add(
        'URL_PAGE_PATH_IN_BUSINESS_POOL',
        len(pageish) == 0,
        'error',
        f'{len(pageish)} frontend routes in business_api_operations',
        {'examples': [((p.get('endpoint') or {}).get('path')) for p in pageish[:5]]},
    )

    unknown = sum(1 for op in business_ops if (op.get('method') or 'UNKNOWN') == 'UNKNOWN')
    total = max(len(business_ops), 1)
    unknown_rate = unknown / total
    # Soft threshold: warn if > 85% UNKNOWN on non-trivial packs.
    method_ok = (len(business_ops) < 5) or (unknown_rate <= 0.85)
    _add(
        'METHOD_UNKNOWN_HIGH_RATE',
        method_ok,
        'warning',
        f'UNKNOWN method rate={unknown_rate:.2%} ({unknown}/{len(business_ops)})',
        {'unknown': unknown, 'total': len(business_ops), 'rate': unknown_rate},
    )

    rf_ok = (pack_dir / 'request_facts.json').exists()
    _add('REQUEST_FACTS_MISSING', rf_ok, 'error', 'request_facts.json present' if rf_ok else 'missing request_facts.json')

    from minidrifter.rcr.io import load_rcr_pack
    rcr_doc = load_rcr_pack(pack_dir)
    rcr_ok = bool(rcr_doc)
    _add('RCR_MISSING', rcr_ok, 'error', 'rcr_pack.json present' if rcr_ok else 'missing rcr_pack.json')

    if rcr_ok:
        n = max(int(rcr_doc.get('rcr_count') or 0), 1)
        unresolved = int(rcr_doc.get('identity_unresolved_count') or 0)
        rate = unresolved / n
        _add(
            'RCR_IDENTITY_UNRESOLVED_RATE',
            True,  # info only — ⊥ is allowed
            'info',
            f'identity unresolved rate={rate:.2%}',
            {'unresolved': unresolved, 'rcr_count': n, 'rate': rate},
        )
        # Soft warn only when a true resource-reference candidate exists but φ_i
        # was not promoted. Signature/crypto fields are Γ_i materialization, not φ_i.
        from minidrifter.analyzers.credential import classify_credential
        from minidrifter.rpgraph.schema import is_business_bind_field

        sensitive_empty = 0
        for c in (rcr_doc.get('rcrs') or rcr_doc.get('ccrs') or []):
            path = ((c.get('endpoint') or {}).get('path') or '')
            if not _SENSITIVE_PATH_RE.search(path):
                continue
            bind = c.get('binding_credentials') or []
            if bind:
                continue
            notes = c.get('notes') or {}
            if isinstance(notes, dict) and (notes.get('path_inferred_binds') or []):
                continue
            rr = ((c.get('request_semantics') or {}).get('resource_reference_candidates') or [])
            if rr:
                continue
            creds = ((c.get('request_semantics') or {}).get('credentials') or [])
            business_creds = [
                x for x in creds
                if is_business_bind_field(str(x))
                and classify_credential(str(x)) != 'signature_or_crypto_material'
                and not re.search(
                    r'^(token|authorization|access_?token|session|appidentity|sign|signature)$',
                    str(x),
                    re.I,
                )
            ]
            if business_creds:
                sensitive_empty += 1
        _add(
            'RCR_BIND_EMPTY_ON_SENSITIVE',
            sensitive_empty == 0,
            'warning',
            f'{sensitive_empty} sensitive RCRs with empty resource-reference (phi) set',
            {'count': sensitive_empty},
        )
    else:
        _add('RCR_IDENTITY_UNRESOLVED_RATE', False, 'info', 'skipped — no RCR pack')
        _add('RCR_BIND_EMPTY_ON_SENSITIVE', False, 'warning', 'skipped — no RCR pack')

    # Contract recovery quality score (F_i + RCR), threshold 90%.
    incomplete = False
    try:
        from minidrifter.quality.contract_score import write_contract_score
        score_doc = write_contract_score(pack_dir)
        incomplete = bool(score_doc.get('structurally_incomplete')) or len(business_ops) < 3
        ok = bool(score_doc.get('passed_threshold'))
        if incomplete:
            _add(
                'STRUCTURALLY_INCOMPLETE_PACK',
                True,
                'warning',
                f"no recoverable business surface (facts={score_doc.get('n')}, business_ops={len(business_ops)})",
                {'n_facts': score_doc.get('n'), 'business_ops': len(business_ops)},
            )
            _add(
                'CONTRACT_RECOVERY_BELOW_90',
                True,
                'info',
                f"skipped — structurally incomplete (score={score_doc.get('score')}%)",
                {'score': score_doc.get('score'), 'parts': score_doc.get('parts')},
            )
        else:
            _add(
                'CONTRACT_RECOVERY_BELOW_90',
                ok,
                'error',
                f"contract recovery score={score_doc.get('score')}% (threshold={score_doc.get('threshold')}%)",
                {'score': score_doc.get('score'), 'parts': score_doc.get('parts')},
            )
    except Exception as exc:
        _add(
            'CONTRACT_RECOVERY_BELOW_90',
            False,
            'error',
            f'contract score failed: {exc}',
            {},
        )

    # RPGraph workflow reconstruction (§5.2.2–5.2.3) health score.
    # Threshold ~75% matches paper-ready packs; <60% is a hard fail.
    try:
        from minidrifter.rpgraph.export import write_rpgraph_pack
        from minidrifter.rpgraph.io import resolve_rpgraph_path
        from minidrifter.quality.workflow_score import write_workflow_score
        if resolve_rpgraph_path(pack_dir) is None:
            write_rpgraph_pack(pack_dir)
        wf_doc = write_workflow_score(pack_dir)
        thr = float(wf_doc.get('threshold') or 75.0)
        score = float(wf_doc.get('score') or 0.0)
        passed = score >= thr
        if incomplete:
            severity, gate_ok = 'info', True
        elif passed:
            severity, gate_ok = 'info', True
        elif score >= 60.0:
            severity, gate_ok = 'warning', False  # soft_fail only
        else:
            severity, gate_ok = 'error', False  # hard_fail
        _add(
            'WORKFLOW_RECONSTRUCTION_BELOW_THRESHOLD',
            gate_ok,
            severity,
            f"workflow reconstruction score={score}% (threshold={thr}%)",
            {
                'score': score,
                'parts': wf_doc.get('parts'),
                'n_workflows': wf_doc.get('n_workflows'),
                'n_edges': wf_doc.get('n_edges'),
                'passed_threshold': passed,
                'structurally_incomplete': incomplete,
            },
        )
    except Exception as exc:
        _add(
            'WORKFLOW_RECONSTRUCTION_BELOW_THRESHOLD',
            False,
            'error',
            f'workflow score failed: {exc}',
            {},
        )

    # Hard failures: error severity gates that are not ok.
    hard_fail = [g for g in gates if not g['ok'] and g['severity'] == 'error']
    soft_fail = [g for g in gates if not g['ok'] and g['severity'] == 'warning']
    passed = len(hard_fail) == 0
    acceptance = {
        'schema_version': '1.0.0',
        'passed': passed,
        'hard_fail_count': len(hard_fail),
        'soft_fail_count': len(soft_fail),
        'gates': gates,
        'summary': {
            'default_business_host': default_host,
            'business_ops': len(business_ops),
            'pageish_in_business': len(pageish),
            'method_unknown_rate': unknown_rate if business_ops else None,
            'request_facts': rf_ok,
            'rcr_pack': rcr_ok,
        },
    }
    return acceptance
