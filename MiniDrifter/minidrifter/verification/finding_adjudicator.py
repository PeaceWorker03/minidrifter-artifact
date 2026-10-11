# -*- coding: utf-8 -*-

"""Rule-based finding adjudicator — oracle confirms, LLM does not."""

from __future__ import annotations



from datetime import datetime, timezone

from typing import Any, Dict, List, Optional, Set



from minidrifter.core.utils import stable_id

from minidrifter.verification.binding_drift_verdict import (

    assess_binding_drift,

    verdict_to_finding_status,

)

from minidrifter.verification.binding_evidence_oracle import enrich_binding_evidence

from minidrifter.verification.finding_classifier import apply_finding_tier_to_finding





def _utc_now() -> str:

    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')





def _m0_analyses_by_api(analyses: List[Dict[str, Any]], test_cases_by_id: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:

    out: Dict[str, Dict[str, Any]] = {}

    for a in analyses:

        tc = test_cases_by_id.get(a.get('test_id') or '') or {}

        mut = tc.get('mutation_type') or ''

        stage = tc.get('test_stage') or ''

        if mut.startswith('M7') or mut.startswith('M8'):

            continue

        if stage.endswith('_m7'):

            continue

        api_id = a.get('api_id') or ''

        if api_id:

            out[api_id] = a

    return out





def _finalize_finding(

    finding: Dict[str, Any],

    analysis: Dict[str, Any],

    test_case: Dict[str, Any],

    *,

    chain_doc: Optional[Dict[str, Any]] = None,

    pack_dir: Optional[Any] = None,

    baseline_context: Optional[Dict[str, Any]] = None,

    binding_verdict: Optional[Dict[str, Any]] = None,

) -> Dict[str, Any]:

    """Apply tier classification and evidence oracle to every contributing finding."""

    apply_finding_tier_to_finding(

        finding, test_case=test_case, analysis=analysis, chain_doc=chain_doc,

    )

    return enrich_binding_evidence(

        finding, analysis, test_case,

        pack_dir=pack_dir, chain_doc=chain_doc,

        baseline_context=baseline_context,

        binding_verdict=binding_verdict or finding.get('binding_verdict'),

    )





def adjudicate_findings(

    analyses: List[Dict[str, Any]],

    test_cases_by_id: Dict[str, Dict[str, Any]],

    *,

    chain_id: Optional[str] = None,

    seed_api_id: Optional[str] = None,

    baseline_context: Optional[Dict[str, Any]] = None,

    pack_dir: Optional[Any] = None,

    chain_doc: Optional[Dict[str, Any]] = None,

) -> List[Dict[str, Any]]:

    findings: List[Dict[str, Any]] = []

    seen_types: Set[tuple] = set()

    m0_by_api = _m0_analyses_by_api(analyses, test_cases_by_id)



    for a in analyses:

        signals = a.get('security_signals') or []

        suspicious = (a.get('signals') or {}).get('suspicious') or []

        tc = test_cases_by_id.get(a.get('test_id') or '') or {}

        api_id = a.get('api_id') or ''

        mut = tc.get('mutation_type') or ''

        if not mut.startswith('M7') and mut not in {'', 'M0'}:

            continue

        if mut and not mut.startswith('M7'):

            continue



        m0_analysis = m0_by_api.get(api_id)

        verdict_doc = assess_binding_drift(

            a, tc,

            baseline_context=baseline_context,

            m0_analysis=m0_analysis,

            pair={

                'm0_outcome': (m0_analysis or {}).get('call_outcome'),

                'm7_outcome': a.get('call_outcome'),

            } if m0_analysis else None,

        )

        status = verdict_to_finding_status(verdict_doc.get('verdict') or 'signal')



        def _emit(ftype: str, *, severity: str, status: str, key: tuple) -> None:

            if key in seen_types:

                return

            seen_types.add(key)

            raw = _finding(

                ftype, a, tc, chain_id,

                severity=severity, status=status,

                seed_api_id=seed_api_id,

                binding_verdict=verdict_doc,

            )

            findings.append(_finalize_finding(

                raw, a, tc,

                chain_doc=chain_doc, pack_dir=pack_dir,

                baseline_context=baseline_context,

                binding_verdict=verdict_doc,

            ))



        if 'subject_object_binding_mismatch' in signals or (

            (a.get('binding_observation') or {}).get('binding_status')

            in {'subject_object_binding_mismatch', 'server_accepts_mutated_subject'}

        ):

            _emit(

                'subject_object_binding_mismatch',

                severity='high', status=status,

                key=('binding_mismatch', api_id, chain_id or '', tc.get('mutation_type')),

            )

        elif a.get('call_outcome') == 'business_success' and tc.get('mutation_type', '').startswith('M7'):

            if a.get('produced_fields') or verdict_doc.get('verdict') in {'likely', 'hypothesis', 'confirmed'}:

                _emit(

                    'mutation_accepted_by_server',

                    severity='high', status=status,

                    key=('mutation_bypass', api_id, chain_id or '', tc.get('target_field')),

                )

        elif 'binding_anomaly' in suspicious and a.get('call_outcome') == 'business_success':

            _emit(

                'binding_anomaly_hypothesis',

                severity='medium', status='signal' if status == 'signal' else 'hypothesis',

                key=('hypothesis', api_id, tc.get('mutation_type')),

            )

        elif verdict_doc.get('verdict') in {'likely', 'hypothesis', 'signal'} and suspicious:

            _emit(

                'binding_anomaly_hypothesis',

                severity='medium', status=status,

                key=('drift_signal', api_id, tc.get('test_id')),

            )



    return findings





def _finding(

    ftype: str,

    analysis: Dict[str, Any],

    test_case: Dict[str, Any],

    chain_id: Optional[str],

    *,

    severity: str,

    status: str,

    seed_api_id: Optional[str] = None,

    binding_verdict: Optional[Dict[str, Any]] = None,

) -> Dict[str, Any]:

    binding = analysis.get('binding_observation') or {}

    return {

        'finding_id': stable_id('fd', ftype, analysis.get('test_id')),

        'finding_type': ftype,

        'status': status,

        'severity': severity,

        'confidence': 'high' if status == 'confirmed' else 'medium',

        'api_id': analysis.get('api_id'),

        'api_path': analysis.get('path'),

        'chain_id': chain_id,

        'seed_api_id': seed_api_id,

        'test_id': analysis.get('test_id'),

        'mutation_type': test_case.get('mutation_type'),

        'binding_verdict': binding_verdict,

        'evidence_summary': {

            **binding,

            'call_outcome': analysis.get('call_outcome'),

            'produced_fields': analysis.get('produced_fields') or [],

            'security_signals': analysis.get('security_signals') or [],

            'verdict': (binding_verdict or {}).get('verdict'),

            'reason_codes': (binding_verdict or {}).get('reason_codes') or [],

        },

        'evidence_test_ids': [analysis.get('test_id')],

        'source': 'rule_adjudicator',

        'adjudicated_at': _utc_now(),

        'status_history': [{

            'status': status,

            'reason': 'initial_oracle_adjudication',

            'at': _utc_now(),

        }],

    }





def chain_verdict_from_findings(primary_findings: List[Dict[str, Any]]) -> str:

    """Map primary findings + evidence grade to chain-level verdict."""

    active = [
        f for f in primary_findings
        if f.get('status') in {'confirmed', 'hypothesis'}
        and f.get('binding_status') not in {'credential_bound_clean', 'inconclusive'}
    ]

    if not active:

        return 'chain_completed_no_drift'

    strong = [
        f for f in active
        if str(f.get('evidence_grade') or '').startswith(('A_', 'B_'))
        and f.get('binding_status') in {
            'likely_binding_drift', 'explicit_subject_object_mismatch',
            'anchor_mutation_accepted', 'object_data_returned',
        }
    ]

    if strong:

        return 'chain_binding_drift'

    weak = [f for f in active if f.get('binding_status') == 'likely_binding_drift']

    if weak:

        return 'chain_binding_drift_hypothesis'

    return 'chain_binding_drift_hypothesis'

