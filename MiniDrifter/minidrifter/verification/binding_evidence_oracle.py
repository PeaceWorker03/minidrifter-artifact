# -*- coding: utf-8
"""Evidence-grade binding oracle — attach provable evidence to M7 findings."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from minidrifter.materials.object_pool_writer import load_baseline_field_pool


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _object_provenance(
    field: str,
    pack_dir: Optional[Any] = None,
    chain_doc: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    prov: Dict[str, Any] = {'field': field}
    if chain_doc:
        of = chain_doc.get('object_flow') or {}
        if of.get('object_source'):
            prov['source'] = of.get('object_source')
            prov['object_value'] = of.get('object_value')
            prov['producer_api'] = of.get('producer_api')
            prov['response_path'] = of.get('producer_path')
            prov['provenance_type'] = 'runtime_object_flow'
            return prov
    if pack_dir is not None:
        pool = load_baseline_field_pool(pack_dir)
        if field in pool.get('fields'):
            prov['object_value'] = pool['fields'].get(field)
            prov['source'] = pool.get('sources', {}).get(field)
            prov['provenance_type'] = 'object_pool'
    return prov


def _evidence_grade(verdict_doc: Dict[str, Any], analysis: Dict[str, Any]) -> str:
    checks = verdict_doc.get('checks_passed') or 0
    total = verdict_doc.get('checks_total') or 5
    verdict = verdict_doc.get('verdict') or 'signal'
    binding = (analysis.get('binding_observation') or {}).get('binding_status')
    if verdict == 'confirmed' and checks >= 4:
        return 'A_confirmed'
    if verdict in {'confirmed', 'likely'} and checks >= 3:
        return 'B_likely'
    if binding == 'subject_object_binding_mismatch' and analysis.get('call_outcome') == 'business_success':
        return 'B_likely'
    if verdict == 'hypothesis' or checks >= 2:
        return 'C_hypothesis'
    return 'D_signal'


def enrich_binding_evidence(
    finding: Dict[str, Any],
    analysis: Dict[str, Any],
    test_case: Dict[str, Any],
    *,
    pack_dir: Optional[Any] = None,
    chain_doc: Optional[Dict[str, Any]] = None,
    baseline_context: Optional[Dict[str, Any]] = None,
    binding_verdict: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Attach reproducible evidence bundle to a binding finding."""
    verdict_doc = binding_verdict or finding.get('binding_verdict') or {}
    binding = analysis.get('binding_observation') or {}
    target_field = test_case.get('target_field') or (chain_doc or {}).get('binding_fields', [''])[0]
    mutated = binding.get('mutated_fields') or []
    baseline = (baseline_context or {}).get('resolved_fields') or {}

    mutation_evidence: List[Dict[str, Any]] = []
    for field in mutated:
        base_ent = baseline.get(field) or {}
        base_val = base_ent.get('value') if isinstance(base_ent, dict) else base_ent
        mut_val = (test_case.get('params') or {}).get(field) or (test_case.get('body_params') or {}).get(field)
        mutation_evidence.append({
            'field': field,
            'baseline_value_redacted': '***' if base_val else None,
            'mutated_value_redacted': '***' if mut_val else None,
            'changed': base_val is not None and str(mut_val) != str(base_val),
        })

    object_prov = _object_provenance(str(target_field), pack_dir=pack_dir, chain_doc=chain_doc)
    grade = _evidence_grade(verdict_doc, analysis)

    evidence_bundle = {
        'evidence_grade': grade,
        'oracle': 'binding_evidence_oracle',
        'generated_at': _utc_now(),
        'api_path': analysis.get('path'),
        'api_id': analysis.get('api_id'),
        'chain_id': finding.get('chain_id') or (chain_doc or {}).get('chain_id'),
        'chain_source': (chain_doc or {}).get('chain_source'),
        'campaign_phase': (chain_doc or {}).get('campaign_phase'),
        'mutation_type': test_case.get('mutation_type'),
        'target_field': target_field,
        'mutated_fields': mutated or ([target_field] if target_field else []),
        'object_anchor_fields': (chain_doc or {}).get('primary_mutation_targets') or (chain_doc or {}).get('binding_fields') or [],
        'call_outcome': analysis.get('call_outcome'),
        'binding_status': binding.get('binding_status'),
        'verdict': verdict_doc.get('verdict'),
        'reason_codes': verdict_doc.get('reason_codes') or [],
        'checks_passed': verdict_doc.get('checks_passed'),
        'checks_total': verdict_doc.get('checks_total'),
        'security_signals': analysis.get('security_signals') or [],
        'produced_fields': analysis.get('produced_fields') or [],
        'mutation_evidence': mutation_evidence,
        'object_provenance': object_prov,
        'm0_m7_pair_required': True,
        'contributes_to_final_verdict': bool(finding.get('is_primary_chain_finding')),
        'replay_hints': {
            'test_id': analysis.get('test_id'),
            'target_field': target_field,
            'requires_baseline_context': True,
        },
    }

    finding = dict(finding)
    finding['evidence_grade'] = grade
    finding['evidence_bundle'] = evidence_bundle
    finding['contributes_to_final_verdict'] = bool(finding.get('is_primary_chain_finding'))
    finding['evidence_summary'] = {
        **(finding.get('evidence_summary') or {}),
        'evidence_grade': grade,
        'object_source': object_prov.get('source'),
        'chain_source': (chain_doc or {}).get('chain_source'),
        'reason_codes': verdict_doc.get('reason_codes') or [],
    }
    return finding
