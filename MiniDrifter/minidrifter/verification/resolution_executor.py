# -*- coding: utf-8
"""Execute hop resolution plans — auto retry, acquire inject, user material emit."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from minidrifter.core.utils import write_json
from minidrifter.verification.graph_feedback import apply_hop_graph_feedback
from minidrifter.verification.material_request_intake import enrich_material_request, sync_material_requests_to_intake
from minidrifter.verification.object_acquisition_planner import plan_acquire_all_missing
from minidrifter.verification.transport_family_tracker import path_family


def execute_hop_resolution(
    hop_verdict: Dict[str, Any],
    *,
    atomic: Any,
    beam: Any,
    object_pool: Dict[str, Any],
    workflow_graph: Dict[str, Any],
    templates_by_id: Dict[str, Any],
    pack_dir: Path,
    confidence: Any,
    progress: Any,
    ticket_registry: Optional[Any] = None,
    material_requests: Optional[List[Dict[str, Any]]] = None,
    retry_queue: Optional[List[Dict[str, Any]]] = None,
    test_case: Optional[Dict[str, Any]] = None,
    transport_tracker: Optional[Any] = None,
    finding_escalation_hook: Optional[Any] = None,
) -> Dict[str, Any]:
    """Apply auto_actions from hop adjudication; return applied summary."""
    plan = hop_verdict.get('resolution_plan') or {}
    applied: List[str] = []
    chain_id = hop_verdict.get('chain_id')

    for action in plan.get('auto_actions') or []:
        act = action.get('action')
        if act == 'acquire_object':
            field = action.get('target_field')
            for acq in plan_acquire_all_missing(
                object_pool, workflow_graph, templates_by_id,
                pack_dir=pack_dir, confidence_tracker=confidence, limit_per_field=2,
            ):
                if field and acq.get('target_field') != field:
                    continue
                tpl = acq.get('template')
                if not tpl:
                    continue
                atomic.inject_front({
                    'seed_id': f"hop_acq_{acq.get('target_field')}_{hop_verdict.get('test_id', '')[:8]}",
                    'api_id': acq.get('producer_api_id'),
                    'path': acq.get('path'),
                    'domain': tpl.get('domain', 'general'),
                    'priority': acq.get('score', 0) + 4,
                    'template': tpl,
                }, boost=3)
                progress.acquire(
                    target_field=acq.get('target_field') or '?',
                    producer_path=acq.get('path') or '?',
                    score=acq.get('score') or 0,
                )
                applied.append(f'acquire_object:{acq.get("target_field")}')
                if field:
                    break

        elif act == 'quarantine_chain' and chain_id and beam:
            revive = action.get('revive_fields') or [
                m.get('field') for m in hop_verdict.get('missing_materials') or []
            ]
            beam.quarantine(chain_id, reason=hop_verdict.get('llm_root_cause') or 'hop_blocked', revive=revive[:3])
            applied.append('quarantine_chain')

        elif act == 'downrank_api' and chain_id and beam:
            beam.downrank(chain_id, penalty=2.0)
            applied.append('downrank_api')

        elif act == 'downrank_path_family':
            path = hop_verdict.get('path') or ''
            domain = (test_case or {}).get('domain') or 'general'
            if transport_tracker:
                transport_tracker.record(
                    path=path, domain=domain,
                    outcome='transport_error',
                    failure_class=(hop_verdict.get('attribution') or {}).get('failure_class'),
                )
            if atomic and hasattr(atomic, 'record_transport_outcome'):
                atomic.record_transport_outcome(
                    path=path, domain=domain,
                    outcome='transport_error',
                    failure_class=(hop_verdict.get('attribution') or {}).get('failure_class'),
                )
            applied.append(f'downrank_path_family:{path_family(path)}')

        elif act == 'graph_feedback':
            attr = hop_verdict.get('attribution') or {}
            corr = hop_verdict.get('param_correlation') or {}
            fb = apply_hop_graph_feedback(
                pack_dir,
                api_id=hop_verdict.get('api_id') or '',
                path=hop_verdict.get('path') or '',
                failure_class=attr.get('failure_class'),
                missing_fields=[m.get('field') for m in hop_verdict.get('missing_materials') or []],
                binding_drift=corr.get('response_delta') in {
                    'binding_mismatch_under_mutation', 'binding_drift_confirmed',
                },
                confidence=confidence,
            )
            if fb.get('status') == 'ok':
                applied.append('graph_feedback')

        elif act == 'finding_escalation' and finding_escalation_hook is not None:
            finding_escalation_hook(hop_verdict, test_case=test_case)
            applied.append('finding_escalation')

        elif act == 'switch_domain':
            atomic.reprioritize()
            if beam:
                available = set(object_pool.get('confirmed_fields') or []) | set(object_pool.get('frontier_unlocks') or [])
                beam.try_revive_all(available)
            applied.append('switch_domain')

        elif act == 'schedule_retry_after_acquire' and retry_queue is not None and test_case:
            retry_queue.append({
                **test_case,
                'retry_reason': 'hop_resolution',
                'retry_after_fields': [
                    m.get('field') for m in hop_verdict.get('missing_materials') or []
                ],
            })
            applied.append('schedule_retry')

    mat_req = hop_verdict.get('material_request')
    if mat_req and material_requests is not None:
        mat_req = enrich_material_request(mat_req, pack_dir=pack_dir)
        hop_verdict = {**hop_verdict, 'material_request': mat_req}
        key = '|'.join(mat_req.get('missing_fields') or []) + (hop_verdict.get('path') or '')
        if not any(
            '|'.join(m.get('missing_fields') or []) + (m.get('blocked_hop', {}).get('path') or '') == key
            for m in material_requests
        ):
            material_requests.append(mat_req)
            applied.append('material_request_logged')

    if ticket_registry is not None:
        from minidrifter.verification.ticket_normalizer import sync_ticket_from_hop_block
        attr = hop_verdict.get('attribution') or {}
        fc = attr.get('failure_class')
        if fc in {'business_state_blocked', 'auth_expired', 'validation_error', 'build_failed', 'transport_url_routing'}:
            hop_idx = (test_case or {}).get('hop_index')
            ticket = sync_ticket_from_hop_block(
                pack_dir,
                hop_verdict,
                chain_id=chain_id,
                hop_index=hop_idx,
            )
            if ticket:
                applied.append('user_ticket')

    return {'applied': applied, 'count': len(applied)}


def persist_material_requests(pack_dir: Path, requests: List[Dict[str, Any]]) -> None:
    if not requests:
        return
    sync_material_requests_to_intake(pack_dir, requests)
