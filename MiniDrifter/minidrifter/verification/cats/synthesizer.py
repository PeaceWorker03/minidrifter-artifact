# -*- coding: utf-8
"""Evidence-grounded binding test plan synthesis (rule-first, optional LLM enrich)."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from minidrifter.business_chain.chain_run_context import load_json
from minidrifter.classification.api_plane_classifier import (
    _card_path,
    classify_path_to_plane_entry,
)
from minidrifter.core.utils import write_json
from minidrifter.materials.intake_param_hints import normalize_api_path
from minidrifter.reasoning.pack_loader import load_pack
from minidrifter.verification.cats.verifier import verify_binding_test_plan
from minidrifter.verification.subject_override_fields import infer_subject_fields_from_path

SCHEMA_VERSION = '1.0.0'

IDENTITY_INVARIANTS = ['uid', 'token', 'authorization', 'session', 'openid']

PLANE_POLICIES: Dict[str, Dict[str, Any]] = {
    'user_profile_personal_info': {
        'candidate_policies': [
            'pool_alternate',
            'authorized_seed',
            'numeric_far_jump_down',
            'numeric_far_jump_up',
            'sibling_subject_value',
            'numeric_increment',
        ],
        'oracle_fields': [
            'identityInfo',
            'drivingLicenceInfo',
            'memberName',
            'decodeNo',
        ],
        'invalid_mutant_policy': 'inconclusive_not_clean',
    },
    'order_detail': {
        'candidate_policies': ['pool_alternate', 'sibling_subject_value', 'numeric_increment'],
        'oracle_fields': ['orderId', 'orderNo', 'orderDetail'],
        'invalid_mutant_policy': 'inconclusive_not_clean',
    },
    'default': {
        'candidate_policies': [
            'pool_alternate',
            'sibling_subject_value',
            'numeric_far_jump_down',
            'numeric_increment',
        ],
        'oracle_fields': [],
        'invalid_mutant_policy': 'inconclusive_not_clean',
    },
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _pool_summary(pack_dir: Path) -> Dict[str, Any]:
    subj = load_json(pack_dir / 'subject_pool.json') or {}
    obj = load_json(pack_dir / 'object_pool.json') or {}
    agg = load_json(pack_dir / 'aggregate_materials.json') or {}
    return {
        'subject_fields': list((subj.get('fields') or {}).keys())[:20],
        'object_fields': list((obj.get('fields') or {}).keys())[:20],
        'aggregate_fields': list((agg.get('fields') or {}).keys())[:30],
    }


def _card_api_id(card: Dict[str, Any]) -> str:
    prov = card.get('provenance') or {}
    return str(
        prov.get('operation_id')
        or card.get('card_id')
        or card.get('api_id')
        or ''
    )


def _rule_plan_for_path(
    path: str,
    *,
    template: Dict[str, Any],
    rank: str = 'P3',
) -> Optional[Dict[str, Any]]:
    entry = classify_path_to_plane_entry(path)
    plane = entry.get('primary_plane') or 'default'
    cfg = PLANE_POLICIES.get(plane) or PLANE_POLICIES['default']
    fields = infer_subject_fields_from_path(path)
    if not fields:
        plain = template.get('plain_template') or {}
        for k in (plain.get('body_params') or {}):
            if k.lower().replace('_', '') in ('memberid', 'userid', 'openid', 'customerid'):
                fields.append(k)
    if not fields:
        return None
    mut_field = fields[0]
    norm = normalize_api_path(path)
    return {
        'plan_id': f"cats-{norm.replace('/', '-')[:48]}",
        'target_api': path,
        'test_intent': 'subject_object_binding_violation',
        'security_property': 'identity credential should bind to business handle',
        'target_effect': 'read_sensitive_state',
        'identity_invariant': list(IDENTITY_INVARIANTS),
        'mutation_field': mut_field,
        'path_inferred_subject': True,
        'candidate_policies': list(cfg['candidate_policies']),
        'candidate_sources': ['subject_pool', 'har_pool', 'authorized_seed', 'numeric_far_jump'],
        'oracle': {
            'type': 'sensitive_content_fingerprint',
            'fields': list(cfg['oracle_fields']),
            'empty_response_policy': 'invalid_mutant_no_evidence',
        },
        'invalid_mutant_policy': cfg['invalid_mutant_policy'],
        'rank': rank,
        'plane': plane,
        'synthesis_mode': 'rule_evidence_grounded',
    }


def synthesize_binding_test_plans(
    pack_dir: Path,
    *,
    api_paths: Optional[List[str]] = None,
    with_llm: bool = False,
    limit: int = 80,
) -> Dict[str, Any]:
    pack_dir = Path(pack_dir)
    pack = load_pack(str(pack_dir))
    cards_by_path = {
        normalize_api_path(_card_path(c)): c
        for c in pack['cards']
        if _card_path(c)
    }
    templates_doc = load_json(pack_dir / 'materialized_api_templates.json') or {}
    templates_by_id = {
        t.get('api_id'): t for t in (templates_doc.get('templates') or []) if t.get('api_id')
    }

    targets: List[str] = []
    if api_paths:
        targets = [normalize_api_path(p) for p in api_paths]
    else:
        from minidrifter.verification.reporting.sensitive_binding_coverage import (
            _collect_target_paths,
        )
        targets = sorted(_collect_target_paths(pack_dir))[:limit]

    known_paths = set(cards_by_path.keys())
    plans: List[Dict[str, Any]] = []
    rejected: List[Dict[str, Any]] = []

    for norm in targets:
        card = cards_by_path.get(norm)
        if not card:
            continue
        path = _card_path(card) or norm
        tpl = templates_by_id.get(_card_api_id(card))
        if not tpl:
            tpl = {'plain_template': {}}
        plan = _rule_plan_for_path(path, template=tpl, rank='P2')
        if not plan:
            continue
        ok, errs = verify_binding_test_plan(
            plan,
            known_paths=known_paths,
            template=tpl,
            identity_invariants=IDENTITY_INVARIANTS,
        )
        if ok:
            plans.append(plan)
        else:
            rejected.append({'target_api': path, 'errors': errs})

    if with_llm and plans:
        plans = _maybe_enrich_with_llm(plans, pack_dir=pack_dir)

    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': _utc_now(),
        'pack_dir': str(pack_dir),
        'synthesis_engine': 'CATS',
        'synthesis_mode': 'rule_evidence_grounded' + ('+llm' if with_llm else ''),
        'pool_summary': _pool_summary(pack_dir),
        'plan_count': len(plans),
        'rejected_count': len(rejected),
        'plans': plans,
        'rejected': rejected[:20],
        'by_path': {normalize_api_path(p['target_api']): p for p in plans},
    }


def _maybe_enrich_with_llm(
    plans: List[Dict[str, Any]],
    *,
    pack_dir: Path,
) -> List[Dict[str, Any]]:
    try:
        from minidrifter.reasoning.llm_client import LLMClient, LLMClientError
        from minidrifter.reasoning.validator import parse_json_from_llm

        client = LLMClient()
        slim = [{'target_api': p['target_api'], 'mutation_field': p['mutation_field'],
                 'plane': p.get('plane'), 'candidate_policies': p['candidate_policies']}
                for p in plans[:15]]
        system = (
            'You refine binding test plans for mini-program API security. '
            'Output JSON array only. Do not invent APIs or fields. '
            'Only reorder candidate_policies or add oracle field paths from input.'
        )
        user = json.dumps({'plans': slim, 'pool': _pool_summary(pack_dir)}, ensure_ascii=False)
        raw = client.chat_json(system, user)
        doc = parse_json_from_llm(raw)
        hints = {normalize_api_path(x.get('target_api', '')): x for x in (doc.get('plans') or doc) if isinstance(x, dict)}
        out = []
        for p in plans:
            h = hints.get(normalize_api_path(p['target_api']))
            if h and isinstance(h.get('candidate_policies'), list):
                merged = dict(p)
                merged['candidate_policies'] = h['candidate_policies']
                merged['synthesis_mode'] = 'rule+llm_refine'
                out.append(merged)
            else:
                out.append(p)
        return out
    except Exception:
        return plans


def write_binding_test_plans(pack_dir: Path, **kwargs: Any) -> Path:
    doc = synthesize_binding_test_plans(pack_dir, **kwargs)
    out = Path(pack_dir) / 'binding_test_plans.json'
    write_json(out, doc)
    return out


def lookup_plan_for_path(pack_dir: Path, api_path: str) -> Optional[Dict[str, Any]]:
    path = Path(pack_dir) / 'binding_test_plans.json'
    if not path.exists():
        return None
    doc = json.loads(path.read_text(encoding='utf-8'))
    return (doc.get('by_path') or {}).get(normalize_api_path(api_path))
