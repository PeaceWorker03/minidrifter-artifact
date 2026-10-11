# -*- coding: utf-8 -*-
"""LLM Acquisition Chain Advisor — rule-authoritative, LLM-guided (Cursor-like).

Rules decide buckets, obtainability tiers, and side-effect gates.
LLM provides semantic field review, dependency-chain narrative, and collection guidance.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from minidrifter.core.utils import write_json
from minidrifter.reasoning.acquisition_planner import build_acquisition_plan
from minidrifter.reasoning.erd import build_evidence_requirements
from minidrifter.reasoning.llm_client import LLMClient, LLMClientError
from minidrifter.reasoning.pack_loader import (
    load_acquisition_plan,
    load_evidence_pack,
    load_pack,
    load_rule_erd,
    slim_card_for_llm,
    slim_plan_for_llm,
)
from minidrifter.reasoning.validator import (
    merge_acquisition_guidance,
    parse_json_from_llm,
    validate_acquisition_advisor,
)

ADVISOR_SYSTEM = """You are the MiniDrifter Runtime Acquisition Chain Advisor.
You work like a code-analysis assistant: deep contextual reasoning under strict gates.

AUTHORITY MODEL (non-negotiable):
- The rule_plan buckets (stage_1_target_apis, auto_discovery_apis, deferred_apis) are AUTHORITATIVE.
- You MUST NOT override rule bucket assignments. If you disagree, record it in bucket_disagreements only.
- You MUST NOT claim vulnerabilities, exploits, or final security verdicts.
- You MUST NOT instruct the user to manually provide workflow-deep IDs in stage 1:
  OrderId, PayNo, FreezeNo, InvoiceOrderId, ContractId, QRCode, PrepayId, PaySign, etc.

YOUR JOB (semantic + chain guidance):
1. Review field roles using callsite evidence and API semantics (e.g. TokenCode on device list ≠ auth Token).
2. Propose an ordered acquisition/test chain: what to collect first, which API unlocks which fields.
3. Explain material packages in plain language for the tester.
4. Identify cross-API field reuse and deduplication opportunities.
5. Flag ambiguous bindings the static rules may have misclassified — with evidence_refs.

OUTPUT: strict JSON only:
{
  "pack_id": "string",
  "agrees_with_rule_plan": true,
  "chain_guidance": {
    "recommended_sequence": [
      {
        "step": 1,
        "phase": "user_material_collection|auto_discovery|stage_1_test|deferred_preview",
        "card_id": "string or null for user_material_collection",
        "material_id": "string (required when phase=user_material_collection)",
        "path": "string",
        "purpose": "string",
        "requires_fields": ["string"],
        "produces_fields": ["string"],
        "depends_on_steps": [0],
        "rule_bucket": "stage_1_target|auto_discovery|deferred|blocked",
        "evidence_refs": ["ev_0"]
      }
    ],
    "dependency_narrative": "string"
  },
  "field_role_reviews": [
    {
      "card_id": "string",
      "field_name": "string",
      "rule_role": "string",
      "suggested_role": "string",
      "rule_obtainability": "string",
      "suggested_obtainability": "O0_static_derived|O1_login_bootstrap|O2_host_local|O3_first_hop_object|O4_workflow_object|O5_sensitive_capability",
      "reason": "string",
      "evidence_refs": ["ev_0"],
      "confidence": 0.0,
      "apply_suggestion": false
    }
  ],
  "material_package_review": {
    "packages": [
      {
        "material_id": "string",
        "priority": 1,
        "why_needed": "string",
        "unlocks_card_ids": ["string"]
      }
    ],
    "dedup_notes": "string"
  },
  "bucket_disagreements": [
    {
      "card_id": "string",
      "rule_bucket": "string",
      "llm_suggested_bucket": "string",
      "reason": "string"
    }
  ],
  "user_collection_narrative": "string",
  "confidence": 0.0
}

Every chain step and field review with a factual claim must cite evidence_refs from the provided cards.
Keep recommended_sequence focused (≤12 steps). Prioritize low side-effect, first-hop discovery paths.
"""


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def select_cards_for_advisor(
    cards: List[Dict[str, Any]],
    rule_plan: Dict[str, Any],
    erd_items: List[Dict[str, Any]],
    *,
    limit: int = 25,
) -> List[Dict[str, Any]]:
    """Pick the most planning-relevant cards for LLM context (not the full pack)."""
    by_id = {c['card_id']: c for c in cards}
    erd_by_id = {i['card_id']: i for i in erd_items}
    selected_ids: List[str] = []
    seen: Set[str] = set()

    def add_from_bucket(bucket_key: str, n: int) -> None:
        for brief in (rule_plan.get(bucket_key) or [])[:n]:
            cid = brief.get('card_id')
            if cid and cid not in seen and cid in by_id:
                seen.add(cid)
                selected_ids.append(cid)

    add_from_bucket('stage_1_target_apis', 12)
    add_from_bucket('auto_discovery_apis', 8)
    add_from_bucket('deferred_apis', 5)
    for brief in (rule_plan.get('explicitly_deferred_examples') or [])[:3]:
        cid = brief.get('card_id')
        if cid and cid not in seen and cid in by_id:
            seen.add(cid)
            selected_ids.append(cid)

    # Cards with ambiguous field roles (rule vs semantic mismatch candidates)
    ambiguous: List[str] = []
    for cid in by_id:
        sk = (erd_by_id.get(cid) or {}).get('runtime_requirement_skeleton') or {}
        for f in sk.get('required_fields') or []:
            name = (f.get('name') or '').lower()
            role = f.get('role') or ''
            if name in {'tokencode', 'devicename', 'osversion'} and role in {'auth_token', 'subject_id'}:
                ambiguous.append(cid)
                break
    for cid in ambiguous:
        if cid not in seen and len(selected_ids) < limit:
            seen.add(cid)
            selected_ids.append(cid)

    return [by_id[cid] for cid in selected_ids[:limit]]


def build_advisor_payload(
    output_dir: Path,
    rule_plan: Dict[str, Any],
    cards: List[Dict[str, Any]],
    erd_items: List[Dict[str, Any]],
    selected: List[Dict[str, Any]],
) -> Dict[str, Any]:
    erd_by_id = {i['card_id']: i for i in erd_items}
    focus_cards = []
    for card in selected:
        cid = card['card_id']
        erd = erd_by_id.get(cid) or {}
        evidence_pack = load_evidence_pack(output_dir, cid)
        focus_cards.append({
            'api_card': slim_card_for_llm(card),
            'evidence_pack': evidence_pack,
            'rule_runtime_skeleton': erd.get('runtime_requirement_skeleton'),
            'rule_bucket': _bucket_for_card(cid, rule_plan),
        })

    graph = rule_plan.get('runtime_demand_graph') or {}
    edges = graph.get('edges') or []
    selected_ids = {c['card_id'] for c in selected}
    relevant_edges = [
        e for e in edges
        if e.get('from') in selected_ids or e.get('to') in selected_ids
    ][:80]

    return {
        'pack_id': rule_plan.get('pack_id'),
        'rule_plan_summary': slim_plan_for_llm(rule_plan),
        'demand_graph_excerpt': {
            'phase': graph.get('phase'),
            'note': graph.get('note'),
            'edges': relevant_edges,
        },
        'focus_cards': focus_cards,
        'hard_rules_reminder': [
            'Rule buckets are authoritative; disagreements go to bucket_disagreements only.',
            'Stage 1 user materials: login sample, profile, OpenId, first-hop list baselines only.',
            'Never ask user for OrderId/PayNo/FreezeNo in stage 1.',
            'Payment/freeze/subscribe/delete APIs stay deferred.',
        ],
    }


def _bucket_for_card(card_id: str, plan: Dict[str, Any]) -> str:
    for key, label in [
        ('stage_1_target_apis', 'stage_1_target'),
        ('auto_discovery_apis', 'auto_discovery'),
        ('deferred_apis', 'deferred'),
        ('blocked_or_unresolved_apis', 'blocked'),
    ]:
        for b in plan.get(key) or []:
            if b.get('card_id') == card_id:
                return label
    return 'unknown'


def build_advisor_messages(payload: Dict[str, Any]) -> List[Dict[str, str]]:
    return [
        {'role': 'system', 'content': ADVISOR_SYSTEM},
        {'role': 'user', 'content': json.dumps(payload, ensure_ascii=False, indent=2)},
    ]


def run_acquisition_advisor(
    output_dir: str | Path,
    *,
    client: Optional[LLMClient] = None,
    limit: int = 25,
    dry_run: bool = False,
) -> Dict[str, Any]:
    root = Path(output_dir)
    pack = load_pack(root)
    erd_items = load_rule_erd(root)
    if not erd_items:
        erd = build_evidence_requirements(pack['cards'], pack['manifest'])
        erd_items = erd.get('items') or []
        write_json(root / 'evidence_requirements.json', erd)

    rule_plan = load_acquisition_plan(root)
    if not rule_plan:
        rule_plan = build_acquisition_plan(pack['cards'], pack['manifest'], erd_items)
        write_json(root / 'acquisition_plan.json', rule_plan)

    selected = select_cards_for_advisor(pack['cards'], rule_plan, erd_items, limit=limit)
    out_dir = root / 'reasoning'
    out_dir.mkdir(parents=True, exist_ok=True)
    advisor_path = out_dir / 'acquisition_advisor.json'

    record: Dict[str, Any] = {
        'task': 'acquisition_advisor',
        'generated_at': _utc_now(),
        'pack_id': rule_plan.get('pack_id'),
        'selected_card_ids': [c['card_id'] for c in selected],
        'status': 'pending',
        'advisor': None,
        'validation_errors': [],
        'model': None,
    }

    if dry_run:
        record['status'] = 'dry_run'
        record['payload_preview'] = {
            'focus_count': len(selected),
            'paths': [
                (c.get('static') or {}).get('endpoint', {}).get('path')
                for c in selected[:8]
            ],
        }
        write_json(advisor_path, record)
        return {
            'selected': len(selected),
            'output': str(advisor_path),
            'dry_run': True,
            'record': record,
        }

    payload = build_advisor_payload(root, rule_plan, pack['cards'], erd_items, selected)
    cards_by_id = pack['cards_by_id']

    if client is None:
        client = LLMClient()
    record['model'] = client.config.get('model')

    try:
        messages = build_advisor_messages(payload)
        raw = client.chat(messages, json_mode=True)
        advisor = parse_json_from_llm(raw)
        ok, errors = validate_acquisition_advisor(advisor, rule_plan, cards_by_id, selected)
        record['advisor'] = advisor
        record['validation_errors'] = errors
        record['status'] = 'accepted' if ok else 'rejected'
    except (LLMClientError, json.JSONDecodeError, ValueError) as e:
        record['status'] = 'error'
        record['validation_errors'] = [str(e)]

    write_json(advisor_path, record)

    if record['status'] == 'accepted' and record.get('advisor'):
        enriched = merge_acquisition_guidance(rule_plan, record['advisor'], record)
        plan_path = root / 'acquisition_plan.json'
        write_json(plan_path, enriched)
    else:
        plan_path = None

    return {
        'selected': len(selected),
        'status': record['status'],
        'validation_errors': record.get('validation_errors'),
        'output': str(advisor_path),
        'plan': str(plan_path) if plan_path else str(root / 'acquisition_plan.json'),
        'record': record,
    }


def run_acquisition_advisor_batch(output_dir: str | Path, **kwargs: Any) -> Dict[str, Any]:
    return run_acquisition_advisor(output_dir, **kwargs)
