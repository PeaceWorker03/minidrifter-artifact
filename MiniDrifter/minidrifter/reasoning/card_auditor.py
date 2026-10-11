# -*- coding: utf-8 -*-
"""LLM Card Consistency Auditor (S2)."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from minidrifter.core.utils import write_json
from minidrifter.reasoning.llm_client import LLMClient, LLMClientError
from minidrifter.reasoning.pack_loader import (
    load_evidence_pack,
    load_pack,
    load_panel_row,
    load_rule_erd,
    slim_card_for_llm,
)
from minidrifter.reasoning.validator import parse_json_from_llm, validate_card_audit

CARD_AUDITOR_SYSTEM = """You are the MiniDrifter Card Consistency Auditor.
Audit API Card field quality under strict evidence constraints.

RULES:
- Do NOT claim vulnerabilities. Never output: vulnerable, exploit, severity, final_verdict.
- Do NOT override static.http.method for replay purposes.
- Every consistency_finding must include evidence_refs from the provided evidence pack.
- Compare static bindings ( *_candidate roles ) with snippet semantics.
- If fuzzing_gate.auto_fuzz_eligible is false, explain why that is reasonable.
- Check: method reliability, param role ambiguity, side_effect underestimation, weak oracle, replay blockers.

OUTPUT: strict JSON only with this schema:
{
  "card_id": "string",
  "field_quality": {
    "method": "reliable|medium|unreliable",
    "param_roles": "clear|ambiguous|overconfident",
    "replay": "ready|partial|blocked",
    "oracle": "strong|medium|weak"
  },
  "consistency_findings": [
    {
      "type": "param_role_ambiguity|method_mismatch|side_effect_underestimated|oracle_weak|fuzzing_gate_reasonable|other",
      "severity": "low|medium|high",
      "description": "string",
      "evidence_refs": ["ev_0"]
    }
  ],
  "agrees_with_rule_erd": true,
  "rule_erd_gaps_highlighted": ["req_type names"],
  "confidence": 0.0
}
"""


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _rule_erd_for_card(output_dir: Path, card_id: str) -> Optional[Dict[str, Any]]:
    for item in load_rule_erd(output_dir):
        if item.get('card_id') == card_id:
            return item
    return None


def build_card_auditor_messages(
    card: Dict[str, Any],
    evidence_pack: Optional[Dict[str, Any]],
    rule_erd: Optional[Dict[str, Any]],
    panel_row: Optional[Dict[str, Any]],
) -> List[Dict[str, str]]:
    user_payload = {
        'api_card': slim_card_for_llm(card),
        'evidence_pack': evidence_pack,
        'rule_evidence_requirements': {
            'requirement_summary': (rule_erd or {}).get('requirement_summary'),
            'blocking_requirements': [
                r for r in (rule_erd or {}).get('requirements') or []
                if r.get('severity') == 'blocking' and r.get('status') == 'missing'
            ],
            'suggested_collection_plan': (rule_erd or {}).get('suggested_collection_plan'),
        },
        'verification_profile': panel_row,
    }
    return [
        {'role': 'system', 'content': CARD_AUDITOR_SYSTEM},
        {'role': 'user', 'content': json.dumps(user_payload, ensure_ascii=False, indent=2)},
    ]


def audit_one_card(
    output_dir: str | Path,
    card: Dict[str, Any],
    client: Optional[LLMClient] = None,
) -> Dict[str, Any]:
    root = Path(output_dir)
    card_id = card['card_id']
    evidence_pack = load_evidence_pack(root, card_id)
    rule_erd = _rule_erd_for_card(root, card_id)
    panel_row = load_panel_row(root, card_id)

    record: Dict[str, Any] = {
        'card_id': card_id,
        'task': 'card_auditor',
        'generated_at': _utc_now(),
        'model': None,
        'status': 'pending',
        'audit': None,
        'validation_errors': [],
    }

    if client is None:
        client = LLMClient()
    record['model'] = client.config.get('model')

    try:
        messages = build_card_auditor_messages(card, evidence_pack, rule_erd, panel_row)
        raw = client.chat(messages, json_mode=True)
        payload = parse_json_from_llm(raw)
        ok, errors = validate_card_audit(payload, card)
        record['audit'] = payload
        record['validation_errors'] = errors
        record['status'] = 'accepted' if ok else 'rejected'
    except (LLMClientError, json.JSONDecodeError, ValueError) as e:
        record['status'] = 'error'
        record['validation_errors'] = [str(e)]

    return record


def select_cards_for_audit(
    cards: List[Dict[str, Any]],
    *,
    tier: Optional[str] = None,
    card_id: Optional[str] = None,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    if card_id:
        return [c for c in cards if c.get('card_id') == card_id]

    ops = [c for c in cards if (c.get('provenance') or {}).get('card_kind') == 'operation']
    if tier:
        ops = [c for c in ops if (c.get('ranking') or {}).get('priority_tier') == tier]
    else:
        ops = [c for c in ops if (c.get('ranking') or {}).get('priority_tier') in {'P0', 'P1'}]

    ops.sort(key=lambda c: (c.get('ranking') or {}).get('rank') or 9999)
    return ops[:limit]


def run_card_auditor_batch(
    output_dir: str | Path,
    *,
    tier: Optional[str] = None,
    card_id: Optional[str] = None,
    limit: int = 50,
    dry_run: bool = False,
) -> Dict[str, Any]:
    pack = load_pack(output_dir)
    selected = select_cards_for_audit(pack['cards'], tier=tier, card_id=card_id, limit=limit)
    root = Path(output_dir)
    out_dir = root / 'reasoning'
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / 'card_audits.jsonl'

    records: List[Dict[str, Any]] = []
    if dry_run:
        for card in selected:
            records.append({
                'card_id': card['card_id'],
                'task': 'card_auditor',
                'status': 'dry_run',
                'path': (card.get('static') or {}).get('endpoint', {}).get('path'),
                'tier': (card.get('ranking') or {}).get('priority_tier'),
            })
        _write_jsonl(out_path, records)
        return {'selected': len(selected), 'output': str(out_path), 'records': records, 'dry_run': True}

    client = LLMClient()
    for card in selected:
        print(f"[card_auditor] {card.get('card_id')} …")
        records.append(audit_one_card(root, card, client))

    _write_jsonl(out_path, records)
    accepted = sum(1 for r in records if r.get('status') == 'accepted')
    return {
        'selected': len(selected),
        'accepted': accepted,
        'rejected': sum(1 for r in records if r.get('status') == 'rejected'),
        'errors': sum(1 for r in records if r.get('status') == 'error'),
        'output': str(out_path),
        'records': records,
    }


def _write_jsonl(path: Path, records: List[Dict[str, Any]], *, merge: bool = True) -> None:
    existing: Dict[str, Dict[str, Any]] = {}
    if merge and path.exists():
        for line in path.read_text(encoding='utf-8').splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            cid = row.get('card_id')
            if cid:
                existing[cid] = row
    for r in records:
        cid = r.get('card_id')
        if cid:
            existing[cid] = r
    lines = [json.dumps(v, ensure_ascii=False) for v in existing.values()]
    path.write_text('\n'.join(lines) + ('\n' if lines else ''), encoding='utf-8')
