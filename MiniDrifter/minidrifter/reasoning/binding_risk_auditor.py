# -*- coding: utf-8
"""LLM batch rerank for binding-risk candidates (hypothesis only — no vulnerability claims)."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from minidrifter.reasoning.llm_client import LLMClient, LLMClientError
from minidrifter.reasoning.pack_loader import load_evidence_pack, slim_card_for_llm
from minidrifter.reasoning.validator import parse_json_from_llm

BINDING_RISK_SYSTEM = """You are MiniDrifter Binding-Risk Analyst.
Rank APIs by likelihood of WEAK identity/credential BINDING enforcement (not yet proven).

RULES:
- Do NOT claim vulnerabilities or use words: vulnerable, exploit, confirmed.
- Output hypotheses only: weak binding, client-trust, cosmetic signature, IDOR surface.
- Prefer APIs where subject id + session/token are client-supplied query params.
- Prefer read APIs returning user/order/profile data.
- Downrank third-party map/weather SDK paths.
- Each item must include api_id matching input.

OUTPUT strict JSON:
{
  "rankings": [
    {
      "api_id": "string",
      "llm_risk_boost": 0.0,
      "confidence": 0.0,
      "rationale": "one sentence",
      "hypothesis_tags": ["client_sign_cosmetic", "identity_in_query", "object_id_param"]
    }
  ]
}
llm_risk_boost range 0-20 (additive to rule score)."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def rerank_binding_risk_batch(
    pack_dir,
    candidates: List[Dict[str, Any]],
    cards_by_id: Dict[str, Any],
    *,
    dry_run: bool = False,
) -> Dict[str, Any]:
    if not candidates:
        return {'used_llm': False, 'status': 'empty', 'results': []}

    if dry_run:
        return {
            'used_llm': False,
            'status': 'dry_run',
            'results': [
                {**c, 'llm_risk_boost': 0.0, 'rationale': 'dry_run'}
                for c in candidates
            ],
        }

    payload = []
    for c in candidates[:15]:
        aid = c.get('api_id')
        card = cards_by_id.get(aid) or {}
        ev = load_evidence_pack(pack_dir, aid)
        payload.append({
            'api_id': aid,
            'path': c.get('path'),
            'rule_score': c.get('rule_score'),
            'rule_signals': c.get('risk_signals'),
            'materialized': c.get('materialized'),
            'card': slim_card_for_llm(card),
            'evidence_snippets': (ev or {}).get('snippets') or (ev or {}).get('evidence') or [],
        })

    user = json.dumps({'candidates': payload}, ensure_ascii=False, indent=2)
    try:
        client = LLMClient()
        raw = client.chat_json(BINDING_RISK_SYSTEM, user)
        parsed = parse_json_from_llm(raw)
        rankings = parsed.get('rankings') or []
        by_id = {r.get('api_id'): r for r in rankings if r.get('api_id')}
        results = []
        for c in candidates:
            aid = c.get('api_id')
            hit = by_id.get(aid) or {}
            boost = float(hit.get('llm_risk_boost') or 0)
            boost = max(0.0, min(20.0, boost))
            results.append({
                'api_id': aid,
                'llm_risk_boost': boost,
                'confidence': hit.get('confidence'),
                'rationale': hit.get('rationale') or '',
                'hypothesis_tags': hit.get('hypothesis_tags') or [],
            })
        return {
            'used_llm': True,
            'status': 'ok',
            'generated_at': _utc_now(),
            'results': results,
        }
    except LLMClientError as exc:
        return {
            'used_llm': False,
            'status': 'llm_unavailable',
            'error': str(exc),
            'results': [{**c, 'llm_risk_boost': 0.0} for c in candidates],
        }
