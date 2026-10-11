# -*- coding: utf-8
"""LLM workflow miner — semantic near-miss and deep chain hypotheses."""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from minidrifter.graph.semantic_workflow_graph import rank_semantic_consumers
from minidrifter.reasoning.llm_client import LLMClient, LLMClientError
from minidrifter.reasoning.validator import parse_json_from_llm

MINER_PROMPT = """You are MiniDrifter Workflow Miner.
Given rule candidates, near-miss (missing 1-2 fields), and semantic_miss candidates,
pick the best NEXT hop OR recommend acquire_object for missing fields.

Consider:
- list → detail → action business continuity
- OrderNo vs orderId alias in same order domain
- Do NOT pick APIs outside provided candidate lists
- If stop, give frontier_hypothesis and fields to acquire

Output JSON:
{
  "next_api_id": "op_... or null",
  "stop": false,
  "frontier_hypothesis": "...",
  "acquire_fields": ["OrderId"],
  "binding_hypothesis": "...",
  "confidence": 0.0-1.0,
  "reasoning": "..."
}
"""


def mine_workflow_hop(
    *,
    chain_nodes: List[Dict[str, Any]],
    rule_candidates: List[Dict[str, Any]],
    near_miss_1: List[Dict[str, Any]],
    near_miss_2: List[Dict[str, Any]],
    semantic_miss: List[Dict[str, Any]],
    available_fields: List[str],
    with_llm: bool = True,
) -> Dict[str, Any]:
    """Rule rank semantic_miss first when no exact match; optional LLM override."""
    from_path = (chain_nodes[-1] or {}).get('path') or ''
    domain = (chain_nodes[-1] or {}).get('domain') or 'general'

    if rule_candidates:
        return {
            'pick': rule_candidates[0],
            'source': 'rule_exact',
            'llm_candidates': rule_candidates,
        }

    pool = near_miss_1 + near_miss_2
    if not semantic_miss and pool:
        semantic_miss = rank_semantic_consumers(
            from_path, pool,
            available_fields=set(available_fields),
            chain_domain=domain,
        )

    if semantic_miss and not with_llm:
        return {'pick': semantic_miss[0], 'source': 'semantic_rule', 'llm_candidates': semantic_miss}

    ctx = {
        'from_path': from_path,
        'domain': domain,
        'available_fields': available_fields,
        'rule_candidates': rule_candidates[:8],
        'near_miss_1': near_miss_1[:6],
        'near_miss_2': near_miss_2[:6],
        'semantic_miss': semantic_miss[:8],
    }

    if not with_llm:
        best = (near_miss_1 or near_miss_2 or semantic_miss or [{}])[0]
        return {'pick': best, 'source': 'near_miss_rule', 'llm_candidates': pool + semantic_miss}

    try:
        client = LLMClient()
        raw = client.chat_json(MINER_PROMPT, json.dumps(ctx, ensure_ascii=False, indent=2))
        parsed = parse_json_from_llm(raw)
        if parsed.get('stop'):
            return {
                'stop': True,
                'frontier_hypothesis': parsed.get('frontier_hypothesis'),
                'acquire_fields': parsed.get('acquire_fields') or [],
                'source': 'llm_miner',
            }
        pick_id = parsed.get('next_api_id')
        all_c = rule_candidates + near_miss_1 + near_miss_2 + semantic_miss
        pick = next((c for c in all_c if c.get('api_id') == pick_id), None)
        if pick:
            return {'pick': pick, 'source': 'llm_miner', 'reasoning': parsed.get('reasoning')}
        if semantic_miss:
            return {'pick': semantic_miss[0], 'source': 'llm_fallback_semantic', 'llm_candidates': semantic_miss}
    except (LLMClientError, json.JSONDecodeError, ValueError, TypeError):
        pass

    best = (semantic_miss or near_miss_1 or near_miss_2 or [{}])[0]
    return {'pick': best, 'source': 'miner_fallback', 'llm_candidates': semantic_miss + pool}
