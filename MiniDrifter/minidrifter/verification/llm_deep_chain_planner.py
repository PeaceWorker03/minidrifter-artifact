# -*- coding: utf-8
"""LLM Deep Chain Planner — discover longer param-valid business chains (logic + dataflow)."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from minidrifter.reasoning.llm_client import LLMClient, LLMClientError
from minidrifter.reasoning.validator import parse_json_from_llm
from minidrifter.verification.chain_path_extractor import (
    build_api_transitions,
    enumerate_paths_from_seed,
    match_pattern_paths,
    paths_to_deep_chain_proposals,
)
from minidrifter.verification.llm_trace import make_trace

SYSTEM_PROMPT = """You are MiniDrifter Deep Chain Planner.

Goal: propose DEEPER multi-hop API chains for identity/binding verification in WeChat mini-programs.

Each chain must satisfy BOTH:
1. **Business logic** — realistic user journey (login → list → detail → action)
2. **Param/dataflow** — each hop consumes fields produced by earlier hops (Token, UserId, OrderId, etc.)

Input: workflow graph edges, materialized templates, object pool, failed shallow chains.

Output JSON only:
{
  "reasoning_steps": [
    {"step": "observe", "content": "..."},
    {"step": "hypothesize", "content": "..."},
    {"step": "plan", "content": "..."},
    {"step": "constraint_check", "content": "param flow + side_effect check"},
    {"step": "emit", "content": "..."}
  ],
  "proposed_chains": [
    {
      "chain_id": "deep_chain_1",
      "domain": "order|device|invoice|...",
      "goal": "binding_check_on_final_hop",
      "hops": [
        {
          "order": 1,
          "api_id": "...",
          "path": "/Wechat/...",
          "role": "producer|consumer|binding_target",
          "requires_fields": ["Token"],
          "produces_fields": ["UserId"],
          "mutation_stage": "M0|binding_mutation",
          "confidence": 0.0-1.0
        }
      ],
      "revival_if_blocked": ["OrderId"],
      "why_deeper_than_static": "string"
    }
  ],
  "confidence": 0.0-1.0
}

Rules:
- Prefer depth 3-6 when graph supports it
- Do not invent api_id/path not in candidates
- Mark binding_target hop for M7 mutation
- If OrderId needed, show which hop produces it
- Avoid S2+ write APIs unless noted needs_human_confirm
"""


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _rule_deep_chains(ctx: Dict[str, Any]) -> Dict[str, Any]:
    """Rule fallback: field-bridge BFS from atomic seeds."""
    seeds = ctx.get('atomic_passed_seeds') or []
    graph = ctx.get('workflow_graph') or {}
    templates = ctx.get('templates_by_id') or {}
    baseline_fields = set(ctx.get('available_fields') or [])
    all_paths: List[Dict[str, Any]] = []

    for seed in seeds[:5]:
        api_id = seed.get('api_id')
        if not api_id:
            continue
        paths = enumerate_paths_from_seed(
            api_id, graph, templates,
            seed_path=seed.get('path') or '',
            baseline_fields=baseline_fields | set(seed.get('harvested') or []),
            max_depth=5,
            max_paths=12,
        )
        tagged = match_pattern_paths(seed.get('path') or '', paths)
        all_paths.extend(tagged or paths)

    # dedupe by terminal api
    seen: set = set()
    unique: List[Dict[str, Any]] = []
    for p in sorted(all_paths, key=lambda x: (x.get('depth', 0), x.get('semantic_score', 0)), reverse=True):
        key = tuple(p.get('path_api_ids') or [])
        if key in seen:
            continue
        seen.add(key)
        unique.append(p)

    proposals = paths_to_deep_chain_proposals(unique[:8], domain='general')
    return {
        'proposed_chains': proposals,
        'confidence': 0.65 if proposals else 0.4,
        'reasoning_steps': [{'step': 'emit', 'content': f'{len(proposals)} rule BFS paths from {len(seeds)} seeds'}],
    }


def build_deep_chain_context(
    pack_dir: Path,
    *,
    workflow_graph: Dict[str, Any],
    templates_by_id: Dict[str, Any],
    object_pool: Dict[str, Any],
    shallow_chains: List[Dict[str, Any]],
    atomic_passed: List[Dict[str, Any]],
) -> Dict[str, Any]:
    transitions = build_api_transitions(workflow_graph, templates_by_id=templates_by_id)
    edges_out = transitions[:80]

    return {
        'pack_dir': str(pack_dir),
        'available_fields': sorted(set(object_pool.get('confirmed_fields') or [])),
        'atomic_passed_seeds': atomic_passed[:15],
        'shallow_chain_summary': [
            {
                'chain_id': c.get('chain_id'),
                'depth': c.get('depth'),
                'status': c.get('status'),
                'blocked_reason': c.get('blocked_reason'),
            }
            for c in shallow_chains[:15]
        ],
        'producer_consumer_edges': edges_out,
        'workflow_graph': workflow_graph,
        'templates_by_id': templates_by_id,
        'candidate_templates': [
            {'api_id': t.get('api_id'), 'path': t.get('path'), 'domain': t.get('domain')}
            for t in list(templates_by_id.values())[:40]
        ],
    }


def plan_deep_chains(
    pack_dir: Path,
    ctx: Dict[str, Any],
    *,
    with_llm: bool = True,
    llm_dry_run: bool = False,
    llm_traces: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    rule = _rule_deep_chains(ctx)
    if not with_llm or llm_dry_run:
        trace = make_trace(
            'chain_reasoner',
            rule.get('reasoning_steps') or [],
            emit={'proposed_chains': rule.get('proposed_chains')},
            rule_fallback='rule_deep_chain',
        )
        if llm_traces is not None:
            llm_traces.append(trace)
        return {'chains': rule, 'used_llm': False, 'trace': trace}

    try:
        client = LLMClient()
        slim_ctx = {k: v for k, v in ctx.items() if k not in ('workflow_graph', 'templates_by_id')}
        raw = client.chat_json(SYSTEM_PROMPT, json.dumps(slim_ctx, ensure_ascii=False, indent=2))
        parsed = parse_json_from_llm(raw)
        llm_chains = parsed.get('proposed_chains') or []
        rule_chains = rule.get('proposed_chains') or []
        # Merge: LLM picks + rule BFS paths not duplicated
        seen_ids = {c.get('chain_id') for c in llm_chains}
        merged = list(llm_chains) + [c for c in rule_chains if c.get('chain_id') not in seen_ids]
        parsed['proposed_chains'] = merged[:10]
        trace = make_trace(
            'chain_reasoner',
            parsed.get('reasoning_steps') or [],
            emit={'proposed_chains': merged, 'confidence': parsed.get('confidence')},
            confidence=parsed.get('confidence'),
        )
        if llm_traces is not None:
            llm_traces.append(trace)
        out_path = Path(pack_dir) / 'deep_chain_plans.json'
        out_path.write_text(json.dumps({'context_summary': slim_ctx, 'plan': parsed, 'rule_fallback': rule}, ensure_ascii=False, indent=2), encoding='utf-8')
        return {'chains': parsed, 'used_llm': True, 'trace': trace}
    except (LLMClientError, json.JSONDecodeError, ValueError, TypeError):
        return {'chains': rule, 'used_llm': False}
