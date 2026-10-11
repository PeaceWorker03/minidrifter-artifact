# -*- coding: utf-8 -*-
"""Chain plausibility auditor — rule authority + optional LLM guard (P2)."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from minidrifter.core.utils import write_json
from minidrifter.quality.resolvers.url_role import is_third_party_sdk_url
from minidrifter.quality.semantics.path_tokens import infer_path_semantic
from minidrifter.reasoning.llm_client import LLMClient, LLMClientError
from minidrifter.reasoning.validator import parse_json_from_llm

PLAUSIBILITY_SYSTEM = """You are MiniDrifter Chain Plausibility Guard.
Judge whether a recovered business API chain is plausible for single-account binding verification.

RULES:
- Do NOT claim vulnerabilities or invent new APIs/chains.
- You may only adjust plausibility_score for EXISTING chain_ids from input.
- Downrank: third-party map/weather SDK as entry, cross-unrelated-domain bridges, weak subject-only bridges.
- Up-rank slightly: list→detail within same domain, entry with page evidence, retail order flows.
- plausibility_delta range: -0.25 to +0.08

OUTPUT strict JSON:
{
  "adjustments": [
    {
      "chain_id": "string",
      "plausibility_delta": -0.15,
      "confidence": 0.8,
      "reject_reason": "third_party_entry|cross_domain_bridge|weak_evidence|plausible",
      "rationale": "one sentence",
      "suggested_entry_page": "from input pages or null"
    }
  ]
}
"""


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _rule_plausibility(chain: Dict[str, Any]) -> Dict[str, Any]:
    entry = chain.get('entry_path') or ''
    delta = 0.0
    reason = 'plausible'
    rationale_parts: List[str] = []

    if entry and is_third_party_sdk_url(entry):
        delta -= 0.30
        reason = 'third_party_entry'
        rationale_parts.append('third-party SDK entry')

    hops = chain.get('hops') or []
    paths = [h.get('path') or '' for h in hops]
    if len(paths) >= 2:
        sem0 = infer_path_semantic(paths[0])
        sem1 = infer_path_semantic(paths[-1])
        if sem0.get('domain_hint') != sem1.get('domain_hint'):
            if sem0.get('domain_hint') not in ('general',) and sem1.get('domain_hint') not in ('general',):
                delta -= 0.10
                reason = reason if reason != 'plausible' else 'cross_domain_bridge'
                rationale_parts.append(f"domain {sem0.get('domain_hint')}->{sem1.get('domain_hint')}")

    if chain.get('entry_page'):
        delta += 0.06
        rationale_parts.append('entry page evidence')
    else:
        delta -= 0.04
        if reason == 'plausible':
            reason = 'weak_evidence'

    if chain.get('chain_type') == 'LIST_DETAIL' and 'order' in entry.lower():
        delta += 0.05
        rationale_parts.append('order list-detail')

    return {
        'chain_id': chain.get('chain_id'),
        'plausibility_delta': round(max(-0.30, min(0.10, delta)), 3),
        'reject_reason': reason,
        'rationale': '; '.join(rationale_parts) or 'rule default',
        'source': 'rule',
    }


def _slim_chain_for_llm(chain: Dict[str, Any], pages: List[str]) -> Dict[str, Any]:
    hops = chain.get('hops') or []
    return {
        'chain_id': chain.get('chain_id'),
        'chain_type': chain.get('chain_type'),
        'entry_path': chain.get('entry_path'),
        'entry_page': chain.get('entry_page'),
        'target_path': chain.get('target_path'),
        'binding_fields': (chain.get('binding_fields') or [])[:6],
        'hop_paths': [h.get('path') for h in hops[:4]],
        'score': chain.get('score'),
    }


def audit_chain_plausibility(
    pack_dir: Path,
    chains: List[Dict[str, Any]],
    *,
    limit: int = 12,
    use_llm: bool = True,
) -> Dict[str, Any]:
    pack_dir = Path(pack_dir)
    pages = _load_pages(pack_dir)
    rule_adj = [_rule_plausibility(c) for c in chains[:limit]]
    by_id = {a['chain_id']: a for a in rule_adj if a.get('chain_id')}

    llm_status = 'skipped'
    if use_llm and chains:
        try:
            client = LLMClient()
            payload = {
                'chains': [_slim_chain_for_llm(c, pages) for c in chains[:limit]],
                'available_pages': pages[:40],
            }
            raw = client.chat_json(PLAUSIBILITY_SYSTEM, json.dumps(payload, ensure_ascii=False))
            parsed = parse_json_from_llm(raw)
            for adj in parsed.get('adjustments') or []:
                cid = adj.get('chain_id')
                if not cid or cid not in by_id:
                    continue
                llm_delta = float(adj.get('plausibility_delta') or 0)
                llm_delta = max(-0.25, min(0.08, llm_delta))
                by_id[cid]['plausibility_delta'] = round(
                    by_id[cid]['plausibility_delta'] + llm_delta * 0.5, 3,
                )
                by_id[cid]['reject_reason'] = adj.get('reject_reason') or by_id[cid]['reject_reason']
                by_id[cid]['rationale'] = adj.get('rationale') or by_id[cid]['rationale']
                by_id[cid]['suggested_entry_page'] = adj.get('suggested_entry_page')
                by_id[cid]['source'] = 'rule+llm'
            llm_status = 'ok'
        except LLMClientError:
            llm_status = 'llm_unavailable'

    doc = {
        'schema_version': '1.0.0',
        'generated_at': _utc_now(),
        'llm_status': llm_status,
        'adjustment_count': len(by_id),
        'adjustments': list(by_id.values()),
    }
    write_json(pack_dir / 'chain_plausibility_audit.json', doc)
    return doc


def apply_plausibility_to_rank_plan(
    rank_plan: Dict[str, Any],
    audit_doc: Dict[str, Any],
) -> Dict[str, Any]:
    adj_by_id = {
        a['chain_id']: a for a in (audit_doc.get('adjustments') or []) if a.get('chain_id')
    }
    for item in rank_plan.get('top_chains') or []:
        adj = adj_by_id.get(item.get('chain_id'))
        if not adj:
            continue
        delta = float(adj.get('plausibility_delta') or 0)
        item['score'] = round(max(0.0, min(1.0, float(item.get('score') or 0) + delta)), 3)
        item.setdefault('why', []).append(f"plausibility:{adj.get('reject_reason')}:{delta:+.2f}")
        if adj.get('suggested_entry_page') and not item.get('entry_page'):
            item['suggested_entry_page'] = adj['suggested_entry_page']
    rank_plan.get('top_chains', []).sort(key=lambda x: x.get('score', 0), reverse=True)
    for i, item in enumerate(rank_plan.get('top_chains') or []):
        item['rank'] = i + 1
    rank_plan['plausibility_applied'] = True
    return rank_plan


def polish_intake_action(entry_ctx: Dict[str, Any], chain: Dict[str, Any]) -> str:
    """P2: natural-language capture guidance without changing expected_path."""
    page = entry_ctx.get('entry_page') or entry_ctx.get('page_label') or '对应业务页面'
    action = entry_ctx.get('action_label') or '触发入口请求'
    api_tail = entry_ctx.get('api_tail') or (chain.get('entry_path') or '').rsplit('/', 1)[-1]
    event = entry_ctx.get('entry_event')
    fields = chain.get('objects') or chain.get('binding_fields') or []
    field_hint = '、'.join(f'`{f}`' for f in fields[:4]) if fields else '业务对象字段'
    ev_part = f'（操作：{event}）' if event else ''
    domain = chain.get('domain') or 'general'
    domain_tip = {
        'order': '建议从订单相关页面进入',
        'member': '建议从个人中心/会员页进入',
        'device': '建议从设备列表页进入',
    }.get(domain, '')
    return (
        f'请登录测试账号，打开 `{page}`{ev_part}，{action}。'
        f'入口 API 为 `{api_tail}`，请上传完整 request + response。'
        f'{domain_tip}响应中需包含 {field_hint}。'
    )


def _load_pages(pack_dir: Path) -> List[str]:
    path = pack_dir / 'page_surface.json'
    if not path.exists():
        return []
    doc = json.loads(path.read_text(encoding='utf-8'))
    return [p.get('page_id') for p in (doc.get('pages') or []) if p.get('page_id')]
