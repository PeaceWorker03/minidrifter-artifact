# -*- coding: utf-8
"""Maximum-yield one-shot baseline capture strategy — unlock matrix + recommendations."""
from __future__ import annotations

import json
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from minidrifter.business_chain.chain_hop_enrichment import (
    build_semantic_user_action,
    resolve_entry_context,
)
from minidrifter.business_chain.chain_semantic_scorer import (
    chain_binding_risk_summary,
    field_binding_risk_tier,
)
from minidrifter.business_chain.schema import SCHEMA_VERSION
from minidrifter.core.utils import stable_id, write_json
from minidrifter.graph.semantic_workflow_graph import infer_domain_from_path, list_detail_score
from minidrifter.materials.intake_param_hints import normalize_api_path
from minidrifter.verification.binding_risk_planner import IDENTITY_PARAM_RE, OBJECT_PARAM_RE

_DOMAIN_ACTIONS = {
    'member': '请登录测试账号，打开「个人中心/会员中心」页面，并上传该过程抓包。',
    'order': '请登录测试账号，进入「订单列表」并打开任意订单详情，上传抓包。',
    'device': '请登录测试账号，进入「我的设备/设备列表」页面，并上传抓包。',
    'task': '请登录测试账号，进入任务/活动相关页面触发列表或详情请求，上传抓包。',
    'cart': '请登录测试账号，进入「购物车」页面，并上传抓包。',
    'address': '请登录测试账号，进入「地址列表」页面，并上传抓包。',
    'payment': '请登录测试账号，进入支付相关页面（仅浏览，勿完成支付），上传抓包。',
    'dept': '请登录测试账号，进入门店/网点选择或地图选店页面，上传抓包。',
    'general': '请登录测试账号，在小程序中触发该业务页面请求，并上传抓包。',
}

_LIST_PATH_RE = re.compile(r'(list|List|query|Query|search|Search|get\w*List)', re.I)
_FIELD_DOMAIN_HINTS = {
    'orderid': 'order',
    'orderno': 'order',
    'taskid': 'task',
    'deviceid': 'device',
    'deptid': 'dept',
    'storeid': 'dept',
    'cityid': 'address',
    'userid': 'member',
    'memberid': 'member',
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _load_json(path: Path) -> Any:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding='utf-8'))


def _baseline_field_pool(pack_dir: Path) -> Set[str]:
    ctx = _load_json(pack_dir / 'baseline_runtime_context.json') or {}
    intake = _load_json(pack_dir / 'baseline_intake_report.json') or {}
    fields: Set[str] = set()
    for k, ent in (ctx.get('resolved_fields') or {}).items():
        if isinstance(ent, dict) and ent.get('value') not in (None, ''):
            fields.add(k)
    agg = ((intake or {}).get('decrypted_fields_aggregate') or {}).get('fields') or {}
    for k, v in agg.items():
        if v not in (None, ''):
            fields.add(k)
    return fields


def _pool_has(field: str, pool: Set[str]) -> bool:
    if not field:
        return True
    if field in pool:
        return True
    fl = field.lower()
    pool_lower = {p.lower() for p in pool}
    if fl in pool_lower:
        return True
    aliases = {
        'userid': {'uid', 'userid', 'user_id', 'memberid', 'member_id'},
        'openid': {'openid', 'open_id'},
        'token': {'token', 'authorization'},
    }
    for alt in aliases.get(fl, set()):
        if alt in pool_lower:
            return True
    return False


def _normalize_domain(path: str, domain: Optional[str] = None) -> str:
    """Path-aware domain — avoid carrctapi→device false positives from substring 'car'."""
    low = (path or '').lower()
    dom = domain or infer_domain_from_path(path)
    if '/account/' in low or '/member/' in low or '/student/' in low:
        return 'member'
    if any(tok in low for tok in ('/order/', 'cardsku', 'cardorder', 'getorderlist')):
        return 'order'
    if any(tok in low for tok in ('/dept/', 'deptlist', 'listandmap', 'citylist')):
        return 'dept'
    if any(tok in low for tok in ('/task/', '/deposit/task')):
        return 'task'
    if any(tok in low for tok in ('/device/', 'digitalkey', 'hicar')):
        return 'device'
    return dom


def _field_domain(field: str) -> str:
    fl = (field or '').lower()
    for hint, dom in _FIELD_DOMAIN_HINTS.items():
        if hint in fl or fl.endswith(hint.replace('id', '')):
            return dom
    tier = field_binding_risk_tier(field)
    if tier == 'high' and 'id' in fl:
        return 'order'
    return 'general'


def _identity_fields_from_candidate(cand: Dict[str, Any], card: Optional[Dict[str, Any]]) -> List[str]:
    out: List[str] = []
    for sig in cand.get('risk_signals') or []:
        if isinstance(sig, str) and sig.startswith('identity_params:'):
            out.extend(x.strip() for x in sig.split(':', 1)[1].split(',') if x.strip())
    if card:
        params = card.get('params') or ((card.get('replay') or {}).get('params')) or []
        for p in params:
            name = p.get('name') if isinstance(p, dict) else None
            if name and (IDENTITY_PARAM_RE.match(str(name)) or OBJECT_PARAM_RE.match(str(name))):
                out.append(name)
    return list(dict.fromkeys(out))


def _chain_fields(chain: Dict[str, Any]) -> List[str]:
    return list(dict.fromkeys(
        (chain.get('binding_fields') or [])
        + (chain.get('objects') or [])
        + (chain.get('primary_mutation_targets') or [])
    ))


def _rank_score(chain: Dict[str, Any], rank_by_id: Dict[str, Dict[str, Any]]) -> float:
    cid = chain.get('chain_id') or ''
    ranked = rank_by_id.get(cid) or {}
    rank = ranked.get('rank')
    if rank is None:
        return 50.0
    return max(0.0, 100.0 - float(rank) * 3.0)


def _discover_producer_entries(
    field: str,
    domain: str,
    *,
    chains: List[Dict[str, Any]],
    cards_by_path: Dict[str, Dict[str, Any]],
    rank_by_id: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Find static entry paths likely to harvest `field` into object pool."""
    candidates: Dict[str, Dict[str, Any]] = {}
    fl = field.lower()

    for chain in chains:
        entry_path = chain.get('entry_path') or ''
        if not entry_path:
            continue
        hops = chain.get('hops') or []
        produces_field = any(
            fl in {str(x).lower() for x in (h.get('produces') or [])}
            for h in hops
        )
        chain_fields = {str(x).lower() for x in _chain_fields(chain)}
        if fl not in chain_fields and not produces_field:
            continue
        score = _rank_score(chain, rank_by_id)
        if produces_field:
            score += 25.0
        if infer_domain_from_path(entry_path) == domain:
            score += 10.0
        norm = normalize_api_path(entry_path)
        prev = candidates.get(norm)
        if not prev or score > prev['score']:
            candidates[norm] = {
                'entry_path': entry_path,
                'entry_api': chain.get('entry_api'),
                'chain_id': chain.get('chain_id'),
                'score': score,
                'source': 'chain_entry',
            }

    for path, card in cards_by_path.items():
        if infer_domain_from_path(path) != domain and domain != 'general':
            continue
        score = 0.0
        if _LIST_PATH_RE.search(path):
            score += 20.0
        if re.search(r'getOrderList|orderList|myOrder|order/list', path, re.I):
            score += 35.0
        if fl.replace('id', '') in path.lower():
            score += 15.0
        ld_bonus = max(
            (list_detail_score(path, p) for p in cards_by_path if fl.replace('id', '') in p.lower()),
            default=0.0,
        )
        score += ld_bonus * 10.0
        if score < 15.0:
            continue
        norm = normalize_api_path(path)
        prev = candidates.get(norm)
        if not prev or score > prev['score']:
            candidates[norm] = {
                'entry_path': path,
                'entry_api': card.get('api_id') or card.get('card_id'),
                'chain_id': None,
                'score': score,
                'source': 'card_list_heuristic',
            }

    return sorted(candidates.values(), key=lambda x: -x['score'])[:6]


def _save_as_hint(entry_path: str, domain: str) -> str:
    slug = re.sub(r'[^\w]+', '_', (entry_path or domain).strip('/').split('/')[-1] or domain)
    slug = slug.strip('_').lower()[:40] or domain
    return f'need_{domain}_{slug}.http'


def _infer_fields_for_probe_path(
    path: str,
    templates_by_path: Dict[str, Dict[str, Any]],
) -> List[str]:
    """Heuristic harvest fields when probe failed for lack of business state."""
    tpl = templates_by_path.get(normalize_api_path(path)) or {}
    fields: List[str] = []
    pt = tpl.get('plain_template') or {}
    runtime = {str(x).lower() for x in (tpl.get('runtime_generated_fields') or [])}
    for bag in (pt.get('body_params') or {}, pt.get('query_params') or {}):
        if not isinstance(bag, dict):
            continue
        for k, v in bag.items():
            if str(k).lower() in runtime:
                continue
            if str(v).startswith('$'):
                continue
            if IDENTITY_PARAM_RE.match(str(k)) or OBJECT_PARAM_RE.match(str(k)):
                fields.append(k)
    if fields:
        return list(dict.fromkeys(fields))
    domain = _normalize_domain(path)
    domain_defaults = {
        'order': ['orderId'],
        'task': ['taskId'],
        'device': ['deviceId'],
        'member': ['userId'],
        'dept': ['deptId'],
    }
    return domain_defaults.get(domain, [])


def _templates_by_path(pack_dir: Path) -> Dict[str, Dict[str, Any]]:
    doc = _load_json(pack_dir / 'materialized_api_templates.json') or {}
    out: Dict[str, Dict[str, Any]] = {}
    for tpl in doc.get('templates') or []:
        p = normalize_api_path(tpl.get('path') or '')
        if p:
            out[p] = tpl
    return out


def _parse_probe_failures(pack_dir: Path) -> List[Dict[str, Any]]:
    failures: List[Dict[str, Any]] = []
    for rel in ('risk_probe_report.json', 'binding_coverage_report.json'):
        doc = _load_json(pack_dir / rel) or {}
        rows = doc.get('results') or ((doc.get('risk_probe') or {}).get('results')) or []
        for row in rows:
            if row.get('status') != 'm0_failed':
                continue
            outcome = row.get('m0_outcome') or ''
            if outcome in {'business_state_blocked', 'validation_error', 'unknown_response'}:
                failures.append({
                    'path': row.get('path'),
                    'api_id': row.get('api_id'),
                    'm0_outcome': outcome,
                    'source': rel,
                })
    seen: Set[str] = set()
    deduped: List[Dict[str, Any]] = []
    for row in failures:
        key = normalize_api_path(row.get('path') or '')
        if not key or key in seen:
            continue
        seen.add(key)
        deduped.append(row)
    return deduped


def _parse_campaign_gaps(pack_dir: Path) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    cov = _load_json(pack_dir / 'binding_coverage_report.json') or {}
    risk = cov.get('risk_coverage') or {}
    gaps: List[Dict[str, Any]] = []
    for row in risk.get('uncovered') or []:
        gaps.append({
            'path': row.get('path'),
            'api_id': row.get('api_id'),
            'rule_score': row.get('rule_score'),
            'source': 'campaign_uncovered_probe',
        })
    for row in cov.get('chain_results') or []:
        if row.get('reached_m7'):
            continue
        if row.get('verdict') in {'chain_blocked', 'stopped', 'blocked', 'waiting_for_entry_capture'}:
            gaps.append({
                'chain_id': row.get('chain_id'),
                'entry_path': row.get('entry_path'),
                'target_path': row.get('target_path'),
                'verdict': row.get('verdict'),
                'source': 'campaign_chain_blocked',
            })
    for row in _parse_probe_failures(pack_dir):
        gaps.append({**row, 'source': 'campaign_probe_m0_failed'})
    return gaps, risk


def build_baseline_capture_strategy(pack_dir: Path) -> Dict[str, Any]:
    """Compute unlock matrix and prioritized one-shot capture recommendations."""
    pack_dir = Path(pack_dir)
    chains_doc = _load_json(pack_dir / 'business_chains.json') or {}
    rank_doc = _load_json(pack_dir / 'chain_rank_plan.json') or {}
    risk_doc = _load_json(pack_dir / 'binding_risk_candidates.json') or {}
    material_plan = _load_json(pack_dir / 'chain_material_request_plan.json') or {}
    ctx = _load_json(pack_dir / 'baseline_runtime_context.json') or {}
    templates_by_path = _templates_by_path(pack_dir)

    chains = list(chains_doc.get('chains') or [])
    rank_by_id = {r.get('chain_id'): r for r in (rank_doc.get('top_chains') or []) if r.get('chain_id')}
    pool = _baseline_field_pool(pack_dir)
    has_auth = bool(ctx.get('crypto_replay_ready')) or any(
        k.lower() in {'token', 'uid', 'authorization'} for k in pool
    )

    cards_by_path: Dict[str, Dict[str, Any]] = {}
    ir_path = pack_dir / 'universal_ir' / 'universal_api_cards.json'
    ir_doc = _load_json(ir_path) or {}
    for card in (ir_doc.get('cards') or ir_doc.get('items') or []):
        p = normalize_api_path(card.get('path') or '')
        if p:
            cards_by_path[p] = card
    if not cards_by_path:
        try:
            from minidrifter.reasoning.pack_loader import load_pack
            pack = load_pack(pack_dir)
            for card in pack.get('cards') or []:
                p = normalize_api_path(card.get('path') or '')
                if p:
                    cards_by_path[p] = card
        except Exception:
            pass

    field_to_chains: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    pool_runnable = 0
    blocked_chains: List[Dict[str, Any]] = []

    for chain in chains:
        fields = _chain_fields(chain)
        missing = [f for f in fields if not _pool_has(f, pool)]
        if missing:
            blocked_chains.append({'chain': chain, 'missing': missing})
            for f in missing:
                field_to_chains[f].append(chain)
        else:
            pool_runnable += 1

    probe_eligible = [
        c for c in (risk_doc.get('candidates') or [])
        if c.get('probe_eligible')
    ]
    field_to_probes: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for cand in probe_eligible:
        path = normalize_api_path(cand.get('path') or '')
        card = cards_by_path.get(path)
        id_fields = _identity_fields_from_candidate(cand, card)
        missing = [f for f in id_fields if not _pool_has(f, pool)]
        for f in missing:
            field_to_probes[f].append(cand)
        if not id_fields and not _pool_has('', pool):
            pass

    all_missing_fields = sorted(
        set(field_to_chains.keys()) | set(field_to_probes.keys()),
        key=lambda f: (
            0 if field_binding_risk_tier(f) == 'high' else 1,
            -(len(field_to_chains.get(f, [])) + len(field_to_probes.get(f, []))),
            f.lower(),
        ),
    )

    campaign_gaps, risk_cov = _parse_campaign_gaps(pack_dir)

    unlock_matrix: List[Dict[str, Any]] = []
    for field in all_missing_fields:
        ch_list = field_to_chains.get(field, [])
        pr_list = field_to_probes.get(field, [])
        domain = _field_domain(field)
        unlock_matrix.append({
            'field': field,
            'domain': domain,
            'status': 'missing',
            'risk_tier': field_binding_risk_tier(field),
            'chains_blocked': len(ch_list),
            'probe_eligible_blocked': len(pr_list),
            'high_risk_chains': sum(
                1 for c in ch_list
                if (chain_binding_risk_summary(_chain_fields(c)).get('binding_risk_tier') == 'high')
            ),
        })

    for row in material_plan.get('satisfied_by_baseline') or []:
        for f in (row.get('binding_fields') or row.get('shared_fields') or []):
            if _pool_has(f, pool) and f not in all_missing_fields:
                unlock_matrix.append({
                    'field': f,
                    'domain': _field_domain(f),
                    'status': 'satisfied',
                    'risk_tier': field_binding_risk_tier(f),
                    'chains_unlocked': len(row.get('unlocks_chains') or []),
                    'matched_capture': row.get('matched_capture'),
                })

    recommendations: List[Dict[str, Any]] = []
    seen_domains: Set[str] = set()

    if not has_auth:
        recommendations.append({
            'recommendation_id': stable_id('rec', 'login', 'baseline'),
            'priority': 'P0',
            'plane': 'A_must_capture',
            'domain': 'auth',
            'title': '登录态基线（必抓）',
            'user_action': '请使用测试账号完成小程序登录，导出含 Token/uid 的首个业务请求 + 响应。',
            'save_as': 'login_baseline.http',
            'target_fields': ['Token', 'uid', 'openId'],
            'example_paths': [],
            'unlocks_chains_estimate': len(chains),
            'unlocks_probe_eligible_estimate': len(probe_eligible),
            'why': '无 replay 就绪认证字段时，其余抓包无法进入 Campaign。',
            'minimum': True,
        })

    domain_groups: Dict[str, Set[str]] = defaultdict(set)
    for field in all_missing_fields:
        domain_groups[_field_domain(field)].add(field)

    for domain, fields in sorted(
        domain_groups.items(),
        key=lambda kv: (
            0 if any(field_binding_risk_tier(f) == 'high' for f in kv[1]) else 1,
            -(sum(len(field_to_chains.get(f, [])) for f in kv[1]) + sum(len(field_to_probes.get(f, [])) for f in kv[1])),
        ),
    ):
        if domain in seen_domains:
            continue
        seen_domains.add(domain)
        fields_sorted = sorted(fields, key=lambda f: field_binding_risk_tier(f) != 'high')
        primary_field = fields_sorted[0]
        entries = _discover_producer_entries(
            primary_field, domain, chains=chains, cards_by_path=cards_by_path, rank_by_id=rank_by_id,
        )
        entry_path = entries[0]['entry_path'] if entries else ''
        entry_api = entries[0].get('entry_api') if entries else None
        chain_for_ctx = next(
            (c for c in field_to_chains.get(primary_field, []) if c.get('entry_path') == entry_path),
            (field_to_chains.get(primary_field) or [{}])[0] if field_to_chains.get(primary_field) else {},
        )
        entry_ctx = resolve_entry_context(pack_dir, entry_path, api_id=entry_api) if entry_path else {}
        chains_unlock = len({c.get('chain_id') for f in fields for c in field_to_chains.get(f, []) if c.get('chain_id')})
        probes_unlock = len({c.get('api_id') for f in fields for c in field_to_probes.get(f, []) if c.get('api_id')})
        high_risk_probes = [
            c for f in fields for c in field_to_probes.get(f, [])
            if float(c.get('rule_score') or 0) >= 45
        ]
        priority = 'P0' if (
            any(field_binding_risk_tier(f) == 'high' for f in fields)
            or high_risk_probes
            or probes_unlock >= 3
        ) else 'P1'

        user_action = (
            build_semantic_user_action(chain_for_ctx, entry_ctx)
            if chain_for_ctx.get('chain_id')
            else _DOMAIN_ACTIONS.get(domain, _DOMAIN_ACTIONS['general'])
        )
        if entry_path and entry_path not in user_action:
            user_action += f' 优先确认响应含 `{", ".join(fields_sorted[:4])}`。'

        plan_req = next(
            (r for r in (material_plan.get('requests') or [])
             if any(normalize_api_path(p) == normalize_api_path(entry_path) for p in (r.get('example_paths') or []))),
            None,
        )
        rec_id = (plan_req or {}).get('request_id') or stable_id('rec', domain, primary_field)

        recommendations.append({
            'recommendation_id': rec_id,
            'priority': priority,
            'plane': 'A_must_capture',
            'domain': domain,
            'title': f'{domain} 域入口（ harvest `{"`, `".join(fields_sorted[:4])}` ）',
            'user_action': user_action,
            'save_as': _save_as_hint(entry_path, domain),
            'target_fields': fields_sorted[:8],
            'example_paths': [entry_path] if entry_path else [],
            'entry_api': entry_api,
            'unlocks_chains_estimate': chains_unlock,
            'unlocks_probe_eligible_estimate': probes_unlock,
            'high_risk_probe_paths': list(dict.fromkeys(
                c.get('path') for c in high_risk_probes if c.get('path')
            ))[:6],
            'why': (
                f'缺字段 `{", ".join(fields_sorted[:4])}` → 阻断 **{chains_unlock}** 条链、'
                f'**{probes_unlock}** 个 probe_eligible 高危 API；'
                f'补 1 条 `{entry_path or "域内列表/详情"}` 抓包可一次性解锁。'
            ),
            'minimum': priority == 'P0',
            'alternative_entries': [e['entry_path'] for e in entries[1:4]],
        })

    for req in material_plan.get('requests') or []:
        rid = req.get('request_id')
        if any(r.get('recommendation_id') == rid for r in recommendations):
            continue
        paths = req.get('example_paths') or []
        recommendations.append({
            'recommendation_id': rid,
            'priority': 'P0' if req.get('priority') == 'high' else 'P1',
            'plane': 'A_must_capture',
            'domain': infer_domain_from_path((paths or [''])[0]),
            'title': f'材料计划缺口 {rid}',
            'user_action': req.get('recommended_user_action') or _DOMAIN_ACTIONS['general'],
            'save_as': _save_as_hint((paths or ['gap'])[0], 'gap'),
            'target_fields': req.get('target_fields') or req.get('binding_fields') or [],
            'example_paths': paths,
            'unlocks_chains_estimate': len((req.get('unlocks') or {}).get('chains') or []),
            'unlocks_probe_eligible_estimate': 0,
            'why': req.get('why_needed') or '',
            'minimum': bool(req.get('minimum')),
        })

    expansion_by_domain: Dict[str, Dict[str, Any]] = {}
    probe_eligible_paths = {
        normalize_api_path(c.get('path') or '')
        for c in probe_eligible
        if c.get('path')
    }
    risk_by_path = {
        normalize_api_path(c.get('path') or ''): c
        for c in (risk_doc.get('candidates') or [])
        if c.get('path')
    }
    for fail in _parse_probe_failures(pack_dir):
        path = normalize_api_path(fail.get('path') or '')
        if not path or (probe_eligible_paths and path not in probe_eligible_paths):
            continue
        domain = _normalize_domain(path)
        harvest = _infer_fields_for_probe_path(path, templates_by_path)
        harvest = [f for f in harvest if not _pool_has(f, pool)]
        cand = risk_by_path.get(path) or {}
        signal_ids = _identity_fields_from_candidate(cand, cards_by_path.get(path))
        if not harvest and not signal_ids:
            continue
        if has_auth and not harvest and cand.get('probe_eligible'):
            continue
        if not harvest and signal_ids:
            harvest = [f for f in signal_ids if not _pool_has(f, pool)]
        if not harvest:
            continue
        blob = expansion_by_domain.get(domain)
        if not blob:
            primary = harvest[0] if harvest else 'orderId'
            entries = _discover_producer_entries(
                primary, domain, chains=chains, cards_by_path=cards_by_path, rank_by_id=rank_by_id,
            )
            expansion_by_domain[domain] = {
                'domain': domain,
                'target_fields': list(dict.fromkeys(harvest)),
                'failed_probe_paths': [path],
                'entry_path': entries[0]['entry_path'] if entries else '',
                'entry_api': entries[0].get('entry_api') if entries else None,
                'alternative_entries': [e['entry_path'] for e in entries[1:4]],
            }
        else:
            blob['failed_probe_paths'].append(path)
            blob['target_fields'] = list(dict.fromkeys(blob['target_fields'] + harvest))

    for domain, blob in expansion_by_domain.items():
        if domain in seen_domains:
            for rec in recommendations:
                if rec.get('domain') == domain:
                    rec.setdefault('high_risk_probe_paths', [])
                    rec['high_risk_probe_paths'] = list(dict.fromkeys(
                        (rec.get('high_risk_probe_paths') or []) + blob['failed_probe_paths']
                    ))[:8]
                    if blob['failed_probe_paths']:
                        rec['priority'] = 'P0'
                        rec['minimum'] = True
                        rec['why'] = (
                            (rec.get('why') or '')
                            + f' Campaign 直探 M0 失败：`{"`, `".join(blob["failed_probe_paths"][:3])}`。'
                        )
            continue
        entry_path = blob.get('entry_path') or ''
        fields = blob.get('target_fields') or []
        recommendations.append({
            'recommendation_id': stable_id('rec', 'expand', domain),
            'priority': 'P0',
            'plane': 'A_must_capture',
            'domain': domain,
            'title': f'{domain} 域扩展（Campaign 未达 M7 的高危 API）',
            'user_action': (
                _DOMAIN_ACTIONS.get(domain, _DOMAIN_ACTIONS['general'])
                + (f' 优先确认响应含 `{", ".join(fields[:4])}`。' if fields else '')
            ),
            'save_as': _save_as_hint(entry_path, domain),
            'target_fields': fields[:8],
            'example_paths': [entry_path] if entry_path else [],
            'entry_api': blob.get('entry_api'),
            'unlocks_chains_estimate': 0,
            'unlocks_probe_eligible_estimate': len(blob.get('failed_probe_paths') or []),
            'high_risk_probe_paths': blob.get('failed_probe_paths') or [],
            'why': (
                f'Campaign 直探 M0 失败 **{len(blob.get("failed_probe_paths") or [])}** 个高危 API；'
                f'补 `{entry_path or domain + " 列表/详情"}` 可注入业务态字段并扩大探测深度。'
            ),
            'minimum': True,
            'alternative_entries': blob.get('alternative_entries') or [],
        })
        seen_domains.add(domain)

    plane_gaps: List[Dict[str, Any]] = []
    try:
        from minidrifter.classification.api_plane_classifier import build_plane_capture_gaps
        plane_gaps = build_plane_capture_gaps(pack_dir)
        seen_plane = {r.get('api_plane') or r.get('plane') for r in recommendations}
        for gap in plane_gaps:
            if gap.get('plane') in seen_plane:
                continue
            recommendations.append({
                'recommendation_id': stable_id('rec', 'plane', gap.get('plane', 'x')),
                'priority': gap.get('priority', 'P1'),
                'plane': 'A_must_capture',
                'api_plane': gap.get('plane'),
                'baseline_category': gap.get('baseline_category'),
                'domain': gap.get('plane', 'general'),
                'title': gap.get('title'),
                'user_action': gap.get('why'),
                'save_as': gap.get('save_as'),
                'target_fields': gap.get('missing_harvest_fields') or [],
                'example_paths': [gap['example_path']] if gap.get('example_path') else [],
                'unlocks_chains_estimate': 0,
                'unlocks_probe_eligible_estimate': gap.get('detected_apis') or 0,
                'why': gap.get('why'),
                'minimum': gap.get('priority') == 'P0',
            })
            seen_plane.add(gap.get('plane'))
    except Exception:
        pass

    recommendations.sort(key=lambda r: (
        0 if r.get('priority') == 'P0' else 1,
        -(r.get('unlocks_chains_estimate') or 0) - (r.get('unlocks_probe_eligible_estimate') or 0) * 2,
    ))

    satisfied_domains: List[Dict[str, Any]] = []
    dom_chains: Dict[str, int] = defaultdict(int)
    for row in material_plan.get('satisfied_by_baseline') or []:
        dom = infer_domain_from_path(row.get('static_entry') or '')
        dom_chains[dom] += len(row.get('unlocks_chains') or [])
    for dom, count in sorted(dom_chains.items(), key=lambda x: -x[1]):
        satisfied_domains.append({'domain': dom, 'chains_unlocked': count, 'status': 'satisfied'})

    total_chains = len(chains)
    rec_chain_unlock = sum(r.get('unlocks_chains_estimate') or 0 for r in recommendations if r.get('plane') == 'A_must_capture')
    est_coverage = min(
        total_chains,
        pool_runnable + rec_chain_unlock,
    ) if total_chains else 0

    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': _utc_now(),
        'pack_dir': str(pack_dir),
        'summary': {
            'static_chain_count': total_chains,
            'pool_runnable_chains': pool_runnable,
            'blocked_chain_count': len(blocked_chains),
            'probe_eligible_total': len(probe_eligible),
            'probe_blocked_by_pool': sum(len(v) for v in field_to_probes.values()),
            'recommendation_count': len(recommendations),
            'must_capture_count': sum(1 for r in recommendations if r.get('minimum')),
            'estimated_chain_coverage_if_complete': est_coverage,
            'baseline_field_count': len(pool),
            'has_auth': has_auth,
        },
        'unlock_matrix': unlock_matrix,
        'capture_recommendations': recommendations,
        'satisfied_domains': satisfied_domains,
        'campaign_feedback_gaps': campaign_gaps,
        'plane_capture_gaps': plane_gaps,
        'risk_coverage_snapshot': {
            'covered_count': risk_cov.get('covered_count'),
            'probe_eligible_total': risk_cov.get('probe_eligible_total'),
            'uncovered_count': risk_cov.get('uncovered_count'),
        },
        'note': (
            'One-shot baseline strategy: each A-plane recommendation is a domain entry capture '
            'intended to maximize chain depth/breadth and probe_eligible high-risk API reach.'
        ),
    }


def write_baseline_capture_strategy(pack_dir: Path) -> Path:
    pack_dir = Path(pack_dir)
    doc = build_baseline_capture_strategy(pack_dir)
    out = pack_dir / 'baseline_capture_strategy.json'
    write_json(out, doc)
    return out


def render_baseline_strategy_section(pack_dir: Path, strategy: Optional[Dict[str, Any]] = None) -> List[str]:
    """Markdown lines for chain_intake_prompt — maximum-yield baseline section."""
    pack_dir = Path(pack_dir)
    doc = strategy or build_baseline_capture_strategy(pack_dir)
    summary = doc.get('summary') or {}
    recs = doc.get('capture_recommendations') or []
    matrix = doc.get('unlock_matrix') or []
    lines = [
        '## 0. 一次性 Baseline 抓包策略（最大收益）',
        '',
        '> **目标**：用**最少条数**的真人抓包，一次性解锁最多业务链（深度/广度）与 probe_eligible 高危 API。',
        '> **A 面必抓** = 下列推荐；**B 面** = 系统自动重放，不要求用户逐 API 抓包。',
        '',
        '### 覆盖预估',
        '',
        f'- 静态业务链：**{summary.get("static_chain_count", 0)}** 条',
        f'- 当前对象池已可跑：**{summary.get("pool_runnable_chains", 0)}** 条',
        f'- 仍缺字段阻断：**{summary.get("blocked_chain_count", 0)}** 条',
        f'- probe_eligible 高危 API：**{summary.get("probe_eligible_total", 0)}**（池外参数阻断约 **{summary.get("probe_blocked_by_pool", 0)}** 次引用）',
        f'- 按本策略补全后预估链覆盖：**{summary.get("estimated_chain_coverage_if_complete", 0)}** 条',
        '',
    ]
    plane_gaps = doc.get('plane_capture_gaps') or []
    if plane_gaps:
        lines.extend(['### 敏感 API 平面缺口（P4）', ''])
        for gap in plane_gaps[:6]:
            fields = ', '.join(gap.get('missing_harvest_fields') or []) or '—'
            lines.append(
                f"- **{gap.get('title', gap.get('plane'))}**（{gap.get('baseline_category', '')}）"
                f" — 缺 `{fields}` · 示例 `{gap.get('example_path', '')}`"
            )
        lines.append('')

    must = [r for r in recs if r.get('plane') == 'A_must_capture' and r.get('minimum')]
    optional = [r for r in recs if r.get('plane') == 'A_must_capture' and not r.get('minimum')]
    if must:
        lines.extend(['### A. 必抓（P0 / minimum）', ''])
        for i, rec in enumerate(must, 1):
            paths = ', '.join(f'`{p}`' for p in (rec.get('example_paths') or [])[:2]) or '—'
            fields = ', '.join(f'`{f}`' for f in (rec.get('target_fields') or [])[:6]) or '—'
            lines.extend([
                f'#### 0.{i} {rec.get("title") or rec.get("domain")}',
                f'- **优先级**：{rec.get("priority", "P0")}',
                f'- **操作**：{rec.get("user_action", "")}',
                f'- **保存为**：`baseline/user_materials/{rec.get("save_as", "capture.http")}`',
                f'- **入口 API**：{paths}',
                f'- **需要 harvest**：{fields}',
                f'- **预估解锁**：**{rec.get("unlocks_chains_estimate", 0)}** 链 + '
                f'**{rec.get("unlocks_probe_eligible_estimate", 0)}** 高危 API',
            ])
            hr = rec.get('high_risk_probe_paths') or []
            if hr:
                lines.append(f'- **关联高危 API**：`{"`, `".join(hr[:4])}`')
            lines.append(f'- **原因**：{rec.get("why", "")}')
            alts = rec.get('alternative_entries') or []
            if alts:
                lines.append(f'- **备选入口**：`{"`, `".join(alts[:3])}`')
            lines.extend(['', '---', ''])

    if optional:
        lines.extend(['### B. 建议扩展（P1，扩大覆盖）', ''])
        for rec in optional[:6]:
            paths = ', '.join(f'`{p}`' for p in (rec.get('example_paths') or [])[:1]) or '—'
            lines.append(
                f'- **{rec.get("domain")}** {paths} → harvest `{", ".join((rec.get("target_fields") or [])[:3])}` '
                f'（+{rec.get("unlocks_chains_estimate", 0)} 链 / +{rec.get("unlocks_probe_eligible_estimate", 0)} 高危）'
            )
        lines.append('')

    satisfied = doc.get('satisfied_domains') or []
    if satisfied:
        lines.extend(['### 已满足域（无需重复抓）', ''])
        for row in satisfied:
            lines.append(f'- **{row.get("domain")}**：已解锁约 **{row.get("chains_unlocked", 0)}** 链')
        lines.append('')

    missing_rows = [m for m in matrix if m.get('status') == 'missing']
    if missing_rows:
        lines.extend(['### 解锁矩阵（缺字段 → 影响）', '', '| 字段 | 域 | 风险 | 阻断链 | 阻断高危 API |', '|---|---|---|---|---|'])
        for row in missing_rows[:12]:
            lines.append(
                f'| `{row.get("field")}` | {row.get("domain")} | {row.get("risk_tier")} | '
                f'{row.get("chains_blocked", 0)} | {row.get("probe_eligible_blocked", 0)} |'
            )
        lines.append('')

    camp = doc.get('campaign_feedback_gaps') or []
    probe_fails = [g for g in camp if g.get('source') == 'campaign_probe_m0_failed']
    if probe_fails:
        lines.extend([
            '### Campaign 反馈（M0 失败 → 补抓建议已上调优先级）',
            '',
        ])
        for g in probe_fails[:8]:
            lines.append(
                f'- `{g.get("path", "—")}` → {g.get("m0_outcome", "m0_failed")}'
            )
        lines.append('')
    elif camp:
        lines.extend([
            '> **Campaign 反馈**：上次跑批仍有未覆盖项，已并入上述推荐优先级。',
            '',
        ])

    lines.extend(['---', ''])
    return lines


def deferred_gaps_from_strategy(pack_dir: Path) -> List[Dict[str, Any]]:
    """Domain-level deferred gaps for binding_coverage_report (post-campaign)."""
    doc = build_baseline_capture_strategy(pack_dir)
    gaps: List[Dict[str, Any]] = []
    for rec in doc.get('capture_recommendations') or []:
        if not rec.get('minimum'):
            continue
        paths = rec.get('example_paths') or []
        fields = rec.get('target_fields') or []
        if not fields and not paths:
            continue
        gaps.append({
            'request_id': rec.get('recommendation_id'),
            'domain': rec.get('domain'),
            'entry_paths': paths,
            'missing_fields': fields,
            'why_needed': rec.get('why'),
            'priority': rec.get('priority'),
            'unlocks_chains_estimate': rec.get('unlocks_chains_estimate'),
            'unlocks_probe_eligible_estimate': rec.get('unlocks_probe_eligible_estimate'),
            'source': 'baseline_capture_strategy',
        })
    return gaps
