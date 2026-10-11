# -*- coding: utf-8
"""Enrich business chain hops: mutation targets, replay materialization, entry context."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from minidrifter.business_chain.field_role import binding_fields_from_list, infer_field_role
from minidrifter.materials.intake_param_hints import normalize_api_path
from minidrifter.quality.semantics.page_evidence import (
    page_matches_api as _page_matches_api_graded,
    resolve_event_evidence_graded,
    resolve_page_evidence_graded,
)
from minidrifter.quality.semantics.path_tokens import infer_path_semantic

_MATERIALIZED_STATUSES = frozenset({'materialized_plain', 'materialized_with_crypto_profile'})
_REPLAY_READY = frozenset({'ready'})
_REPLAY_PARTIAL = frozenset({'partial', 'blocked'})

_SEMANTIC_PAGE_HINTS: List[Tuple[re.Pattern[str], str]] = [
    (re.compile(r'orders/description/list|orderquiz/apptag', re.I), 'pages/my/orderList/orderList'),
    (re.compile(r'citylist|deptlist|searchdept|listandmap', re.I), 'package/common/pages/cityList/index'),
    (re.compile(r'deptdetail', re.I), 'package/order/pages/deptDetail/index'),
]

_API_SEMANTIC_RULES: List[Tuple[re.Pattern[str], str, str]] = [
    (re.compile(r'citylist|opencity|city/list', re.I), '城市/门店选择', '选择城市或门店'),
    (re.compile(r'listandmap|dept.*map', re.I), '门店地图列表', '浏览门店地图'),
    (re.compile(r'dept.*list|querydept|storelist|searchdept', re.I), '门店搜索/选择', '搜索或选择门店'),
    (re.compile(r'dept.*detail|deptdetail', re.I), '门店详情', '查看门店详情'),
    (re.compile(r'addedservice', re.I), '增值服务列表', '浏览增值服务'),
    (re.compile(r'order.*list|orderdata/list|refund', re.I), '订单列表', '浏览订单列表'),
    (re.compile(r'order.*detail|orders/detail', re.I), '订单详情', '查看订单详情'),
    (re.compile(r'device/list', re.I), '设备列表', '浏览我的设备'),
    (re.compile(r'device.*detail|digitalkey', re.I), '设备/钥匙详情', '查看设备或数字钥匙'),
    (re.compile(r'invoice', re.I), '发票相关', '浏览发票列表或详情'),
    (re.compile(r'member|profile|userinfo', re.I), '个人中心', '打开个人中心'),
    (re.compile(r'comment', re.I), '评价列表', '浏览评价'),
    (re.compile(r'dropoff|pickup', re.I), '取还车', '取车或还车操作'),
]


def object_credential_fields_from_card(card: Optional[Dict[str, Any]]) -> Set[str]:
    """Extract object/subject credential field names from a frozen API card."""
    if not card:
        return set()
    out: Set[str] = set()
    replay = card.get('replay') or {}
    for mp in replay.get('mutation_points') or []:
        f = mp.get('field')
        if f:
            out.add(str(f))
    for bag in (
        (replay.get('plain_request_shape') or {}).get('body') or {},
        (replay.get('plain_request_shape') or {}).get('query') or {},
        (card.get('bindings') or {}).get('params') or {},
    ):
        if isinstance(bag, dict):
            for k, v in bag.items():
                if isinstance(v, str) and 'credential' in v:
                    out.add(str(k))
    for hint in (card.get('bindings') or {}).get('binding_hints_static') or []:
        if not isinstance(hint, dict):
            continue
        role = hint.get('credential_role') or hint.get('role') or ''
        if 'credential' in str(role):
            f = hint.get('field') or hint.get('name')
            if f:
                out.add(str(f))
    return out


def hop_readiness_status(
    api_id: str,
    *,
    card: Optional[Dict[str, Any]],
    template: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """Split replay readiness — partial is NOT runtime-ready."""
    tpl = template or {}
    replay = (card or {}).get('replay') or {}
    readiness_info = replay.get('readiness') or {}
    readiness = readiness_info.get('status') or ''
    blockers = list(readiness_info.get('blockers') or [])

    template_ready = tpl.get('status') in _MATERIALIZED_STATUSES
    runtime_ready = readiness in _REPLAY_READY and not blockers
    request_partial = readiness in _REPLAY_PARTIAL or bool(blockers)
    plain_shape = replay.get('plain_request_shape') or {}
    static_constructible = bool(
        template_ready
        or runtime_ready
        or request_partial
        or plain_shape.get('body')
        or plain_shape.get('query')
    )

    reason = 'not_materialized'
    if template_ready:
        reason = 'template_materialized'
    elif runtime_ready:
        reason = 'card_replay_ready'
    elif readiness == 'partial':
        reason = 'card_replay_partial'
    elif readiness:
        reason = f'card_replay_{readiness}'

    return {
        'static_constructible': static_constructible,
        'request_template_partial': request_partial and not template_ready and not runtime_ready,
        'request_template_ready': template_ready or runtime_ready,
        'runtime_replay_ready': runtime_ready or template_ready,
        'entry_seed_available': static_constructible,
        'replay_readiness': readiness or 'none',
        'replay_blockers': blockers,
        'materialized': runtime_ready or template_ready,
        'materialized_reason': reason,
    }


def hop_is_materialized(
    api_id: str,
    *,
    card: Optional[Dict[str, Any]],
    template: Optional[Dict[str, Any]],
) -> Tuple[bool, str]:
    """Backward-compatible strict readiness (runtime/template ready only)."""
    st = hop_readiness_status(api_id, card=card, template=template)
    return bool(st.get('materialized')), str(st.get('materialized_reason') or '')


def compute_hop_mutation_targets(
    hop: Dict[str, Any],
    *,
    chain_objects: Set[str],
    prev_hop: Optional[Dict[str, Any]],
    object_credential_fields: Set[str],
) -> List[str]:
    """mutation_targets = consumer.consumes ∩ chain.objects ∩ object_credential_fields;
    fallback: consumer.consumes ∩ producer.produces."""
    consumes = set(hop.get('consumes') or hop.get('requires') or [])
    if not consumes:
        return []

    primary = consumes & chain_objects & object_credential_fields
    if primary:
        return sorted(primary)

    if prev_hop:
        produces = set(prev_hop.get('produces') or [])
        bridge = consumes & produces
        if bridge:
            binding = set(binding_fields_from_list(sorted(bridge), path=hop.get('path') or ''))
            if binding:
                return sorted(binding)
            return sorted(bridge)

    binding = set(binding_fields_from_list(sorted(consumes & chain_objects), path=hop.get('path') or ''))
    return sorted(binding)


def enrich_hop(
    hop: Dict[str, Any],
    *,
    chain_objects: Set[str],
    prev_hop: Optional[Dict[str, Any]],
    card: Optional[Dict[str, Any]],
    template: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """Attach mutation_targets and materialized to a single hop."""
    cred_fields = object_credential_fields_from_card(card)
    hop = dict(hop)
    hop['mutation_targets'] = compute_hop_mutation_targets(
        hop,
        chain_objects=chain_objects,
        prev_hop=prev_hop,
        object_credential_fields=cred_fields,
    )
    readiness = hop_readiness_status(hop.get('api_id') or '', card=card, template=template)
    hop.update(readiness)
    if cred_fields:
        hop['object_credential_fields'] = sorted(cred_fields)
    return hop


def enrich_chain(
    chain: Dict[str, Any],
    *,
    cards_by_id: Dict[str, Dict[str, Any]],
    templates_by_id: Dict[str, Dict[str, Any]],
    pack_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    """Enrich all hops and recompute chain-level binding/risk fields."""
    chain = dict(chain)
    objects = set(chain.get('objects') or [])
    hops_in = chain.get('hops') or []
    hops_out: List[Dict[str, Any]] = []
    prev: Optional[Dict[str, Any]] = None
    for hop in hops_in:
        aid = hop.get('api_id') or ''
        enriched = enrich_hop(
            hop,
            chain_objects=objects,
            prev_hop=prev,
            card=cards_by_id.get(aid),
            template=templates_by_id.get(aid),
        )
        hops_out.append(enriched)
        prev = enriched
    chain['hops'] = hops_out

    binding_fields = sorted({f for h in hops_out for f in (h.get('mutation_targets') or [])})
    from minidrifter.business_chain.chain_semantic_scorer import (
        field_binding_risk_tier,
        is_subject_bridge_field,
    )
    primary_mutation = sorted(f for f in binding_fields if field_binding_risk_tier(f) == 'high')
    weak_mutation = sorted(f for f in binding_fields if is_subject_bridge_field(f))
    if not primary_mutation:
        primary_mutation = [f for f in binding_fields if not is_subject_bridge_field(f)]
    chain['binding_fields'] = binding_fields
    chain['primary_mutation_targets'] = primary_mutation
    chain['weak_mutation_targets'] = weak_mutation

    risk_hops = [h['api_id'] for h in hops_out if h.get('mutation_targets')]
    if primary_mutation:
        risk_hops = [
            h['api_id'] for h in hops_out
            if any(f in primary_mutation for f in (h.get('mutation_targets') or []))
        ] or risk_hops
    if not risk_hops and hops_out:
        risk_hops = [hops_out[-1]['api_id']]
    chain['risk_hops'] = risk_hops

    entry_hop = hops_out[0] if hops_out else {}
    consumer = hops_out[-1] if hops_out else {}

    chain['entry_materialized'] = bool(entry_hop.get('runtime_replay_ready'))
    chain['entry_materialized_reason'] = entry_hop.get('materialized_reason') or ''
    chain['entry_static_constructible'] = bool(entry_hop.get('static_constructible'))
    chain['entry_request_template_ready'] = bool(entry_hop.get('request_template_ready'))
    chain['entry_request_template_partial'] = bool(entry_hop.get('request_template_partial'))
    chain['entry_runtime_replay_ready'] = bool(entry_hop.get('runtime_replay_ready'))
    chain['entry_seed_available'] = bool(entry_hop.get('entry_seed_available'))

    chain['consumer_constructible'] = bool(
        consumer.get('static_constructible')
        and (consumer.get('mutation_targets') or consumer.get('consumes'))
    )
    chain['consumer_runtime_replay_ready'] = bool(consumer.get('runtime_replay_ready'))
    chain['mutation_target_count'] = sum(len(h.get('mutation_targets') or []) for h in hops_out)

    from minidrifter.business_chain.chain_semantic_scorer import chain_binding_risk_summary
    chain.update(chain_binding_risk_summary(binding_fields))

    entry_path = chain.get('entry_path') or ''
    if pack_dir and entry_path:
        entry_ctx = resolve_entry_context(
            pack_dir, entry_path, cards_by_id=cards_by_id, api_id=chain.get('entry_api'),
        )
        chain['entry_page'] = entry_ctx.get('entry_page')
        chain['entry_event'] = entry_ctx.get('entry_event')
        chain['entry_page_evidence'] = entry_ctx.get('entry_page_evidence')
        if entry_ctx.get('entry_page_confidence') is not None:
            chain['entry_page_confidence'] = entry_ctx.get('entry_page_confidence')
        chain['entry_event_evidence'] = entry_ctx.get('entry_event_evidence')
        chain['expected_response_fields'] = entry_ctx.get('expected_response_fields') or []

    missing = [
        o for o in sorted(objects)
        if not entry_hop.get('entry_seed_available') and not entry_hop.get('runtime_replay_ready')
    ]
    chain['missing_materials'] = missing[:6]
    return chain


def enrich_chains_doc(
    chains_doc: Dict[str, Any],
    *,
    cards_by_id: Dict[str, Dict[str, Any]],
    templates_by_id: Dict[str, Dict[str, Any]],
    pack_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    doc = dict(chains_doc)
    doc['chains'] = [
        enrich_chain(c, cards_by_id=cards_by_id, templates_by_id=templates_by_id, pack_dir=pack_dir)
        for c in (doc.get('chains') or [])
    ]
    return doc


def infer_api_semantic(api_path: str) -> Dict[str, str]:
    """Human-readable page/action labels from generic path token rules."""
    sem = infer_path_semantic(api_path)
    return {
        'page_label': sem['page_label'],
        'action_label': sem['action_label'],
        'api_tail': sem['api_tail'],
        'domain_hint': sem.get('domain_hint'),
        'page_tokens': sem.get('page_tokens'),
        'path_tokens': sem.get('path_tokens'),
    }


def resolve_entry_context(
    pack_dir: Optional[Path],
    api_path: str,
    *,
    cards_by_id: Optional[Dict[str, Dict[str, Any]]] = None,
    api_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Resolve reachability evidence — does NOT treat weak hints as capture entry."""
    pack_dir = Path(pack_dir) if pack_dir else None
    norm = normalize_api_path(api_path)
    semantic = infer_api_semantic(api_path)
    ctx: Dict[str, Any] = {
        'entry_path': api_path,
        'entry_api': api_id,
        'entry_page': None,
        'entry_event': None,
        'entry_page_evidence': None,
        'entry_event_evidence': None,
        'page_label': semantic['page_label'],
        'action_label': semantic['action_label'],
        'api_tail': semantic['api_tail'],
        'expected_response_fields': [],
        'reachability_candidates': [],
        'ui_reachability': None,
        'usable_for_capture': False,
    }

    if pack_dir and pack_dir.exists():
        from minidrifter.quality.runtime_reachability.ui_api_reachability import (
            assess_api_reachability,
            usable_for_capture,
        )
        reach = assess_api_reachability(pack_dir, api_path, api_id=api_id)
        ctx['reachability_candidates'] = reach.get('candidates') or []
        ctx['ui_reachability'] = reach.get('ui_reachability')
        ctx['usable_for_capture'] = reach.get('usable_for_capture', False)

        best = next((c for c in ctx['reachability_candidates'] if usable_for_capture(c)), None)
        if best:
            ctx['entry_page'] = best.get('page')
            ctx['entry_page_evidence'] = best.get('evidence')
            ctx['entry_page_confidence'] = best.get('confidence')
        else:
            page_hit = resolve_page_evidence_graded(
                pack_dir, api_path, api_id=api_id, semantic=semantic,
            )
            if page_hit:
                ctx['entry_page'] = page_hit.get('page')
                ctx['entry_page_evidence'] = page_hit.get('evidence')
                ctx['entry_page_confidence'] = page_hit.get('confidence')
                ctx['entry_page_usable_for_capture'] = page_hit.get('usable_for_capture', False)

        event_hit = resolve_event_evidence_graded(
            pack_dir, ctx.get('entry_page'), semantic=semantic,
        )
        if event_hit:
            ctx['entry_event'] = event_hit.get('event')
            ctx['entry_event_evidence'] = event_hit.get('evidence')

    if cards_by_id:
        card = None
        if api_id:
            card = cards_by_id.get(api_id)
        if not card:
            for c in cards_by_id.values():
                static = c.get('static') or {}
                ep = static.get('endpoint') or {}
                if normalize_api_path(ep.get('path') or static.get('path') or '') == norm:
                    card = c
                    break
        if card:
            orch = ((card.get('replay') or {}).get('oracle_hints') or {})
            ctx['expected_response_fields'] = list((orch.get('object_echo_fields') or [])[:6])
            objs = chain_objects_from_card(card)
            ctx['expected_response_fields'] = list(dict.fromkeys(
                ctx['expected_response_fields'] + sorted(objs)
            ))[:8]

    return ctx


def chain_objects_from_card(card: Dict[str, Any]) -> Set[str]:
    return object_credential_fields_from_card(card)


def build_semantic_user_action(
    chain: Dict[str, Any],
    entry_ctx: Optional[Dict[str, Any]] = None,
) -> str:
    """Accurate user capture instruction — delegates to P2 polish when available."""
    try:
        from minidrifter.reasoning.chain_plausibility_auditor import polish_intake_action
        return polish_intake_action(entry_ctx or {}, chain)
    except Exception:
        pass
    entry_ctx = entry_ctx or {}
    page = (
        entry_ctx.get('entry_page')
        or entry_ctx.get('page_label')
        or '对应业务页面'
    )
    action = entry_ctx.get('action_label') or '触发入口请求'
    api_path = chain.get('entry_path') or entry_ctx.get('entry_path') or ''
    api_tail = (entry_ctx.get('api_tail') or api_path.rsplit('/', 1)[-1]) if api_path else ''
    fields = chain.get('objects') or chain.get('binding_fields') or []
    field_hint = '、'.join(f'`{f}`' for f in fields[:4]) if fields else '业务对象字段'
    event = entry_ctx.get('entry_event')
    event_part = f'，操作：{event}' if event else ''
    return (
        f'请打开 `{page}` 页面{event_part}，{action}（入口 API: `{api_tail or api_path}`），'
        f'上传 request + response，响应中需包含 {field_hint}。'
    )


def _page_matches_api(page: str, semantic: Dict[str, str]) -> bool:
    return _page_matches_api_graded(page, semantic)


def _load_json(path: Path) -> Any:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding='utf-8'))


def _resolve_page_evidence(
    pack_dir: Path,
    api_path: str,
    *,
    api_id: Optional[str],
    semantic: Dict[str, str],
) -> Optional[Dict[str, Any]]:
    """Rank page candidates: callsite > demand graph > page_surface token match."""
    candidates: List[Tuple[float, str, str]] = []

    norm = normalize_api_path(api_path)
    tokens = _api_path_tokens(norm)
    api_tail = (semantic.get('api_tail') or '').lower()

    for pat, page in _SEMANTIC_PAGE_HINTS:
        if pat.search(norm):
            candidates.append((0.98, page, 'semantic_page_hint'))

    # 1) Direct call sites
    calls = _load_json(pack_dir / 'api_call_sites.json') or []
    if isinstance(calls, dict):
        calls = calls.get('api_call_sites') or calls.get('calls') or []
    for call in calls:
        url = normalize_api_path((call.get('resolved_url') or call.get('url') or '').split('?', 1)[0])
        if not _url_matches_api(url, norm, tokens):
            continue
        page = _page_from_source(call.get('source') or {})
        if page and _page_matches_api(page, semantic):
            candidates.append((0.95, page, 'api_call_site'))

    # 2) Demand graph callsite refs
    if api_id:
        full = _load_json(pack_dir / 'runtime_demand_graph.full.json') or {}
        for edge in full.get('edges') or []:
            if edge.get('from_api') != api_id and edge.get('from') != api_id:
                continue
            for ref in edge.get('evidence_refs') or []:
                if not isinstance(ref, str) or not ref.startswith('callsite:'):
                    continue
                m = re.search(r'(pages/[^:]+|package/[^:]+)\.js', ref.replace('\\', '/'))
                if m:
                    page = m.group(1)
                    if not page.endswith('/index') and '/index' not in page:
                        page = page  # keep as-is
                    candidates.append((0.88, page, 'demand_graph_callsite'))

    # 3) page_surface token scoring
    surface = _load_json(pack_dir / 'page_surface.json') or {}
    for pg in surface.get('pages') or []:
        pid = (pg.get('page_id') or '').lower()
        score = _page_token_score(pid, tokens, api_tail, semantic)
        if score >= 0.45:
            candidates.append((score, pg.get('page_id') or '', 'page_surface'))

    if not candidates:
        return None
    candidates.sort(key=lambda x: x[0], reverse=True)
    best_score, page, evidence = candidates[0]
    if page and _page_matches_api(page, semantic):
        return {'page': page, 'evidence': evidence, 'confidence': round(best_score, 2)}
    # fallback: page_surface with semantic label only
    for score, page, evidence in candidates:
        if evidence == 'page_surface' and score >= 0.5:
            return {'page': page, 'evidence': evidence, 'confidence': round(score, 2)}
    return None


def _resolve_event_evidence(
    pack_dir: Path,
    page_id: Optional[str],
    *,
    semantic: Dict[str, str],
) -> Optional[Dict[str, Any]]:
    if not page_id:
        return None
    events = _load_json(pack_dir / 'events.json') or []
    if isinstance(events, dict):
        events = events.get('events') or events.get('items') or []
    page_low = page_id.lower()
    matched: List[Tuple[float, str, str]] = []
    for ev in events:
        pg = str(ev.get('page') or '')
        if pg.lower() != page_low and page_low not in pg.lower() and pg.lower() not in page_low:
            continue
        et = ev.get('event_type') or ''
        handler = ev.get('handler') or ''
        score = 0.5
        if et in {'onLoad', 'onShow'}:
            score = 0.92
        elif et in {'bindtap', 'bind:tap', 'tap'}:
            score = 0.75
        if any(k in handler.lower() for k in ('load', 'init', 'fetch', 'list', 'search', 'select')):
            score += 0.08
        matched.append((score, f'{et}:{handler}' if handler else et, 'events.json'))
    if not matched:
        return None
    matched.sort(key=lambda x: x[0], reverse=True)
    score, event, evidence = matched[0]
    return {'event': event, 'evidence': evidence, 'confidence': round(score, 2)}


def _api_path_tokens(norm_path: str) -> Set[str]:
    parts = [p for p in norm_path.split('/') if p and p not in _GENERIC_SEG]
    if 'order' in norm_path or 'orders' in norm_path:
        parts.extend(['order', 'orders'])
    if 'list' in norm_path:
        parts.append('list')
    return {p.lower() for p in parts}


def _url_matches_api(url: str, norm_path: str, tokens: Set[str]) -> bool:
    if not url or len(url) < 8 or url in {'/', ''}:
        return False
    if url == norm_path or norm_path in url or url.endswith(norm_path.rsplit('/', 1)[-1]):
        return True
    tail = norm_path.rsplit('/', 1)[-1]
    if tail and len(tail) > 2 and tail in url:
        return True
    matched = sum(1 for t in tokens if len(t) > 3 and t in url)
    return matched >= 2


def _page_from_source(source: Dict[str, Any]) -> Optional[str]:
    fpath = (source.get('file') or '').replace('\\', '/')
    if fpath.startswith('pages/') or fpath.startswith('package/'):
        return fpath.rsplit('.', 1)[0]
    m = re.search(r'((?:pages|package)/[\w./-]+)', fpath)
    return m.group(1).rstrip('/') if m else None


def _page_token_score(page_id: str, tokens: Set[str], api_tail: str, semantic: Dict[str, str]) -> float:
    pid = page_id.lower()
    score = 0.0
    if api_tail and api_tail in pid:
        score += 0.55
    overlap = sum(1 for t in tokens if t in pid)
    score += min(0.35, overlap * 0.12)
    label = (semantic.get('page_label') or '').lower()
    if '城市' in label or '门店' in label:
        if any(k in pid for k in ('city', 'dept', 'store', 'shop')):
            score += 0.25
    if '订单' in label and 'order' in pid:
        score += 0.30
    if '设备' in label and any(k in pid for k in ('device', 'digitalkey')):
        score += 0.25
    return min(score, 0.98)
