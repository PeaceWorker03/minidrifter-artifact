# -*- coding: utf-8 -*-
"""LLM enrichment for chain UI capture guides — concrete navigation + Chinese labels."""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from minidrifter.core.utils import write_json
from minidrifter.materials.intake_param_hints import normalize_api_path
from minidrifter.reasoning.llm_client import LLMClient, LLMClientError
from minidrifter.reasoning.validator import parse_json_from_llm

UI_GUIDE_SYSTEM = """你是 MiniDrifter 小程序抓包操作指引助手。
根据静态分析证据，为测试人员生成**具体、可执行**的小程序 UI 操作步骤（中文）。

硬性规则：
1. 只能使用输入中出现的 page_id、API path、event 名称、navigation_steps；禁止编造不存在的页面或接口。
2. 若输入 llm_eligible=false，返回空 enrichments 列表。
3. 步骤面向真人操作：打开微信 → 进入小程序 → 点击可见按钮/Tab → 等待加载 → 抓包。
4. 若证据不足，不要虚构细节；可省略 navigation_steps，仅润色 page_name_zh。
5. 页面中文名根据 page_id、wxml 按钮文案、API 语义合理翻译。
6. 不要写安全漏洞、渗透、攻击相关内容。
7. navigation_steps 必须复用或细化输入中的 navigation_steps / inbound_nav，不得凭空写「首页网点地图」等未出现的路径。
8. ui_steps 中抓包筛选的 API path 必须与 capture_path 或 capture_accept_paths 一致。
9. login_baseline_steps 仅当输入无 rule_login_steps 时生成（4–6 步）。

输出严格 JSON：
{
  "login_baseline_steps": ["步骤1"] 或 [],
  "enrichments": [
    {
      "request_id": "必须与输入一致",
      "page_name_zh": "页面中文名",
      "one_line_task": "一句话任务描述",
      "navigation_steps": ["从首页…", "点击…"],
      "ui_steps": ["完整步骤…"]
    }
  ]
}
"""

def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _load_json(path: Path) -> Any:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding='utf-8'))


def _resolve_project_root(pack_dir: Path) -> Optional[Path]:
    prof = _load_json(pack_dir / 'project_profile.json') or {}
    root = prof.get('project_root')
    if root and Path(root).is_dir():
        return Path(root)
    parent = pack_dir.parent
    if (parent / 'app.json').exists():
        return parent
    return None


def _wxml_hints(root: Path, page_id: Optional[str]) -> Dict[str, Any]:
    if not page_id:
        return {}
    wxml_path = root / f'{page_id}.wxml'
    if not wxml_path.exists():
        return {}
    text = wxml_path.read_text(encoding='utf-8', errors='replace')
    bindtaps = list(dict.fromkeys(re.findall(r'bindtap=["\']([^"\']+)["\']', text)))[:12]
    catchtaps = list(dict.fromkeys(re.findall(r'catchtap=["\']([^"\']+)["\']', text)))[:8]
    labels = []
    for m in re.finditer(r'>([^<]{2,24})</', text):
        t = m.group(1).strip()
        if t and not t.startswith('{{') and t not in labels:
            labels.append(t)
        if len(labels) >= 12:
            break
    return {
        'bindtap_handlers': bindtaps,
        'catchtap_handlers': catchtaps,
        'visible_text_samples': labels,
        'wxml_excerpt': text[:1800],
    }


def _app_navigation_hints(root: Path) -> Dict[str, Any]:
    app = _load_json(root / 'app.json') or {}
    tab_bar = app.get('tabBar') or {}
    tabs = []
    for item in tab_bar.get('list') or []:
        tabs.append({
            'text': item.get('text'),
            'pagePath': item.get('pagePath'),
        })
    login_pages = [p for p in (app.get('pages') or []) if 'login' in p.lower()]
    entry = app.get('entryPagePath')
    return {
        'entry_page': entry,
        'tab_bar': tabs,
        'login_pages': login_pages[:5],
        'subpackage_roots': [s.get('root') for s in (app.get('subPackages') or []) if s.get('root')][:12],
    }


def _callsites_for_entry(pack_dir: Path, entry_path: str, entry_api: Optional[str]) -> List[Dict[str, Any]]:
    calls = _load_json(pack_dir / 'api_call_sites.json') or []
    if isinstance(calls, dict):
        calls = calls.get('api_call_sites') or calls.get('calls') or []
    norm = (entry_path or '').lower()
    tail = norm.rsplit('/', 1)[-1] if norm else ''
    out: List[Dict[str, Any]] = []
    for call in calls:
        url = (call.get('resolved_url') or call.get('url') or '').lower()
        if tail and tail not in url:
            continue
        src = call.get('source') or {}
        out.append({
            'file': (src.get('file') or '').replace('\\', '/'),
            'function': src.get('function') or src.get('name'),
            'line': src.get('line'),
        })
        if len(out) >= 6:
            break
    return out


def _build_request_payload(
    pack_dir: Path,
    req: Dict[str, Any],
    chain: Dict[str, Any],
    entry_ctx: Dict[str, Any],
    rule_guide: Dict[str, Any],
) -> Dict[str, Any]:
    pack_dir = Path(pack_dir)
    root = _resolve_project_root(pack_dir)
    page_id = (
        req.get('entry_page')
        or entry_ctx.get('entry_page')
        or chain.get('entry_page')
    )
    entry_path = (req.get('example_paths') or [chain.get('entry_path') or ''])[0]
    payload: Dict[str, Any] = {
        'request_id': req.get('request_id'),
        'priority': req.get('priority'),
        'minimum': req.get('minimum'),
        'project_name': pack_dir.parent.name,
        'entry_page': page_id,
        'entry_event': req.get('entry_event') or entry_ctx.get('entry_event') or chain.get('entry_event'),
        'entry_path': entry_path,
        'entry_api': req.get('entry_api') or chain.get('entry_api'),
        'chain_type': chain.get('chain_type'),
        'chain_type_label': rule_guide.get('chain_type_label'),
        'domain': chain.get('domain'),
        'expected_response_fields': req.get('expected_response_fields') or entry_ctx.get('expected_response_fields') or [],
        'binding_fields': req.get('binding_fields') or chain.get('binding_fields') or [],
        'unlock_chain_summary': rule_guide.get('ui_steps', [])[:3],
        'rule_page_name': rule_guide.get('page_name'),
        'rule_ui_steps': rule_guide.get('ui_steps') or [],
        'page_evidence': {
            'entry_page_evidence': req.get('entry_page_evidence') or chain.get('entry_page_evidence'),
            'entry_event_evidence': req.get('entry_event_evidence') or chain.get('entry_event_evidence'),
        },
        'callsites': _callsites_for_entry(pack_dir, entry_path, req.get('entry_api')),
    }
    if root:
        payload['app_navigation'] = _app_navigation_hints(root)
        payload['wxml_hints'] = _wxml_hints(root, page_id)
    meta = {}
    surface = _load_json(pack_dir / 'page_surface.json') or {}
    for pg in surface.get('pages') or []:
        if pg.get('page_id') == page_id:
            meta = {k: pg.get(k) for k in ('subpackage', 'is_tab_page', 'declared_from')}
            break
    payload['page_surface'] = meta
    return payload


def _allowed_vocabulary(payload: Dict[str, Any]) -> Tuple[Set[str], Set[str]]:
    pages: Set[str] = set()
    paths: Set[str] = set()
    for key in ('entry_page', 'ui_page', 'capture_page'):
        if payload.get(key):
            pages.add(str(payload[key]))
    for pg in payload.get('ui_pages_from_callsite') or []:
        if pg.get('page'):
            pages.add(str(pg['page']))
    for nav in payload.get('inbound_nav') or []:
        if nav.get('from_page'):
            pages.add(str(nav['from_page']))
    for p in payload.get('capture_accept_paths') or payload.get('capture_paths') or []:
        paths.add(normalize_api_path(str(p)))
    if payload.get('entry_path'):
        paths.add(normalize_api_path(str(payload['entry_path'])))
    if payload.get('capture_path'):
        paths.add(normalize_api_path(str(payload['capture_path'])))
    app = payload.get('app_navigation') or {}
    for tab in app.get('tab_bar') or []:
        if tab.get('pagePath'):
            pages.add(str(tab['pagePath']).replace('.html', ''))
    if app.get('entry_page'):
        pages.add(str(app['entry_page']))
    return pages, paths


def _step_uses_only_allowed(text: str, allowed_pages: Set[str], allowed_paths: Set[str]) -> bool:
    low = text.lower()
    for pg in allowed_pages:
        if pg and pg.lower() in low:
            return True
    for path in allowed_paths:
        tail = path.rsplit('/', 1)[-1]
        if path.lower() in low or (tail and len(tail) > 3 and tail.lower() in low):
            return True
    safe_markers = ('抓包', 'charles', 'fiddler', 'mitmproxy', '登录', '微信', 'ssl', '导出', 'response', 'request', 'header', 'baseline')
    return any(m in low for m in safe_markers)


def _sanitize_enrichment_steps(
    item: Dict[str, Any],
    allowed_pages: Set[str],
    allowed_paths: Set[str],
    rule_guide: Dict[str, Any],
) -> Dict[str, Any]:
    out = dict(item)
    for field in ('navigation_steps', 'ui_steps'):
        steps = [str(s).strip() for s in (out.get(field) or []) if str(s).strip()]
        filtered = [s for s in steps if _step_uses_only_allowed(s, allowed_pages, allowed_paths)]
        if field == 'navigation_steps' and rule_guide.get('navigation_steps'):
            base = rule_guide['navigation_steps']
            out[field] = base if len(filtered) < 2 else filtered
        else:
            out[field] = filtered if filtered else (rule_guide.get(field) or rule_guide.get('ui_steps') or [])
    return out


def _validate_enrichment(
    item: Dict[str, Any],
    request_id: str,
    *,
    allowed_pages: Optional[Set[str]] = None,
    allowed_paths: Optional[Set[str]] = None,
    rule_guide: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    if item.get('request_id') != request_id:
        return None
    if allowed_pages is not None and allowed_paths is not None:
        item = _sanitize_enrichment_steps(item, allowed_pages, allowed_paths, rule_guide or {})
    ui_steps = [str(s).strip() for s in (item.get('ui_steps') or []) if str(s).strip()]
    if len(ui_steps) < 4:
        return None
    return {
        'request_id': request_id,
        'page_name_zh': (item.get('page_name_zh') or '').strip() or None,
        'one_line_task': (item.get('one_line_task') or '').strip() or None,
        'navigation_steps': [
            str(s).strip() for s in (item.get('navigation_steps') or []) if str(s).strip()
        ],
        'ui_steps': ui_steps,
    }


def enrich_guides_with_llm(
    pack_dir: Path,
    requests: List[Dict[str, Any]],
    chains_by_id: Dict[str, Dict[str, Any]],
    guides: List[Dict[str, Any]],
    *,
    use_llm: bool = True,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Apply LLM enrichment to rule-based guides; fallback silently on failure."""
    pack_dir = Path(pack_dir)
    meta: Dict[str, Any] = {
        'schema_version': '1.0.0',
        'generated_at': _utc_now(),
        'llm_status': 'skipped',
        'login_baseline_steps': None,
    }
    if not use_llm or not requests or not guides:
        return guides, meta

    payloads = []
    eligible_payloads = []
    guide_by_rid = {g.get('request_id'): g for g in guides}
    for req in requests[:8]:
        rid = req.get('request_id')
        chain = chains_by_id.get(req.get('chain_id') or '') or {}
        from minidrifter.business_chain.chain_hop_enrichment import resolve_entry_context
        entry_path = (req.get('example_paths') or [chain.get('entry_path') or ''])[0]
        entry_ctx = resolve_entry_context(pack_dir, entry_path, api_id=req.get('entry_api'))
        rule_guide = guide_by_rid.get(rid) or {}
        surface = rule_guide.get('capture_surface') or {}
        pld = _build_request_payload(pack_dir, req, chain, entry_ctx, rule_guide)
        pld['capture_surface'] = {
            'capture_role': surface.get('capture_role'),
            'capture_path': rule_guide.get('capture_path') or entry_path,
            'capture_accept_paths': (rule_guide.get('capture_filter') or {}).get('accept_paths'),
            'ui_page': surface.get('ui_page'),
            'llm_eligible': rule_guide.get('llm_eligible', surface.get('llm_eligible')),
            'navigation_steps': surface.get('navigation_steps'),
            'runtime_proxies': surface.get('runtime_proxies'),
            'inbound_nav': (surface.get('runtime_proxies') or [{}])[0].get('inbound_nav') if surface.get('runtime_proxies') else [],
        }
        from minidrifter.quality.runtime_reachability.llm_ui_guard import llm_eligible_for_steps
        pld['llm_eligible'] = llm_eligible_for_steps({
            'usable_for_capture': entry_ctx.get('usable_for_capture') or surface.get('llm_eligible'),
            'evidence': entry_ctx.get('entry_page_evidence') or surface.get('page_evidence'),
            'confidence': entry_ctx.get('entry_page_confidence') or surface.get('confidence', 0),
            'ui_reachability': entry_ctx.get('ui_reachability'),
            'capture_anchor_confirmed': bool(surface.get('runtime_proxies')),
        })
        payloads.append(pld)
        if pld['llm_eligible']:
            eligible_payloads.append(pld)

    if not eligible_payloads:
        meta['llm_status'] = 'skipped_ineligible'
        meta['skipped_reason'] = 'all_requests_have_sufficient_static_evidence_or_static_only'
        write_json(pack_dir / 'chain_intake_llm_enrichment.json', meta)
        return guides, meta

    user_payload = {
        'material_requests': eligible_payloads,
        'instruction': (
            '仅为 llm_eligible=true 的请求生成中文 UI 指引。'
            'navigation_steps 必须基于输入 navigation_steps / inbound_nav；'
            'ui_steps 抓包 API 必须匹配 capture_path。'
        ),
    }

    try:
        client = LLMClient()
        raw = client.chat_json(UI_GUIDE_SYSTEM, json.dumps(user_payload, ensure_ascii=False))
        doc = parse_json_from_llm(raw)
        meta['llm_status'] = 'ok'
        meta['model'] = client.config.get('model')
    except (LLMClientError, json.JSONDecodeError, KeyError, TypeError) as exc:
        meta['llm_status'] = 'failed'
        meta['error'] = str(exc)[:500]
        write_json(pack_dir / 'chain_intake_llm_enrichment.json', meta)
        return guides, meta

    login_steps = [
        str(s).strip() for s in (doc.get('login_baseline_steps') or []) if str(s).strip()
    ]
    if login_steps:
        meta['login_baseline_steps'] = login_steps

    enrich_by_id = {}
    payload_by_rid = {p['request_id']: p for p in eligible_payloads}
    for item in doc.get('enrichments') or []:
        rid = item.get('request_id')
        if not rid:
            continue
        pld = payload_by_rid.get(rid) or {}
        allowed_pages, allowed_paths = _allowed_vocabulary({
            **pld,
            **(pld.get('capture_surface') or {}),
        })
        validated = _validate_enrichment(
            item, rid,
            allowed_pages=allowed_pages,
            allowed_paths=allowed_paths,
            rule_guide=guide_by_rid.get(rid) or {},
        )
        if validated:
            enrich_by_id[rid] = validated

    meta['eligible_count'] = len(eligible_payloads)
    meta['total_requests'] = len(payloads)

    meta['enriched_count'] = len(enrich_by_id)
    meta['enrichments'] = list(enrich_by_id.values())
    write_json(pack_dir / 'chain_intake_llm_enrichment.json', meta)

    out: List[Dict[str, Any]] = []
    for guide in guides:
        g = dict(guide)
        enr = enrich_by_id.get(g.get('request_id') or '')
        if not enr:
            out.append(g)
            continue
        if g.get('capture_role') == 'ui_proxy':
            cap_path = normalize_api_path(g.get('capture_path') or '')
            entry_path = normalize_api_path(g.get('entry_path') or '')
            if cap_path and entry_path and cap_path != entry_path:
                out.append(g)
                continue
        if g.get('weak_evidence') or (g.get('capture_surface') or {}).get('weak_evidence'):
            g = dict(g)
            g['llm_enriched'] = False
            out.append(g)
            continue
        g['llm_enriched'] = True
        if enr.get('page_name_zh'):
            g['page_name'] = enr['page_name_zh']
            g['page_name_zh'] = enr['page_name_zh']
        if enr.get('one_line_task'):
            g['one_line_task'] = enr['one_line_task']
        if enr.get('navigation_steps'):
            g['navigation_steps'] = enr['navigation_steps']
        if enr.get('ui_steps'):
            g['ui_steps'] = enr['ui_steps']
        out.append(g)

    return out, meta


def apply_cached_llm_enrichment(
    guides: List[Dict[str, Any]],
    pack_dir: Path,
) -> List[Dict[str, Any]]:
    """Merge prior chain_intake_llm_enrichment.json into guides (no API call)."""
    pack_dir = Path(pack_dir)
    doc = _load_json(pack_dir / 'chain_intake_llm_enrichment.json') or {}
    if doc.get('llm_status') != 'ok':
        return guides
    enrich_by_id = {
        e['request_id']: e for e in (doc.get('enrichments') or []) if e.get('request_id')
    }
    if not enrich_by_id:
        return guides
    out: List[Dict[str, Any]] = []
    for guide in guides:
        g = dict(guide)
        enr = enrich_by_id.get(g.get('request_id') or '')
        if not enr:
            out.append(g)
            continue
        # Dual-plane ui_proxy: stale LLM may still target static entry_path — keep rule guide.
        if g.get('capture_role') == 'ui_proxy':
            cap_path = normalize_api_path(g.get('capture_path') or '')
            entry_path = normalize_api_path(g.get('entry_path') or '')
            if cap_path and entry_path and cap_path != entry_path:
                out.append(g)
                continue
        if g.get('weak_evidence') or (g.get('capture_surface') or {}).get('weak_evidence'):
            g = dict(g)
            g['llm_enriched'] = False
            out.append(g)
            continue
        g['llm_enriched'] = True
        if enr.get('page_name_zh'):
            g['page_name'] = enr['page_name_zh']
            g['page_name_zh'] = enr['page_name_zh']
        if enr.get('one_line_task'):
            g['one_line_task'] = enr['one_line_task']
        if enr.get('navigation_steps'):
            g['navigation_steps'] = enr['navigation_steps']
        if enr.get('ui_steps'):
            g['ui_steps'] = enr['ui_steps']
        out.append(g)
    return out


def render_llm_login_preamble(meta: Dict[str, Any]) -> Optional[List[str]]:
    """Optional LLM-refined login baseline section."""
    steps = meta.get('login_baseline_steps')
    if not steps:
        return None
    lines = [
        '**小程序内操作（LLM 细化）：**',
        '',
    ]
    for i, step in enumerate(steps, 1):
        lines.append(f'{i}. {step}')
    lines.append('')
    return lines
