# -*- coding: utf-8 -*-
"""Generate baseline_material_template.json for user collection."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from minidrifter.materials.material_units import MATERIAL_UNITS, NEVER_REQUEST_STAGE1

SCHEMA_VERSION = '1.0.0'


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _domains_for_material(
    material_id: str,
    field_requirements: Dict[str, Any],
    material_rec: Dict[str, Any],
) -> List[str]:
    domains: Set[str] = set()
    for fname in material_rec.get('covered_fields') or []:
        st = field_requirements.get(fname) or {}
        domains.update(st.get('domains') or [])
    unit = MATERIAL_UNITS.get(material_id) or {}
    if unit.get('domain'):
        domains.add(unit['domain'])
    return sorted(domains)[:12]


def _why_needed(material_id: str, material_rec: Dict[str, Any]) -> str:
    defaults = {
        'authenticated_request_sample': (
            '该小程序 wrapper 统一注入认证与签名头，完整请求样本比手工填写字段更可靠。'
        ),
        'login_or_user_profile_response': (
            '多数组件从 globalData.User.UserId 读取当前账户主体。'
        ),
        'openid_flow_sample': (
            '部分微信身份相关接口需要 OpenId，但不一定适合第一阶段自动执行。'
        ),
        'first_hop_response_device_list': (
            '设备对象属于一跳可获得对象，适合作为第一阶段单点验证入口。'
        ),
        'first_hop_response_order_list': (
            'OrderId 属于业务流程对象，应由订单列表自动发现，不应第一阶段手工提供。'
        ),
    }
    return defaults.get(material_id) or material_rec.get('user_instruction') or ''


def _stage1_target_preview(
    acquisition_plan: Dict[str, Any],
    material_requirements: Dict[str, Any],
    erd_by_id: Dict[str, Dict[str, Any]],
    *,
    limit: int = 25,
) -> List[Dict[str, Any]]:
    preview = []
    for brief in (acquisition_plan.get('stage_1_target_apis') or [])[:limit]:
        cid = brief.get('card_id')
        sk = (erd_by_id.get(cid) or {}).get('runtime_requirement_skeleton') or {}
        mats: Set[str] = set()
        for f in sk.get('required_fields') or []:
            mats.update(f.get('material_candidates') or [])
        preview.append({
            'api_id': cid,
            'path': brief.get('path') or sk.get('path'),
            'method': brief.get('method') or sk.get('method'),
            'required_materials': sorted(mats),
            'runtime_sublevel': sk.get('runtime_sublevel'),
            'side_effect_level': sk.get('side_effect_level'),
        })
    return preview


def generate_baseline_material_template(
    material_requirements: Dict[str, Any],
    acquisition_plan: Dict[str, Any],
    domain_tree: Optional[Dict[str, Any]] = None,
    demand_graph: Optional[Dict[str, Any]] = None,
    erd_items: Optional[List[Dict[str, Any]]] = None,
    manifest: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    packs = material_requirements.get('material_packages') or {}
    field_reqs = material_requirements.get('field_requirements') or {}
    erd_by_id = {i['card_id']: i for i in (erd_items or [])}

    def _enrich_bucket(bucket_key: str, out_key: str) -> List[Dict[str, Any]]:
        out = []
        for rec in packs.get(bucket_key) or []:
            mid = rec['material_id']
            unit = MATERIAL_UNITS.get(mid) or {}
            entry = {
                'material_id': mid,
                'priority': bucket_key if bucket_key != 'recommended' else 'recommended',
                'user_instruction': rec.get('user_instruction') or unit.get('user_instruction', ''),
                'accepted_formats': rec.get('accepted_formats') or unit.get('accepted_formats', []),
                'covers_fields': rec.get('covered_fields') or unit.get('covers_fields', []),
                'unlocks_api_count': rec.get('covered_api_count', 0),
                'unlocks_domains': _domains_for_material(mid, field_reqs, rec),
                'material_score': rec.get('score'),
            }
            if bucket_key == 'required':
                entry['why_needed'] = _why_needed(mid, rec)
            if bucket_key == 'deferred':
                entry['why_deferred'] = _why_needed(mid, rec)
            out.append(entry)
        return out

    app_label = (manifest or {}).get('project_context', {}).get('app_label') or 'miniapp'
    template_id = f"{app_label}_stage1_baseline_template"

    graph_summary = {}
    if demand_graph:
        graph_summary = {
            'edge_counts': demand_graph.get('edge_counts'),
            'produces_count': demand_graph.get('produces_count'),
            'field_node_count': len(demand_graph.get('field_nodes') or []),
        }

    return {
        'schema_version': SCHEMA_VERSION,
        'template_id': template_id,
        'miniapp': app_label,
        'pack_id': material_requirements.get('pack_id') or acquisition_plan.get('pack_id'),
        'phase': 'pre_baseline',
        'goal': 'materialize N1 runtime templates for first-stage replay',
        'generated_at': _utc_now(),
        'required_materials': _enrich_bucket('required', 'required'),
        'recommended_materials': _enrich_bucket('recommended', 'recommended'),
        'deferred_materials': _enrich_bucket('deferred', 'deferred'),
        'never_request_in_stage1': list(NEVER_REQUEST_STAGE1),
        'stage_1_target_preview': _stage1_target_preview(
            acquisition_plan, material_requirements, erd_by_id,
        ),
        'domain_tree_summary': {
            'known_domain_percent': (domain_tree or {}).get('known_domain_percent'),
            'domain_distribution': (domain_tree or {}).get('domain_distribution'),
        },
        'demand_graph_summary': graph_summary,
        'material_summary': material_requirements.get('summary'),
        'user_collection_brief': _build_user_brief(packs, app_label),
    }


def _build_user_brief(packs: Dict[str, List[Dict[str, Any]]], app_label: str = 'miniapp') -> List[str]:
    label = app_label or 'miniapp'
    lines = [f'{label} Stage-1 材料采集概要：']
    n = 1
    for rec in packs.get('required') or []:
        lines.append(f"{n}. [必填] {rec.get('user_instruction') or rec['material_id']}")
        n += 1
    for rec in packs.get('recommended') or []:
        lines.append(f"{n}. [推荐] {rec.get('user_instruction') or rec['material_id']}")
        n += 1
    lines.append('暂不要求用户手填：' + '、'.join(NEVER_REQUEST_STAGE1[:6]) + ' 等深层业务 ID。')
    return lines
