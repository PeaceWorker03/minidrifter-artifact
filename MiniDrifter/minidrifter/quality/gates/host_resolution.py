# -*- coding: utf-8 -*-
"""Host resolution quality gates."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from minidrifter.quality.models import QualityReport, StaticIssue
from minidrifter.optimizers.url_utils import is_excluded_business_host
from minidrifter.quality.resolvers.url_role import is_third_party_sdk_host


def gate_host_resolution(pack_dir: Path, report: QualityReport) -> None:
    host_path = pack_dir / 'host_resolution.json'
    if not host_path.exists():
        return
    doc = json.loads(host_path.read_text(encoding='utf-8'))
    strategy = doc.get('host_resolution_strategy') or ''
    default = doc.get('default_business_host') or ''
    runtime_dyn = doc.get('runtime_dynamic_host')

    if default and (is_third_party_sdk_host(default) or is_excluded_business_host(default)):
        report.add(StaticIssue(
            code='HOST_DEFAULT_IS_NOISE',
            message=f'默认业务 host 为噪声/第三方: {default}',
            artifact='host_resolution.json',
            evidence={'default_business_host': default, 'strategy': strategy},
            severity='error',
        ))
        report.add(StaticIssue(
            code='HOST_RELATIVE_ASSIGNED_THIRD_PARTY',
            message=f'默认业务 host 为第三方 SDK: {default}',
            artifact='host_resolution.json',
            evidence={'default_business_host': default},
        ))

    if runtime_dyn and not doc.get('authoritative_business_host'):
        report.add(StaticIssue(
            code='HOST_RUNTIME_EXTCONFIG',
            message='检测到运行时动态域名（getServerUrl/extConfig），静态未解析具体 host',
            artifact='host_resolution.json',
            evidence={'strategy': strategy},
        ))

    if not default and strategy in {'unresolved', 'runtime_extconfig_pending'}:
        report.add(StaticIssue(
            code='HOST_UNRESOLVED_RELATIVE',
            message='相对业务路径无可用 default business host',
            artifact='host_resolution.json',
        ))

    if doc.get('authoritative_business_host'):
        report.add(StaticIssue(
            code='HOST_BASELINE_OVERRIDE',
            message=f"baseline Host 覆盖: {doc['authoritative_business_host']}",
            artifact='host_resolution.json',
            severity='info',
        ))


def gate_url_inventory(cards: List[Dict[str, Any]], report: QualityReport) -> None:
    third_in_business = 0
    relative_no_host = 0
    for card in cards:
        ep = (card.get('static') or {}).get('endpoint') or {}
        host = ep.get('host') or ''
        path = ep.get('path') or ep.get('original_url') or ''
        url_role = ep.get('url_role') or ''
        if url_role == 'business_relative' and not host:
            relative_no_host += 1
        if url_role == 'third_party_sdk' and (card.get('replay') or {}).get('readiness', {}).get('status') != 'not_applicable':
            third_in_business += 1
        elif is_third_party_sdk_host(host) and path and '.jhtml' in path:
            third_in_business += 1

    if third_in_business:
        report.add(StaticIssue(
            code='URL_THIRD_PARTY_IN_BUSINESS_POOL',
            message=f'{third_in_business} 个 API 仍为第三方 host 承载业务路径',
            artifact='api_cards.json',
            evidence={'count': third_in_business},
        ))
    if relative_no_host:
        report.summary['business_relative_without_host'] = relative_no_host
