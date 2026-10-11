# -*- coding: utf-8 -*-
"""Chain graph quality gates."""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List

from minidrifter.quality.models import QualityReport, StaticIssue
from minidrifter.quality.resolvers.url_role import is_third_party_sdk_url


def gate_chain_artifacts(pack_dir: Path, report: QualityReport) -> None:
    rank_path = pack_dir / 'chain_rank_plan.json'
    chains_path = pack_dir / 'business_chains.json'
    trans_path = pack_dir / 'business_api_transitions.json'
    if not rank_path.exists():
        return

    rank = json.loads(rank_path.read_text(encoding='utf-8'))
    top = (rank.get('top_chains') or [{}])[0]
    entry = top.get('entry_path') or ''
    if entry and is_third_party_sdk_url(entry):
        report.add(StaticIssue(
            code='CHAIN_THIRD_PARTY_ENTRY',
            message=f'Top1 链入口为第三方 SDK: {entry}',
            artifact='chain_rank_plan.json',
            evidence={'chain_id': top.get('chain_id'), 'score': top.get('score')},
        ))

    if chains_path.exists():
        chains = json.loads(chains_path.read_text(encoding='utf-8'))
        ch_list = chains.get('chains') or []
        no_page = sum(1 for c in ch_list if not c.get('entry_page'))
        p3_hits = sum(1 for c in ch_list if (c.get('entry_page_evidence') or '').startswith('chunk_')
                       or c.get('entry_page_evidence') in {
                           'offset_local_snippet', 'registry_callsite_source',
                           'demand_graph_callsite_soft', 'chunk_require_backtrace', 'chunk_id_backtrace',
                       })
        if p3_hits:
            report.summary['callsite_backtrace_hits'] = p3_hits
            report.add(StaticIssue(
                code='CALLSITE_BACKTRACE_APPLIED',
                message=f'P3 callsite 回溯解析 {p3_hits} 条链入口页面',
                artifact='business_chains.json',
                severity='info',
            ))
        if ch_list and no_page == len(ch_list):
            report.add(StaticIssue(
                code='CHAIN_NO_PAGE_EVIDENCE',
                message=f'全部 {len(ch_list)} 条链无 entry_page 证据',
                artifact='business_chains.json',
            ))
        entries = Counter(c.get('entry_api') or c.get('entry_path') for c in ch_list)
        if ch_list:
            top_entry, top_n = entries.most_common(1)[0]
            if top_n / len(ch_list) > 0.5:
                report.add(StaticIssue(
                    code='CHAIN_ENTRY_OVER_CONVERGED',
                    message=f'入口过度收敛: {top_entry} 占 {top_n}/{len(ch_list)}',
                    artifact='business_chains.json',
                    evidence={'entry': top_entry, 'share': round(top_n / len(ch_list), 3)},
                ))

    if trans_path.exists():
        trans = json.loads(trans_path.read_text(encoding='utf-8'))
        pruned = (trans.get('prune_stats') or {}).get('rejected_count', 0)
        if pruned:
            report.summary['transitions_pruned'] = pruned
