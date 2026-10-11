# -*- coding: utf-8
from pathlib import Path

from minidrifter.orchestration.frontier_scheduler import (
    build_campaign_frontier_plan,
    chain_dedupe_key,
    primary_object_anchor,
)


def test_chain_dedupe_key_distinguishes_producer_domain():
    a = {
        'target_path': '/order/detail',
        'entry_path': '/order/list',
        'binding_fields': ['orderId'],
        'chain_source': 'runtime_object_flow',
        'domain': 'order',
    }
    b = {
        'target_path': '/order/detail',
        'entry_path': '/city/list',
        'binding_fields': ['cityId'],
        'chain_source': 'runtime_object_flow',
        'domain': 'city',
    }
    assert chain_dedupe_key(a) != chain_dedupe_key(b)
    assert primary_object_anchor(a) == 'orderId'
    assert primary_object_anchor(b) == 'cityId'


def test_frontier_plan_selects_from_pack(tmp_path):
    pack = Path(r'd:\Work\NKU\MiniDrifter\Workspace\神州租车\OUTPUT')
    if not (pack / 'coverage_frontier.json').exists():
        return
    plan = build_campaign_frontier_plan(pack, max_chains=40)
    assert plan['candidate_chains'] >= 0
    selected = plan.get('selected_chains') or []
    assert len(selected) <= 40
    if selected:
        assert selected[0].get('priority') is not None
        assert selected[0].get('object_anchor')
