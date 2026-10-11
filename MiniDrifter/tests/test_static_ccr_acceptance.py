# -*- coding: utf-8 -*-
"""Unit tests for host exclusion, frontend routes, and RCR construction."""
from __future__ import annotations

from minidrifter.rcr.construct import construct_ccr
from minidrifter.extractors.wrapper_url_resolver import _score_api_base_key
from minidrifter.optimizers.url_utils import (
    classify_url_type,
    is_excluded_business_host,
    is_frontend_route_path,
)
from minidrifter.quality.resolvers.host_pool import resolve_host_pools
from minidrifter.request_facts.builder import build_request_fact


def test_bare_url_key_not_high_score():
    assert _score_api_base_key('url') == 0.0
    assert _score_api_base_key('requestUrl') >= 10.0
    assert _score_api_base_key('baseUrl') >= 10.0


def test_noise_host_excluded():
    assert is_excluded_business_host('https://mp.weixin.qq.com')
    assert is_excluded_business_host('mp.weixin.qq.com')
    assert not is_excluded_business_host('https://api.wkzuche.com')


def test_frontend_route_detection():
    assert is_frontend_route_path('/sub-packages/order/list')
    assert is_frontend_route_path('/pages/index/index')
    assert classify_url_type('/sub-packages/foo/bar')['url_type'] == 'frontend_route'
    assert classify_url_type('/sub-packages/foo/bar')['is_business_api'] is False


def test_host_pool_prefers_business_over_noise_api_base():
    inventory = [
        {
            'raw_url': 'https://api.example-biz.com/action/list',
            'url_classification': {'is_business_api': True, 'url_type': 'business_backend_api'},
        },
        {
            'raw_url': 'https://mp.weixin.qq.com/s/abcd',
            'url_classification': {'is_business_api': False, 'url_type': 'third_party_or_telemetry'},
        },
    ]
    # Even if a noisy url were passed as api_base, it must not win.
    pooled = resolve_host_pools(
        inventory,
        api_base_hosts=[{'key': 'url', 'url': 'https://mp.weixin.qq.com', 'score': 12.0}],
    )
    default = (pooled.get('default_business_host') or '').lower()
    assert 'mp.weixin' not in default
    assert 'example-biz' in default or 'api.example' in default


def test_request_fact_and_ccr_shape():
    op = {
        'operation_id': 'op_test',
        'method': 'POST',
        'method_source': 'explicit_or_extractor',
        'method_confidence': 0.95,
        'endpoint': {
            'host': 'https://api.example.com',
            'path': '/order/detail',
            'endpoint_key': 'api.example.com|/order/detail',
            'url_role': 'business_explicit',
        },
        'param_schema': ['token', 'orderId'],
        'header_schema': [],
        'supporting_sources': [{'file': 'a.js', 'line': 10, 'snippet': 'getStorageSync("token"); orderId'}],
        'supporting_callsites': [],
        'surface_types': {'callsite': 1},
        'support_count': 1,
        'url_classification': {'is_business_api': True, 'url_type': 'business_backend_api'},
        'host_resolution': {},
    }
    fact = build_request_fact(op, crypto_cards=[], wrappers=[], events=[])
    assert fact['method']['value'] == 'POST'
    assert 'token' in fact['provenance']
    RCR = construct_rcr(fact)
    assert RCR['operation_id'] == 'op_test'
    assert 'orderId' in (RCR.get('binding_credentials') or RCR.get('request_semantics', {}).get('credentials') or [])
    assert RCR['notes']['claims_backend_rho'] is False
