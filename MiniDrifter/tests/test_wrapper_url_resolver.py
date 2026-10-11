# -*- coding: utf-8 -*-
from minidrifter.extractors.wrapper_url_resolver import (
    apply_wrapper_url_resolution,
    extract_api_base_urls,
    extract_relative_api_path,
    join_base_and_path,
    resolve_wrapper_relative_url,
)


def test_extract_relative_path_from_url_expr():
    expr = '{\n    url: "admin/m/customer/getCustomerInfoWx" + t.jointParams(r, 0),\n    method: "GET"\n  }'
    assert extract_relative_api_path(expr) == 'admin/m/customer/getCustomerInfoWx'


def test_extract_api_base_urls_prefers_request_url():
    registry = {
        'entries': {
            'requestUrl': {'resolved_url': 'https://center.hengdianfilm.com'},
            'imgUrl': {'resolved_url': 'https://obsziying.hengdianfilm.com/hdFiles/'},
        },
        'host_constants': {},
    }
    bases = extract_api_base_urls(registry)
    assert bases
    assert bases[0]['key'] == 'requestUrl'
    assert bases[0]['url'] == 'https://center.hengdianfilm.com'


def test_resolve_wrapper_relative_url():
    bases = [{'key': 'requestUrl', 'url': 'https://center.hengdianfilm.com', 'score': 12.0}]
    expr = 'url: "order/order/getUserOrderList"'
    full, meta = resolve_wrapper_relative_url(url_expr=expr, snippet='', api_bases=bases)
    assert full == 'https://center.hengdianfilm.com/order/order/getUserOrderList'
    assert meta['strategy'] == 'wrapper_base_concat'


def test_apply_wrapper_url_resolution_promotes_dynamic():
    registry = {
        'entries': {'requestUrl': {'resolved_url': 'https://api.example.com'}},
        'host_constants': {},
    }
    api_call_res = {
        'api_call_sites': [],
        'dynamic_api_candidates': [{
            'api_call_id': 'call_test',
            'callee': 'e.myRequest',
            'method': 'GET',
            'url_expr': 'url: "cinema/mobile/movieInfo"',
            'dynamic_url': True,
            'source': {'file': 'api/filmInfo.js', 'snippet': 'myRequest({ url: "cinema/mobile/movieInfo"' },
        }],
    }
    out = apply_wrapper_url_resolution(api_call_res, registry)
    assert out['wrapper_url_promoted_count'] == 1
    assert len(out['api_call_sites']) == 1
    assert out['api_call_sites'][0]['resolved_url'] == 'https://api.example.com/cinema/mobile/movieInfo'
    assert out['dynamic_api_candidates'] == []


def test_join_base_and_path():
    assert join_base_and_path('https://host.com/', '/admin/foo') == 'https://host.com/admin/foo'
