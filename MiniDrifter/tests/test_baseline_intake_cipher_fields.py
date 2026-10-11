# -*- coding: utf-8 -*-
from minidrifter.materials.baseline_intake import analyze_capture, classify_value_layer


def test_classify_cipher_h5_body_field():
    layer = classify_value_layer(
        'cipherH5',
        'sOoh/fDC+Ujxe/2JWdZfXH2efZRZpi1oEyjcz9u3IZZBmjTc3oBxiRN5ufUJRe1z',
        location='body',
    )
    assert layer['layer'] == 'crypto_encrypted_body'


def test_analyze_capture_marks_cipher_transport_acceptable_partial():
    static_crypto = {
        'profile_id': 'aes_cfb_md5_header_query_wrapper',
        'available': True,
        'can_replay': False,
        'chain_available': True,
    }
    req = {
        'method': 'POST',
        'path': '/MiniPro/queryAccountInfoBaseCanal.json',
        'url': '/MiniPro/queryAccountInfoBaseCanal.json?_locale=zh_CN',
        'headers': {'host': 'yaoyao.cebbank.com', 'content-type': 'application/x-www-form-urlencoded'},
        'query': {'_locale': 'zh_CN'},
        'body_form': {
            'requestType': 'mini',
            'cipherH5': 'sOoh/fDC+Ujxe/2JWdZfXH2efZRZpi1oEyjcz9u3IZZBmjTc3oBxiRN5ufUJRe1z',
        },
    }
    cap = analyze_capture(req, capture_index=0, static_crypto=static_crypto)
    assert cap['overall_status'] == 'acceptable_plaintext_partial'
    assert cap['transport_assessment']['has_encrypted_body'] is True
