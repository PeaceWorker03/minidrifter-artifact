# -*- coding: utf-8 -*-
from pathlib import Path

from minidrifter.runtime.crypto.aes_cbc_cipherh5_form_wrapper import AesCbcCipherH5FormEngine
from minidrifter.runtime.crypto.profile_key_extract import (
    extract_appid_switch_key_map,
    extract_crypto_material,
)
from minidrifter.runtime.crypto.registry import _match_profile


YUNJIAOFEI_ROOT = Path(__file__).resolve().parents[2] / 'Workspace' / '云缴费'
BASE_INFO = (YUNJIAOFEI_ROOT / 'utils' / 'baseInfo.js').read_text(encoding='utf-8')
CONSTANTS = (YUNJIAOFEI_ROOT / 'utils' / 'constants.js').read_text(encoding='utf-8')
HTTP_JS = (YUNJIAOFEI_ROOT / 'utils' / 'http.js').read_text(encoding='utf-8')


def test_extract_appid_switch_keys_from_base_info():
    key_map = extract_appid_switch_key_map(
        BASE_INFO,
        field_patterns={
            'aes_key': [r'AK1\s*=\s*o\.enc\.Utf8\.parse\("([^"]+)"\)'],
            'aes_iv': [r'AI1\s*=\s*o\.enc\.Utf8\.parse\("([^"]+)"\)'],
            'base_url': [r'baseUrl\s*=\s*"([^"]+)"'],
        },
    )
    prod = key_map.get('wxe8a78f33c5f9b2ae') or {}
    assert prod.get('aes_key') == 'c680ada3e69b756d037ff447fa13ebe4'
    assert prod.get('aes_iv') == '8888777766665544'
    assert 'yaoyao.cebbank.com' in (prod.get('base_url') or '')


def test_extract_crypto_material_appid_switch_for_yunjiaofei():
    if not YUNJIAOFEI_ROOT.exists():
        return
    pack_dir = YUNJIAOFEI_ROOT / 'OUTPUT'
    mat = extract_crypto_material(
        'aes_cbc_cipherh5_form_wrapper',
        BASE_INFO,
        source_label='utils/baseInfo.js',
        source_dir=YUNJIAOFEI_ROOT,
        pack_dir=pack_dir if pack_dir.exists() else None,
        wrapper_file='utils/http.js',
    )
    assert mat is not None
    assert mat.replay_ready
    assert mat.aes_key == 'c680ada3e69b756d037ff447fa13ebe4'
    assert mat.extras.get('secret_one') == '87ee4b44ca6e49a29ec6af55ad1e4609'


def test_cipherh5_decrypt_roundtrip():
    mat = extract_crypto_material(
        'aes_cbc_cipherh5_form_wrapper',
        BASE_INFO,
        source_label='utils/baseInfo.js',
        source_dir=YUNJIAOFEI_ROOT,
        pack_dir=YUNJIAOFEI_ROOT / 'OUTPUT',
        wrapper_file='utils/http.js',
    )
    engine = AesCbcCipherH5FormEngine(mat)
    sample = (
        'sOoh/fDC+Ujxe/2JWdZfXH2efZRZpi1oEyjcz9u3IZZBmjTc3oBxiRN5ufUJRe1zBBOYkTiXaORAvapJODFCq2Sz5J7XRsx'
        '9c9fIvNiW+gNQ2zvrGDFiAtjoeDEMOj8p+RbjRmaaRuozsp34fwR5i36SAc3Kfjk96+IMC3ftcJCziLGrN9S56xsKw0SVt6ahpy'
        'qjmiKAu7gYQeWpUSYoFySQyK/oSy6JUPeBs36fSClQN1sKTs/dJLxY3ylas5k1yH/H7Xzo0od3CFgIIs8jTLIoOG6XjJNRWt0UDK/'
        'a/gVOksA8bGPnXgwzpXJRc9YcQw4GG7XmSLgQNxFBs9yXUzV5lYmacsDGyt7+jZH6hn0='
    )
    plain = engine.decrypt_cipher_h5(sample)
    assert 'accountType=' in plain


def test_parse_urlencoded_form_preserves_plus_in_cipher_blob():
    from minidrifter.materials.baseline_importer import parse_urlencoded_form
    body = 'requestType=mini&cipherH5=abc+def/ghi='
    parsed = parse_urlencoded_form(body)
    assert parsed['cipherH5'] == 'abc+def/ghi='


def test_http_wrapper_matches_cipherh5_profile():
    wrapper = {
        'file': 'utils/http.js',
        'calls_platform_request': True,
        'header_hints': [],
        'crypto_hints': ['AES', 'MD5', 'cipher', 'encrypt'],
        'evidence': {'snippet': HTTP_JS[:400]},
    }
    spec, score = _match_profile(wrapper, source_dir=YUNJIAOFEI_ROOT)
    assert spec is not None
    assert spec.profile_id == 'aes_cbc_cipherh5_form_wrapper'
    assert score >= 12.0
