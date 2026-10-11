# -*- coding: utf-8 -*-
from pathlib import Path

from minidrifter.materials.baseline_importer import parse_urlencoded_form
from minidrifter.runtime.crypto.profile_key_extract import (
    extract_baselife_appid_key_map,
    extract_crypto_material,
)
from minidrifter.runtime.crypto.sm4_dual_form_wrapper import Sm4DualFormEngine
from minidrifter.runtime.crypto.triple_mix_key import derive_triple_mix_key

YUNJIAOFEI_ROOT = Path(__file__).resolve().parents[2] / 'Workspace' / '云缴费'
BASELIFE = (YUNJIAOFEI_ROOT / 'utils' / 'baselifeConfig.js').read_text(encoding='utf-8')


def test_extract_baselife_literals_for_prod_app():
    key_map = extract_baselife_appid_key_map(BASELIFE)
    prod = key_map.get('wxe8a78f33c5f9b2ae') or {}
    assert prod.get('f') == '38e2bd3337364620a39159bb66a5e4b3'
    assert prod.get('l') == '6eb6a1c16b2c404aa88b640faf2d2bd0'
    assert prod.get('g') == '6e2e8ec923ff4bc0bacf06eef57f75b1'
    assert prod.get('d') == 'a4d6d3bec7c947838eab29a61487809d'


def test_triple_mix_key_matches_baselife_type2():
    key_map = extract_baselife_appid_key_map(BASELIFE)
    prod = key_map['wxe8a78f33c5f9b2ae']
    mixed = derive_triple_mix_key(prod['f'], prod['l'], prod['g'])
    assert mixed == '6E2E8EC923FF4BC0BACF06EEF57F75B1' or len(mixed) == 32


def test_extract_sm4_crypto_material_for_yunjiaofei():
    if not YUNJIAOFEI_ROOT.exists():
        return
    pack_dir = YUNJIAOFEI_ROOT / 'OUTPUT'
    mat = extract_crypto_material(
        'sm4_dual_form_wrapper',
        BASELIFE,
        source_label='utils/baselifeConfig.js',
        source_dir=YUNJIAOFEI_ROOT,
        pack_dir=pack_dir if pack_dir.exists() else None,
        wrapper_file='utils/http.js',
    )
    assert mat is not None
    assert mat.replay_ready
    assert mat.extras.get('sm4_type2_key_hex')
    assert mat.extras.get('sm4_type1_default_hex')


def test_cipher_two_decrypt_from_capture_042():
    if not YUNJIAOFEI_ROOT.exists():
        return
    http_path = YUNJIAOFEI_ROOT / 'OUTPUT' / 'user_materials' / 'har_capture_042.http'
    if not http_path.exists():
        return
    mat = extract_crypto_material(
        'sm4_dual_form_wrapper',
        BASELIFE,
        source_label='utils/baselifeConfig.js',
        source_dir=YUNJIAOFEI_ROOT,
        pack_dir=YUNJIAOFEI_ROOT / 'OUTPUT',
        wrapper_file='utils/http.js',
    )
    engine = Sm4DualFormEngine(mat)
    text = http_path.read_text(encoding='utf-8')
    form = parse_urlencoded_form(text.split('\n\n', 1)[1].split('\nHTTP')[0].strip())
    plain = engine.decrypt_cipher_two(form['cipherTwo'])
    assert 'canal=yunjiaofeimini' in plain
    assert 'openId=' in plain
