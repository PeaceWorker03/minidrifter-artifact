# -*- coding: utf-8 -*-
"""N1 eligibility gate: prune when ciphertext arrives without static crypto chain."""
from __future__ import annotations

from typing import Any, Dict, List

from minidrifter.runtime.crypto_replay import is_ciphertext_blob


def _plaintext_replay_usable(capture: Dict[str, Any]) -> bool:
    transport = capture.get('transport_assessment') or {}
    if transport.get('token_present'):
        return True
    if transport.get('replay_mode') == 'plaintext_only_fallback':
        return True
    plain_layers = {'plaintext_auth_token', 'plaintext_metadata', 'plaintext_param', 'plaintext_json'}
    return any((l.get('layer') or '') in plain_layers for l in (capture.get('field_layers') or []))


def evaluate_capture_n1_gate(
    capture: Dict[str, Any],
    crypto_capability: Dict[str, Any],
) -> Dict[str, Any]:
    layers = capture.get('field_layers') or []
    has_ciphertext = any(is_ciphertext_blob(l.get('layer', '')) for l in layers)
    chain = bool(crypto_capability.get('chain_available'))
    can_replay = bool(crypto_capability.get('can_replay'))
    crypto_proc = capture.get('crypto_processing') or {}
    decrypt_ok = not crypto_proc.get('errors')
    plaintext_ok = _plaintext_replay_usable(capture)

    if has_ciphertext and not chain:
        if plaintext_ok:
            return {
                'n1_eligible': True,
                'gate': 'open_plaintext_fallback',
                'reason': '密文 transport 但抓包含可用明文字段，降级为明文 replay',
                'next_action': 'import_plaintext_fields_only',
            }
        return {
            'n1_eligible': False,
            'gate': 'pruned_ciphertext_no_chain',
            'reason': '密文输入但静态未提取到加解密链，N1 减枝',
            'next_action': 'blocked_until_crypto_chain_or_plaintext_material',
        }
    if has_ciphertext and chain and not can_replay:
        if plaintext_ok:
            return {
                'n1_eligible': True,
                'gate': 'open_plaintext_fallback',
                'reason': '静态有加密链但密钥未解析；使用明文 session 字段继续',
                'next_action': 'import_plaintext_fields_only',
            }
        return {
            'n1_eligible': False,
            'gate': 'pruned_ciphertext_keys_unresolved',
            'reason': '有加密链索引但密钥/Profile 未就绪，N1 减枝',
            'next_action': 'provide_source_dir_or_node_bridge',
        }
    if has_ciphertext and can_replay and not decrypt_ok:
        return {
            'n1_eligible': False,
            'gate': 'pruned_ciphertext_decrypt_failed',
            'reason': '解密失败，N1 减枝',
            'next_action': 'fix_capture_or_crypto_profile',
        }
    if has_ciphertext and can_replay:
        auth = crypto_proc.get('authorization_check') or {}
        return {
            'n1_eligible': True,
            'gate': 'open_with_crypto',
            'reason': '密文已解密且可 parametric replay',
            'next_action': 'import_decrypted_context_and_replay',
            'authorization_verified': auth.get('verified'),
        }
    return {
        'n1_eligible': True,
        'gate': 'open_plaintext',
        'reason': '明文 transport，直接进入 materialize/replay',
        'next_action': 'import_as_authenticated_sample_and_materialize',
    }


def summarize_n1_gate(captures: List[Dict[str, Any]]) -> Dict[str, Any]:
    eligible = [c for c in captures if (c.get('n1_gate') or {}).get('n1_eligible')]
    pruned = [c for c in captures if not (c.get('n1_gate') or {}).get('n1_eligible')]
    gates = {}
    for c in captures:
        g = (c.get('n1_gate') or {}).get('gate', 'unknown')
        gates[g] = gates.get(g, 0) + 1
    overall = 'open' if eligible else 'pruned_all'
    if eligible and pruned:
        overall = 'partial'
    return {
        'overall': overall,
        'eligible_capture_count': len(eligible),
        'pruned_capture_count': len(pruned),
        'gate_histogram': gates,
        'n1_materialize_allowed': bool(eligible),
    }
