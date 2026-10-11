# -*- coding: utf-8 -*-
"""Baseline material intake: validate, classify plaintext/crypto, decrypt when chain available.

Authority: rules decide transport/crypto gates, N1 prune, and next_action.
Crypto engine decrypts when static profile resolves; LLM optional for ambiguous mapping only.
"""
from __future__ import annotations

import json
import math
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import unquote, urlparse

from minidrifter.materials.baseline_importer import parse_raw_http
from minidrifter.materials.material_units import MATERIAL_UNITS, NEVER_REQUEST_STAGE1
from minidrifter.runtime.crypto_profile import load_crypto_capability, normalize_profile_id
from minidrifter.runtime.crypto_replay import is_ciphertext_blob, process_request_crypto, process_response_result
from minidrifter.runtime.n1_gate import evaluate_capture_n1_gate, summarize_n1_gate

SCHEMA_VERSION = '1.0.0'

HEX32_RE = re.compile(r'^[0-9a-fA-F]{32}$')
UUID_LIKE_RE = re.compile(r'^[0-9a-fA-F-]{16,64}$')
REQUEST_SPLIT_RE = re.compile(r'(?=^(?:GET|POST|PUT|PATCH|DELETE)\s+)', re.M | re.I)

PATH_MATERIAL_HINTS: List[Tuple[re.Pattern[str], str, str]] = [
    (re.compile(r'/Device/List|/devices?/list|device/list', re.I), 'first_hop_response_device_list', 'device_list_baseline'),
    (re.compile(r'/User/(Base/)?CacheInfo|/User/Profile|/CardInfo|personalData|getUserInfo|user/info|account/profile', re.I),
     'login_or_user_profile_response', 'user_cache_profile'),
    (re.compile(r'/Federated/Login|/MiniProgram/OpenId|/Login/Code|wx\.login|/login', re.I), 'openid_flow_sample', 'login_bootstrap'),
    (re.compile(r'/Orders?/List|/order/list|/invoice/list', re.I), 'first_hop_response_order_list', 'order_list_auto_discovery'),
]

CRYPTO_QUERY_RE = re.compile(r'[%\$]|%24|[A-Za-z0-9+/]{40,}={0,2}\*?$')
CIPHER_FIELD_RE = re.compile(r'^(cipher\w*|code\d+)$', re.I)
CRYPTO_BLOB_RE = re.compile(r'^[A-Za-z0-9+/]{40,}={0,2}$')


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _normalize_headers(headers: Dict[str, str]) -> Dict[str, str]:
    out = {}
    for k, v in headers.items():
        out[k.lower()] = v
    return out


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def classify_value_layer(name: str, value: str, *, location: str = 'header') -> Dict[str, Any]:
    """Rule-based plaintext vs crypto_derived vs encrypted_blob."""
    if not value or not str(value).strip():
        return {
            'layer': 'missing',
            'confidence': 0.95,
            'rule_evidence': ['empty_value'],
            'replay_use': 'missing',
        }

    val = str(value).strip()
    low = name.lower()

    if low in {'appversion', 'appplatform', 'host', 'content-type', 'user-agent', 'accept', 'referer'}:
        return {
            'layer': 'plaintext_metadata',
            'confidence': 0.95,
            'rule_evidence': ['known_plaintext_header'],
            'replay_use': 'copy_as_is',
        }

    if low == 'token':
        if UUID_LIKE_RE.match(val):
            return {
                'layer': 'plaintext_auth_token',
                'confidence': 0.9,
                'rule_evidence': ['token_uuid_like'],
                'replay_use': 'copy_for_replay',
            }
        return {
            'layer': 'unknown',
            'confidence': 0.5,
            'rule_evidence': ['token_nonstandard_format'],
            'replay_use': 'review',
        }

    if low == 'authorization':
        if HEX32_RE.match(val):
            return {
                'layer': 'crypto_signature',
                'confidence': 0.88,
                'rule_evidence': ['authorization_32hex_md5_like'],
                'replay_use': 'requires_crypto_recompute_or_capture_pair',
            }
        return {
            'layer': 'crypto_derived',
            'confidence': 0.7,
            'rule_evidence': ['authorization_non_hex'],
            'replay_use': 'requires_crypto_recompute_or_capture_pair',
        }

    if low == 'sign' and val.isdigit() and len(val) >= 20:
        return {
            'layer': 'crypto_signature',
            'confidence': 0.85,
            'rule_evidence': ['sign_numeric_signature'],
            'replay_use': 'requires_crypto_recompute_or_capture_pair',
        }

    if low in {'uid', 'cid'}:
        return {
            'layer': 'plaintext_auth_token' if low == 'uid' else 'plaintext_param',
            'confidence': 0.88,
            'rule_evidence': [f'form_body_transport_{low}'],
            'replay_use': 'copy_for_replay',
        }

    if low == 'q' and len(val) > 40:
        return {
            'layer': 'crypto_encrypted_query',
            'confidence': 0.9,
            'rule_evidence': ['form_body_encrypted_q_blob'],
            'replay_use': 'do_not_hand_edit_replay_via_wrapper',
        }

    if low == 'appletencrypt':
        return {
            'layer': 'plaintext_metadata',
            'confidence': 0.95,
            'rule_evidence': ['applet_encrypt_mode_flag'],
            'replay_use': 'copy_as_is',
        }

    if low == 'appidentity':
        ent = _shannon_entropy(unquote(val))
        if len(val) > 80 or ent > 4.5 or '$' in val or '%24' in val:
            return {
                'layer': 'crypto_encrypted_header',
                'confidence': 0.9,
                'rule_evidence': ['appidentity_high_entropy_or_encoded_blob'],
                'replay_use': 'requires_crypto_chain_from_static_or_node_bridge',
            }
        return {
            'layer': 'crypto_derived',
            'confidence': 0.65,
            'rule_evidence': ['appidentity_short'],
            'replay_use': 'review',
        }

    if location == 'query':
        if CRYPTO_QUERY_RE.search(val) or _shannon_entropy(unquote(val)) > 4.2:
            return {
                'layer': 'crypto_encrypted_query',
                'confidence': 0.88,
                'rule_evidence': ['query_blob_high_entropy'],
                'replay_use': 'do_not_hand_edit_replay_via_wrapper',
            }
        if val.isdigit() or re.match(r'^[\w.-]+$', val):
            return {
                'layer': 'plaintext_param',
                'confidence': 0.85,
                'rule_evidence': ['query_simple_literal'],
                'replay_use': 'copy_for_replay',
            }

    if location == 'body' and (val.startswith('{') or val.startswith('[')):
        return {
            'layer': 'plaintext_json',
            'confidence': 0.9,
            'rule_evidence': ['json_body'],
            'replay_use': 'copy_for_replay',
        }

    if location == 'body' and CIPHER_FIELD_RE.match(low):
        if CRYPTO_BLOB_RE.match(val) or _shannon_entropy(val) > 4.0:
            return {
                'layer': 'crypto_encrypted_body',
                'confidence': 0.92,
                'rule_evidence': ['form_body_cipher_field_high_entropy'],
                'replay_use': 'do_not_hand_edit_replay_via_wrapper',
            }

    return {
        'layer': 'unknown',
        'confidence': 0.45,
        'rule_evidence': ['no_rule_match'],
        'replay_use': 'review',
    }


def split_multi_raw_http(text: str) -> List[str]:
    chunks = [c.strip() for c in REQUEST_SPLIT_RE.split(text.replace('\r\n', '\n')) if c.strip()]
    if not chunks:
        chunks = [text.strip()]
    return chunks


def extract_response_json_from_chunk(chunk: str) -> Optional[Any]:
    """Parse JSON response body from a raw HTTP capture chunk (req + optional resp)."""
    text = chunk.replace('\r\n', '\n')
    m = re.search(r'\nHTTP/\d(?:\.\d)?\s+\d+', text, re.I)
    if not m:
        return None
    resp_part = text[m.start() + 1:]
    sep = resp_part.find('\n\n')
    if sep < 0:
        return None
    body = resp_part[sep + 2:].strip()
    if not body:
        return None
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        return None


def _response_preview(body_json: Any, *, limit: int = 4000) -> str:
    try:
        text = json.dumps(body_json, ensure_ascii=False)
    except (TypeError, ValueError):
        text = str(body_json)
    return text[:limit] if len(text) > limit else text


def infer_material_candidates(path: str, headers: Dict[str, str]) -> List[str]:
    cands = ['authenticated_request_sample']
    for pat, mid, _ in PATH_MATERIAL_HINTS:
        if pat.search(path):
            cands.append(mid)
    norm = _normalize_headers(headers)
    if not norm.get('token') and re.search(r'login|federated|openid', path, re.I):
        cands = ['openid_flow_sample'] + cands
    if re.search(r'cacheinfo|cardinfo|profile|byuserid', path, re.I):
        if 'login_or_user_profile_response' not in cands:
            cands.append('login_or_user_profile_response')
    return list(dict.fromkeys(cands))


def _load_static_crypto_evidence(output_dir: Path, *, source_dir: Optional[Path] = None) -> Dict[str, Any]:
    cap = load_crypto_capability(output_dir, source_dir=source_dir)
    base = cap.to_dict()
    base['profile_id'] = normalize_profile_id(base.get('profile_id'))
    base['available'] = cap.chain_available
    return base


def analyze_capture(
    req: Dict[str, Any],
    *,
    capture_index: int,
    static_crypto: Dict[str, Any],
    crypto_capability: Any = None,
    output_dir: Optional[Path] = None,
    source_dir: Optional[Path] = None,
    response_body: Optional[Any] = None,
    session_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    path = req.get('path') or ''
    headers = req.get('headers') or {}
    norm = _normalize_headers(headers)
    query = req.get('query') or {}

    field_layers = []
    for hk, hv in norm.items():
        if hk in {'connection', 'accept-encoding', 'accept-language', 'sec-fetch-site', 'sec-fetch-mode',
                  'sec-fetch-dest', 'priority', 'xweb_xhr', 'remark'}:
            continue
        field_layers.append({
            'name': hk,
            'location': 'header',
            **classify_value_layer(hk, hv, location='header'),
        })

    for qk, qv in query.items():
        field_layers.append({
            'name': qk or '(raw_query_blob)',
            'location': 'query',
            **classify_value_layer(qk or 'query', str(qv), location='query'),
        })

    if not query and '?' in (req.get('url') or ''):
        raw_q = (req.get('url') or '').split('?', 1)[-1]
        field_layers.append({
            'name': '(raw_query_blob)',
            'location': 'query',
            **classify_value_layer('query', raw_q, location='query'),
        })

    body_form = req.get('body_form') or {}
    for bk, bv in body_form.items():
        field_layers.append({
            'name': bk,
            'location': 'body',
            **classify_value_layer(bk, str(bv), location='body'),
        })

    crypto_layers = {
        l['layer'] for l in field_layers
        if l['layer'].startswith('crypto_')
    }
    has_encrypted_transport = bool(
        crypto_layers & {
            'crypto_encrypted_query', 'crypto_encrypted_body',
            'crypto_encrypted_header', 'crypto_signature',
        }
    )

    material_candidates = infer_material_candidates(path, headers)
    session_keys = frozenset({
        'logincustomertoken', 'customertoken', 'apitoken', 'token', 'authorization',
    })
    token_present = bool(
        norm.get('token')
        or body_form.get('uid')
        or any(str(k).lower() in session_keys and v for k, v in query.items())
        or any(str(k).lower() in session_keys and v for k, v in body_form.items())
    )

    issues = []
    if has_encrypted_transport and not static_crypto.get('available'):
        issues.append('encrypted_fields_detected_but_no_static_crypto_index')
    if has_encrypted_transport and static_crypto.get('can_replay'):
        issues.append('static_crypto_chain_ready_for_decrypt_and_replay')
    elif has_encrypted_transport and static_crypto.get('available'):
        issues.append('static_crypto_chain_available_but_keys_unresolved')
    if not token_present and not re.search(r'login|federated|openid', path, re.I):
        issues.append('missing_token_on_non_login_request')
    if token_present and re.search(r'Federated/Login', path, re.I):
        issues.append('token_present_on_login_bootstrap_may_be_stale')

    crypto_processing = (
        process_request_crypto(
            req, field_layers, crypto_capability,
            output_dir=output_dir, source_dir=source_dir,
            session_context=session_context,
        )
        if crypto_capability else {}
    )

    response_crypto_processing: Dict[str, Any] = {}
    response_fields: List[str] = []
    response_body_preview = ''
    if response_body is not None and crypto_capability:
        response_crypto_processing = process_response_result(
            response_body, crypto_capability,
            output_dir=output_dir, source_dir=source_dir,
        )
        response_fields = sorted((response_crypto_processing.get('produces_fields') or {}).keys())
        if response_crypto_processing.get('body_json') is not None:
            response_body_preview = _response_preview(response_crypto_processing['body_json'])
        elif isinstance(response_body, dict):
            response_body_preview = _response_preview(response_body)

    plaintext_usable = token_present or any(
        l.get('layer') in {'plaintext_metadata', 'plaintext_param', 'plaintext_json'}
        for l in field_layers
    )

    if has_encrypted_transport and static_crypto.get('can_replay'):
        next_action = 'import_decrypted_context_and_replay'
        replay_mode = 'parametric_crypto_replay'
    elif has_encrypted_transport and plaintext_usable:
        next_action = 'import_plaintext_fields_only'
        replay_mode = 'plaintext_only_fallback'
    elif has_encrypted_transport:
        next_action = 'n1_pruned_ciphertext_no_chain'
        replay_mode = 'blocked_ciphertext'
    elif token_present:
        next_action = 'import_as_authenticated_sample_and_materialize'
        replay_mode = 'header_replay_candidate'
    else:
        next_action = 'import_as_login_bootstrap_sample'
        replay_mode = 'pre_auth_capture'

    if has_encrypted_transport and static_crypto.get('can_replay'):
        overall = 'acceptable_with_crypto'
    elif has_encrypted_transport and plaintext_usable:
        overall = 'acceptable_plaintext_partial'
    elif has_encrypted_transport and not static_crypto.get('available'):
        overall = 'blocked_ciphertext_no_chain'
    elif has_encrypted_transport:
        overall = 'blocked_ciphertext_keys_unresolved'
    elif token_present:
        overall = 'acceptable_plaintext'
    elif re.search(r'login|federated', path, re.I):
        overall = 'acceptable_pre_auth'
    else:
        overall = 'needs_review'

    transport_mode = 'unknown'
    has_cipher_layer = bool(crypto_layers & {
        'crypto_encrypted_query', 'crypto_encrypted_body', 'crypto_encrypted_header',
    })
    if has_cipher_layer and plaintext_usable:
        transport_mode = 'mixed'
    elif has_cipher_layer or 'crypto_signature' in crypto_layers:
        transport_mode = 'ciphertext_only'
    elif plaintext_usable:
        transport_mode = 'plaintext_only'

    result = {
        'capture_index': capture_index,
        'method': req.get('method'),
        'path': path,
        'host': norm.get('host'),
        'transport_snapshot': {
            k: str(body_form[k])
            for k in ('cid', 'q', 'uid', 'sign')
            if body_form.get(k)
        },
        'material_candidates': material_candidates,
        'field_layers': field_layers,
        'transport_assessment': {
            'has_encrypted_query': any(
                l['layer'] in {'crypto_encrypted_query', 'crypto_encrypted_body'}
                for l in field_layers
            ),
            'has_encrypted_body': any(l['layer'] == 'crypto_encrypted_body' for l in field_layers),
            'has_crypto_headers': any(l['layer'] in {'crypto_signature', 'crypto_encrypted_header'} for l in field_layers),
            'token_present': token_present,
            'replay_mode': replay_mode,
            'transport_mode': transport_mode,
            'plaintext_usable': plaintext_usable,
        },
        'static_crypto_crossref': static_crypto if has_encrypted_transport else {'checked': False},
        'crypto_processing': crypto_processing,
        'response_crypto_processing': response_crypto_processing or None,
        'response_fields': response_fields,
        'response_body_preview': response_body_preview or None,
        'query_fields': sorted(query.keys()),
        'header_fields': sorted(norm.keys()),
        'issues': issues,
        'overall_status': overall,
        'next_action': next_action,
    }
    result['n1_gate'] = evaluate_capture_n1_gate(result, static_crypto)
    return result


def validate_against_template(
    captures: List[Dict[str, Any]],
    template: Dict[str, Any],
) -> Dict[str, Any]:
    required_ids = {m['material_id'] for m in template.get('required_materials') or []}
    covered: Dict[str, List[int]] = {mid: [] for mid in required_ids}
    for cap in captures:
        for mid in cap.get('material_candidates') or []:
            if mid in covered:
                covered[mid].append(cap['capture_index'])

    missing_required = [mid for mid, idxs in covered.items() if not idxs]
    return {
        'required_materials': sorted(required_ids),
        'covered_by_capture': covered,
        'missing_required_materials': missing_required,
        'coverage_ratio': round(
            (len(required_ids) - len(missing_required)) / max(len(required_ids), 1), 2
        ),
    }


def _score_authenticated_sample_capture(cap: Dict[str, Any]) -> float:
    """Prefer real Bearer + Sign on business paths over placeholder auth."""
    score = 0.0
    path = cap.get('path') or ''
    ta = cap.get('transport_assessment') or {}
    if not ta.get('token_present'):
        return -1.0
    if not str(cap.get('overall_status') or '').startswith('acceptable'):
        score -= 2.0
    for layer in cap.get('field_layers') or []:
        name = str(layer.get('name') or '').lower()
        val = str(layer.get('value') or '')
        if name == 'authorization':
            if val.lower().startswith('bearer ') and val not in {'Bearer 123', 'bearer 123'} and len(val) > 24:
                score += 20.0
            elif val.lower().startswith('basic '):
                score += 4.0
            elif val in {'123', 'Bearer 123'}:
                score += 1.0
        if name == 'sign' and val:
            score += 10.0
    if re.search(r'customer|member|profile|personal|order|card', path, re.I):
        score += 12.0
    if re.search(r'login|oauth|token', path, re.I):
        score += 3.0
    return score


def _recommended_import_from_captures(
    captures: List[Dict[str, Any]],
    template: Dict[str, Any],
) -> Dict[str, Optional[int]]:
    """Derive material_id → capture_index from captures + pack template preview."""
    rec: Dict[str, Optional[int]] = {}
    preview_paths: Dict[str, List[str]] = {}
    for item in template.get('stage_1_target_preview') or []:
        path = item.get('path') or ''
        for mid in item.get('required_materials') or []:
            preview_paths.setdefault(mid, []).append(path)

    def _match_path(cap_path: str, patterns: List[str]) -> bool:
        if not cap_path:
            return False
        for p in patterns:
            if p and p in cap_path:
                return True
        return False

    for cap in captures:
        idx = cap.get('capture_index')
        path = cap.get('path') or ''
        for mid in cap.get('material_candidates') or []:
            if mid not in rec:
                rec[mid] = idx
        for mid, paths in preview_paths.items():
            if mid not in rec and _match_path(path, paths):
                rec[mid] = idx

    if 'authenticated_request_sample' not in rec:
        best_idx: Optional[int] = None
        best_score = -1.0
        for c in captures:
            sc = _score_authenticated_sample_capture(c)
            if sc > best_score:
                best_score = sc
                best_idx = c.get('capture_index')
        rec['authenticated_request_sample'] = best_idx
    for mid in ('login_or_user_profile_response', 'first_hop_response_device_list', 'openid_flow_sample'):
        if mid not in rec:
            rec[mid] = next(
                (c['capture_index'] for c in captures if mid in (c.get('material_candidates') or [])),
                None,
            )
    return rec


def build_intake_report(
    raw_text: str,
    output_dir: Path,
    template: Optional[Dict[str, Any]] = None,
    *,
    source_label: str = 'user_paste',
    source_dir: Optional[Path] = None,
    source_path: Optional[Path] = None,
) -> Dict[str, Any]:
    output_dir = Path(output_dir)
    if template is None:
        tmpl_path = output_dir / 'baseline_material_template.json'
        template = json.loads(tmpl_path.read_text(encoding='utf-8')) if tmpl_path.exists() else {}

    crypto_capability = load_crypto_capability(output_dir, source_dir=source_dir)
    static_crypto = _load_static_crypto_evidence(output_dir, source_dir=source_dir)
    captures = []
    parse_errors = []
    har_sequence_meta: Optional[Dict[str, Any]] = None
    chunk_count = 0

    from minidrifter.materials.har_sequence import (
        har_file_to_capture_inputs,
        har_text_to_capture_inputs,
        looks_like_har,
    )

    use_har = (
        looks_like_har(raw_text)
        or (source_path is not None and str(source_path).lower().endswith('.har'))
    )
    if use_har:
        if source_path and Path(source_path).exists() and not looks_like_har(raw_text):
            har_inputs = har_file_to_capture_inputs(Path(source_path))
        else:
            har_inputs = har_text_to_capture_inputs(raw_text)
        # Cap oversized sessions so intake stays interactive on multi-MB HARs
        if len(har_inputs) > 80:
            har_inputs = har_inputs[:80]
        chunk_count = len(har_inputs)
        har_sequence_meta = {
            'entry_count': chunk_count,
            'source': 'har',
            'source_file': str(source_path) if source_path else None,
        }
        acc_session_context: Dict[str, Any] = {}
        for i, item in enumerate(har_inputs):
            try:
                req = item['request']
                captures.append(analyze_capture(
                    req,
                    capture_index=i + 1,
                    static_crypto=static_crypto,
                    crypto_capability=crypto_capability,
                    output_dir=output_dir,
                    source_dir=source_dir,
                    response_body=item.get('response_body'),
                    session_context=acc_session_context,
                ))
                if item.get('started_at'):
                    captures[-1]['started_at'] = item['started_at']
                for k, v in (captures[-1].get('crypto_processing') or {}).get('resolved_fields', {}).items():
                    if v not in (None, ''):
                        if k == 'factor' and acc_session_context.get('user_key1') and str(v) != str(acc_session_context.get('user_key1')):
                            acc_session_context['user_key3'] = v
                        else:
                            acc_session_context[k] = v
                for k, v in (captures[-1].get('response_crypto_processing') or {}).get('produces_fields', {}).items():
                    if v not in (None, ''):
                        acc_session_context[k] = v
            except Exception as e:
                parse_errors.append({'capture_index': i + 1, 'error': str(e)})
    else:
        chunks = split_multi_raw_http(raw_text)
        chunk_count = len(chunks)
        acc_session_context: Dict[str, Any] = {}
        for i, chunk in enumerate(chunks):
            try:
                req = parse_raw_http(chunk)
                resp_body = extract_response_json_from_chunk(chunk)
                captures.append(analyze_capture(
                    req,
                    capture_index=i + 1,
                    static_crypto=static_crypto,
                    crypto_capability=crypto_capability,
                    output_dir=output_dir,
                    source_dir=source_dir,
                    response_body=resp_body,
                    session_context=acc_session_context,
                ))
                for k, v in (captures[-1].get('crypto_processing') or {}).get('resolved_fields', {}).items():
                    if v not in (None, ''):
                        if k == 'factor' and acc_session_context.get('user_key1') and str(v) != str(acc_session_context.get('user_key1')):
                            acc_session_context['user_key3'] = v
                        else:
                            acc_session_context[k] = v
                for k, v in (captures[-1].get('response_crypto_processing') or {}).get('produces_fields', {}).items():
                    if v not in (None, ''):
                        acc_session_context[k] = v
            except Exception as e:
                parse_errors.append({'capture_index': i + 1, 'error': str(e)})

    template_check = validate_against_template(captures, template) if template else {}
    n1_summary = summarize_n1_gate(captures)
    decrypted_aggregate = _aggregate_decrypted_fields(captures)

    crypto_count = sum(
        1 for c in captures
        if c['transport_assessment'].get('has_encrypted_query')
        or c['transport_assessment'].get('has_crypto_headers')
    )

    recommended_import = _recommended_import_from_captures(captures, template)

    strategy_hint = 'plaintext_direct'
    if crypto_count and static_crypto.get('can_replay'):
        strategy_hint = 'crypto_full_pipeline'
    elif crypto_count and any(c.get('transport_assessment', {}).get('plaintext_usable') for c in captures):
        strategy_hint = 'plaintext_fallback'

    report = {
        'schema_version': SCHEMA_VERSION,
        'generated_at': _utc_now(),
        'source_label': source_label,
        'pack_id': template.get('pack_id'),
        'miniapp': template.get('miniapp'),
        'capture_count': chunk_count,
        'parse_errors': parse_errors,
        'har_sequence_meta': har_sequence_meta,
        'crypto_capability': static_crypto,
        'n1_gate': n1_summary,
        'decrypted_fields_aggregate': decrypted_aggregate,
        'captures': captures,
        'template_coverage': template_check,
        'summary': {
            'acceptable': sum(1 for c in captures if c['overall_status'].startswith('acceptable')),
            'blocked': sum(1 for c in captures if c['overall_status'].startswith('blocked')),
            'needs_review': sum(1 for c in captures if c['overall_status'] == 'needs_review'),
            'crypto_transport_captures': crypto_count,
            'authorization_verified_count': sum(
                1 for c in captures
                if ((c.get('crypto_processing') or {}).get('authorization_check') or {}).get('verified')
            ),
            'plaintext_replay_candidates': sum(
                1 for c in captures if c['transport_assessment'].get('replay_mode') == 'header_replay_candidate'
            ),
            'n1_materialize_allowed': n1_summary.get('n1_materialize_allowed'),
        },
        'authority_model': {
            'rules': 'transport/crypto classification, decrypt when chain+keys ready, N1 prune, next_action',
            'llm_optional': 'explain ambiguous mapping only; cannot override crypto gates',
        },
        'recommended_file_split': recommended_import,
        'intake_strategy_hint': strategy_hint,
        'user_guidance': _build_user_guidance(captures, template_check, static_crypto, recommended_import, n1_summary),
        'never_hand_fill_in_stage1': NEVER_REQUEST_STAGE1,
    }
    try:
        from minidrifter.materials.object_pool_writer import enrich_intake_with_object_harvest
        report = enrich_intake_with_object_harvest(report, pack_dir=output_dir)
    except Exception:
        pass
    try:
        from minidrifter.materials.capture_sequence import write_capture_sequence
        write_capture_sequence(output_dir, report)
    except Exception:
        pass
    try:
        from minidrifter.verification.ticket_normalizer import sync_tickets_from_intake_report
        sync_tickets_from_intake_report(output_dir, report)
    except Exception:
        pass
    return report


def _aggregate_decrypted_fields(captures: List[Dict[str, Any]]) -> Dict[str, Any]:
    from minidrifter.classification.sensitive_field_normalizer import (
        expand_canonical_aliases,
        extract_canonical_fields_from_body,
    )

    merged: Dict[str, Any] = {}
    sources: Dict[str, str] = {}
    for cap in captures:
        idx = cap.get('capture_index')
        for proc_key in ('crypto_processing', 'response_crypto_processing'):
            proc = cap.get(proc_key) or {}
            for k, v in (proc.get('resolved_fields') or {}).items():
                if v in (None, ''):
                    continue
                merged[k] = v
                sources[k] = f'capture_{idx}.{proc_key}'
            for k, v in (proc.get('produces_fields') or {}).items():
                if v in (None, ''):
                    continue
                merged[k] = v
                sources[k] = f'capture_{idx}.{proc_key}.produces'
            body_json = proc.get('body_json')
            if body_json:
                for k, v in extract_canonical_fields_from_body(body_json).items():
                    if v in (None, ''):
                        continue
                    merged.setdefault(k, v)
                    sources.setdefault(k, f'capture_{idx}.{proc_key}.body_canonical')
    merged = expand_canonical_aliases(merged)
    for k in merged:
        sources.setdefault(k, sources.get(k) or 'canonical_alias')
    return {'fields': merged, 'sources': sources, 'field_count': len(merged)}


def _build_user_guidance(
    captures: List[Dict[str, Any]],
    template_check: Dict[str, Any],
    static_crypto: Dict[str, Any],
    recommended_import: Dict[str, Optional[int]],
    n1_summary: Dict[str, Any],
) -> List[str]:
    lines = []
    if static_crypto.get('can_replay'):
        lines.append(
            f'静态加密链已就绪（profile={static_crypto.get("profile_id")}，wrapper={static_crypto.get("primary_wrapper")}）。'
            ' 已自动解密 query/AppIdentity 并校验 Authorization。'
        )
    elif static_crypto.get('available'):
        lines.append('静态有加密链索引但密钥未解析；将尝试明文 session 字段降级 replay，或提供 --source-dir 启用完整解密。')
    elif any(c['transport_assessment'].get('has_encrypted_query') for c in captures):
        fallback = sum(1 for c in captures if c.get('transport_assessment', {}).get('plaintext_usable'))
        if fallback:
            lines.append(f'检测到密文 transport 且无静态链；{fallback} 条 capture 可降级为明文字段导入。')
        else:
            lines.append('检测到密文 transport 但无静态加密链 → N1 减枝，仅接受明文材料继续。')

    if n1_summary.get('overall') == 'pruned_all':
        lines.append('全部 capture 被 N1 减枝：密文且无解密能力，无法进入 materialize/replay。')
    elif n1_summary.get('pruned_capture_count'):
        lines.append(
            f"N1 门禁：{n1_summary.get('eligible_capture_count')} 条可继续，"
            f"{n1_summary.get('pruned_capture_count')} 条被减枝。"
        )

    auth_ok = sum(
        1 for c in captures
        if ((c.get('crypto_processing') or {}).get('authorization_check') or {}).get('verified')
    )
    if auth_ok:
        lines.append(f'Authorization 校验通过: {auth_ok}/{len(captures)} 条 capture。')

    agg = _aggregate_decrypted_fields(captures).get('fields') or {}
    if agg.get('UserId') or agg.get('userId'):
        lines.append(f"解密得到 UserId={agg.get('UserId') or agg.get('userId')}，可写入 baseline_runtime_context。")
    if agg.get('OpenId') or agg.get('openId'):
        lines.append(f"解密得到 OpenId={agg.get('OpenId') or agg.get('openId')}。")

    cov = template_check.get('coverage_ratio')
    if cov is not None:
        lines.append(f'Stage-1 必填材料覆盖率: {cov * 100:.0f}%')
        for mid in template_check.get('missing_required_materials') or []:
            lines.append(f'仍缺必填材料: {mid}（见 baseline_material_template.json）')
    if recommended_import.get('authenticated_request_sample'):
        lines.append(
            f'建议将 capture #{recommended_import["authenticated_request_sample"]} 存为 authenticated_request_sample.http'
        )
    if recommended_import.get('openid_flow_sample'):
        lines.append(
            f'Login bootstrap (capture #{recommended_import["openid_flow_sample"]}) 已解密 openId/code；'
            'response Result 若加密请一并提供。'
        )
    if not any((c.get('crypto_processing') or {}).get('decrypted', {}).get('response') for c in captures):
        lines.append('仍建议补充 response body（CacheInfo/Device List 的 Result 字段，可加密）。')
    return lines
