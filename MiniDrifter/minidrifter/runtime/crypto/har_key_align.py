# -*- coding: utf-8 -*-
"""Align crypto material keys against HAR ciphertext (generic, profile-agnostic).

Tries all candidates in app_key_map (AES cipherH5 + SM4 f/l/g,d/b/y) until
decrypt yields structured plaintext (query-string or JSON). Rewrites
crypto_static_profile.json material when a better pick is found.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import parse_qsl, unquote, urlparse

from minidrifter.core.utils import write_json
from minidrifter.runtime.crypto.profile_key_extract import CryptoMaterial
from minidrifter.runtime.crypto.triple_mix_key import derive_triple_mix_key

_PRINTABLE_RE = re.compile(r'[\x20-\x7E\u4e00-\u9fff]')


def _printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    sample = text[:240]
    return sum(1 for c in sample if _PRINTABLE_RE.match(c)) / max(1, len(sample))


def decrypt_quality(plain: str) -> float:
    """Higher is better. Structured KV/JSON plaintext scores high; binary garbage ≈ 0."""
    if not plain:
        return 0.0
    ratio = _printable_ratio(plain)
    if ratio < 0.55:
        return 0.0
    score = ratio
    if '=' in plain and '&' in plain:
        score += 0.35
    if plain.lstrip().startswith(('{', '[')):
        score += 0.35
    if re.search(r'(userid|openid|token|account|phone|mobile|card|member)', plain, re.I):
        score += 0.2
    # reject mostly replacement chars
    if plain.count('\ufffd') > max(3, len(plain) // 10):
        return 0.0
    return score


def _iter_har_entries(har_path: Path) -> List[Dict[str, Any]]:
    doc = json.loads(Path(har_path).read_text(encoding='utf-8', errors='replace'))
    return list((doc.get('log') or {}).get('entries') or [])


def _body_params(entry: Dict[str, Any]) -> Dict[str, str]:
    req = entry.get('request') or {}
    post = req.get('postData') or {}
    text = post.get('text') or ''
    params: Dict[str, str] = {}
    if text:
        if text.lstrip().startswith('{'):
            try:
                obj = json.loads(text)
                if isinstance(obj, dict):
                    params.update({str(k): str(v) for k, v in obj.items() if v is not None})
            except Exception:
                pass
        if not params:
            for k, v in parse_qsl(text, keep_blank_values=True):
                params[k] = v
    for item in post.get('params') or []:
        if isinstance(item, dict) and item.get('name'):
            params[str(item['name'])] = str(item.get('value') or '')
    # URL-decode cipher blobs
    for k in list(params):
        if 'cipher' in k.lower() and params[k]:
            params[k] = unquote(params[k])
    return params


def collect_har_cipher_samples(har_path: Path, *, limit: int = 24) -> Dict[str, List[str]]:
    """Collect cipherH5 / cipherOne / cipherTwo blobs from HAR."""
    out: Dict[str, List[str]] = {'cipherH5': [], 'cipherOne': [], 'cipherTwo': []}
    for entry in _iter_har_entries(har_path):
        params = _body_params(entry)
        for key, bucket in (
            ('cipherH5', 'cipherH5'),
            ('cipherh5', 'cipherH5'),
            ('cipherOne', 'cipherOne'),
            ('cipherone', 'cipherOne'),
            ('cipherTwo', 'cipherTwo'),
            ('ciphertwo', 'cipherTwo'),
        ):
            val = params.get(key)
            if val and val not in out[bucket]:
                out[bucket].append(val)
                if sum(len(v) for v in out.values()) >= limit:
                    return out
    return out


def har_host_hints(har_path: Path) -> List[str]:
    counts: Dict[str, int] = {}
    for entry in _iter_har_entries(har_path):
        url = ((entry.get('request') or {}).get('url') or '')
        host = urlparse(url).netloc.lower()
        if not host or 'datafinder' in host or host.startswith('static.'):
            continue
        counts[host] = counts.get(host, 0) + 1
    return [h for h, _ in sorted(counts.items(), key=lambda x: -x[1])]


def _aes_key_iv_variants(key: str, iv: str) -> List[Tuple[str, str]]:
    """Yield (key, iv) string forms accepted by AesCbcCipherH5FormEngine."""
    out = [(key, iv)]
    # If stored as hex of ASCII key, also try decoded ASCII
    if re.fullmatch(r'[0-9a-fA-F]{32}', key or ''):
        try:
            decoded = bytes.fromhex(key).decode('utf-8', errors='ignore')
            if decoded and len(decoded) in (16, 24, 32):
                out.append((decoded, iv))
        except Exception:
            pass
    if re.fullmatch(r'[0-9a-fA-F]{32}', iv or ''):
        try:
            decoded_iv = bytes.fromhex(iv).decode('utf-8', errors='ignore')
            if decoded_iv and len(decoded_iv) == 16:
                for k, _ in list(out):
                    out.append((k, decoded_iv))
        except Exception:
            pass
    # unique
    seen = set()
    uniq = []
    for item in out:
        if item not in seen:
            seen.add(item)
            uniq.append(item)
    return uniq


def _aes_decrypt(blob: str, key: str, iv: str) -> str:
    from minidrifter.runtime.crypto.aes_cbc_cipherh5_form_wrapper import AesCbcCipherH5FormEngine
    from minidrifter.runtime.crypto.profile_key_extract import CryptoMaterial as CM
    last_err = None
    best_plain = ''
    best_score = -1.0
    for k, v in _aes_key_iv_variants(key, iv):
        try:
            eng = AesCbcCipherH5FormEngine(CM(profile_id='aes_cbc_cipherh5_form_wrapper', aes_key=k, aes_iv=v))
            plain = eng.decrypt_cipher_h5(blob)
            score = decrypt_quality(plain)
            if score > best_score:
                best_score = score
                best_plain = plain
        except Exception as ex:
            last_err = ex
            continue
    if best_score >= 0:
        return best_plain
    if last_err:
        raise last_err
    return ''



def _sm4_score_entry(entry: Dict[str, str], samples: Dict[str, List[str]]) -> Tuple[float, Dict[str, str]]:
    extras: Dict[str, str] = {}
    if not (entry.get('f') and entry.get('l') and entry.get('g')):
        return 0.0, extras
    type2 = derive_triple_mix_key(entry['f'], entry['l'], entry['g'])
    type1 = ''
    if entry.get('d') and entry.get('b') and entry.get('y'):
        type1 = derive_triple_mix_key(entry['d'], entry['b'], entry['y'])
    extras['sm4_type2_key_hex'] = type2
    if type1:
        extras['sm4_type1_default_hex'] = type1
    from minidrifter.runtime.crypto.sm4_dual_form_wrapper import Sm4DualFormEngine
    from minidrifter.runtime.crypto.profile_key_extract import CryptoMaterial as CM
    try:
        eng = Sm4DualFormEngine(CM(
            profile_id='sm4_dual_form_wrapper',
            extras=extras,
        ))
    except Exception:
        return 0.0, extras
    best = 0.0
    for blob in (samples.get('cipherTwo') or [])[:4]:
        try:
            plain = eng.decrypt_cipher_two(blob)
            best = max(best, decrypt_quality(plain))
        except Exception:
            continue
    for blob in (samples.get('cipherOne') or [])[:4]:
        try:
            plain = eng.decrypt_cipher_one(blob)
            best = max(best, decrypt_quality(plain) * 0.9)
        except Exception:
            continue
    return best, extras


def align_crypto_material_with_har(
    material: CryptoMaterial,
    har_path: Path,
    *,
    min_score: float = 0.55,
) -> Dict[str, Any]:
    """Try app_key_map candidates; mutate material in-place when a better key wins."""
    har_path = Path(har_path)
    report: Dict[str, Any] = {
        'ok': False,
        'har': str(har_path),
        'aes_aligned': False,
        'sm4_aligned': False,
        'aes_score': 0.0,
        'sm4_score': 0.0,
        'picked_app_id': material.extras.get('app_id') or '',
        'hosts': har_host_hints(har_path)[:8],
        'notes': [],
    }
    if not har_path.exists():
        report['notes'].append('har_missing')
        return report

    samples = collect_har_cipher_samples(har_path)
    report['sample_counts'] = {k: len(v) for k, v in samples.items()}
    key_map = dict(material.extras.get('app_key_map') or {})

    # --- AES cipherH5 ---
    aes_candidates: List[Tuple[str, str, str]] = []  # app_id, key, iv
    if material.aes_key and material.aes_iv:
        aes_candidates.append((str(material.extras.get('app_id') or 'current'), material.aes_key, material.aes_iv))
    for app_id, entry in key_map.items():
        if isinstance(entry, dict) and entry.get('aes_key') and entry.get('aes_iv'):
            aes_candidates.append((app_id, entry['aes_key'], entry['aes_iv']))

    best_aes = (0.0, '', '', '')
    for app_id, key, iv in aes_candidates:
        scores = []
        for blob in (samples.get('cipherH5') or [])[:6]:
            try:
                plain = _aes_decrypt(blob, key, iv)
                scores.append(decrypt_quality(plain))
            except Exception:
                scores.append(0.0)
        score = max(scores) if scores else 0.0
        if score > best_aes[0]:
            best_aes = (score, app_id, key, iv)
    report['aes_score'] = best_aes[0]
    if best_aes[0] >= min_score and best_aes[2]:
        material.aes_key = best_aes[2]
        material.aes_iv = best_aes[3]
        material.extras['app_id'] = best_aes[1]
        report['aes_aligned'] = True
        report['picked_app_id'] = best_aes[1]
        report['notes'].append(f'aes_pick:{best_aes[1]}:{best_aes[0]:.2f}')
    elif samples.get('cipherH5'):
        report['notes'].append(f'aes_no_good_candidate:best={best_aes[0]:.2f}')

    # Prefer host-matching SM4 entry
    hosts = report['hosts']
    sm4_rows: List[Tuple[float, str, Dict[str, str], Dict[str, str]]] = []
    for app_id, entry in key_map.items():
        if not isinstance(entry, dict):
            continue
        score, extras = _sm4_score_entry(entry, samples)
        if hosts and entry.get('base_url'):
            base = str(entry['base_url']).lower()
            if any(h in base for h in hosts):
                score += 0.2
        sm4_rows.append((score, app_id, entry, extras))
    sm4_rows.sort(key=lambda r: -r[0])
    # Soft accept: host-matched SM4 with any non-zero decrypt progress
    sm4_threshold = min_score
    if sm4_rows and hosts and sm4_rows[0][2].get('base_url'):
        base = str(sm4_rows[0][2].get('base_url') or '').lower()
        if any(h in base for h in hosts):
            sm4_threshold = min(min_score, 0.15)
    if sm4_rows and sm4_rows[0][0] >= sm4_threshold and sm4_rows[0][3].get('sm4_type2_key_hex'):
        score, app_id, entry, extras = sm4_rows[0]
        material.extras.update(extras)
        material.extras['app_id'] = app_id or material.extras.get('app_id') or ''
        material.extras['sm4_aligned_app_id'] = app_id
        if entry.get('base_url') and not material.api_host:
            material.api_host = entry['base_url']
        report['sm4_aligned'] = True
        report['sm4_score'] = score
        report['picked_app_id'] = material.extras.get('app_id') or app_id
        report['notes'].append(f'sm4_pick:{app_id}:{score:.2f}')
    elif samples.get('cipherOne') or samples.get('cipherTwo'):
        best = sm4_rows[0][0] if sm4_rows else 0.0
        report['sm4_score'] = best
        report['notes'].append(f'sm4_no_good_candidate:best={best:.2f}')

    report['ok'] = bool(report['aes_aligned'] or report['sm4_aligned'])
    return report


def align_pack_crypto_with_har(
    pack_dir: Path,
    har_path: Path,
    *,
    persist: bool = True,
) -> Dict[str, Any]:
    """Load pack crypto profile, align against HAR, optionally rewrite profile."""
    from minidrifter.runtime.crypto.registry import get_crypto_engine_for_pack

    pack_dir = Path(pack_dir)
    har_path = Path(har_path)
    engine, cap = get_crypto_engine_for_pack(pack_dir)
    if not engine or not hasattr(engine, 'material'):
        return {'ok': False, 'notes': ['no_crypto_engine'], 'can_replay': bool(cap and cap.can_replay)}

    material: CryptoMaterial = engine.material
    report = align_crypto_material_with_har(material, har_path)
    report['profile_id'] = getattr(cap, 'profile_id', None)
    report['transport_style'] = getattr(cap, 'transport_style', None)

    if persist and report.get('ok'):
        prof_path = pack_dir / 'crypto_static_profile.json'
        if prof_path.exists():
            doc = json.loads(prof_path.read_text(encoding='utf-8'))
            mat = doc.setdefault('material', {})
            mat['aes_key'] = material.aes_key
            mat['aes_iv'] = material.aes_iv
            mat['api_host'] = material.api_host or mat.get('api_host') or ''
            mat['extras'] = material.extras
            mat['transport_style'] = material.transport_style or mat.get('transport_style')
            doc['har_key_align'] = {
                'aes_aligned': report.get('aes_aligned'),
                'sm4_aligned': report.get('sm4_aligned'),
                'aes_score': report.get('aes_score'),
                'sm4_score': report.get('sm4_score'),
                'picked_app_id': report.get('picked_app_id'),
                'har': str(har_path),
            }
            write_json(prof_path, doc)
            report['persisted'] = str(prof_path)
    return report
