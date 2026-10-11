# -*- coding: utf-8 -*-
"""Profile-driven crypto material extraction from decompiled JS (universal)."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from minidrifter.runtime.crypto.key_extract import (
    extract_md5_aeskey_from_snippets,
    extract_wrapper_keys_from_js,
)
from minidrifter.runtime.crypto.sign_engines import load_sign_method_from_profile
from minidrifter.runtime.crypto.triple_mix_key import derive_triple_mix_key

_PACKS_ROOT = Path(__file__).resolve().parents[3] / 'packs'


@dataclass
class CryptoMaterial:
    """Resolved crypto constants for a transport profile."""
    profile_id: str
    aes_key: str = ''
    aes_iv: str = ''
    md5_aeskey: str = ''
    cid: str = ''
    sign_key: str = ''
    sign_method: str = ''
    api_host: str = ''
    transport_style: str = ''
    extras: Dict[str, str] = field(default_factory=dict)
    extraction_method: str = ''
    source_label: str = ''

    @property
    def replay_ready(self) -> bool:
        if self.transport_style == 'form_cid_q_sign':
            return bool(self.aes_key and self.cid and self.sign_key)
        if self.transport_style == 'header_hmac_sign':
            return bool(self.sign_key) and not self._sign_key_placeholder()
        if self.transport_style == 'form_des_params_encrypted':
            return bool(self.aes_key or self.extras.get('des_key'))
        if self.transport_style == 'form_cipherh5_encrypted':
            return bool(self.aes_key and self.aes_iv)
        if self.transport_style == 'form_sm4_cipherone_ciphertwo':
            return bool(self.extras.get('sm4_type2_key_hex'))
        return bool(self.aes_key and self.aes_iv)

    def _sign_key_placeholder(self) -> bool:
        low = (self.sign_key or '').lower()
        placeholders = (
            'replace-with-your-sign-secret',
            'your-sign-secret',
            'changeme',
            'placeholder',
        )
        return any(p in low for p in placeholders)


def load_crypto_profile_doc(profile_id: str) -> Dict[str, Any]:
    path = _PACKS_ROOT / 'crypto_profiles' / f'{profile_id}.json'
    if path.exists():
        return json.loads(path.read_text(encoding='utf-8'))
    return {'profile_id': profile_id}


def _first_match(text: str, patterns: List[str]) -> Optional[str]:
    for pat in patterns:
        m = re.search(pat, text, re.I | re.S)
        if m:
            return m.group(1) if m.lastindex else m.group(0)
    return None


APPID_CASE_RE = re.compile(r'case\s+"(wx[a-f0-9]{16})"\s*:', re.I)
DEFAULT_CASE_RE = re.compile(r'\bdefault\s*:\s*([\s\S]*?)(?=\}\s*;|\nfunction\s|\nexports\.)', re.I)


def _glob_source_files(root: Path, pattern: str) -> List[Path]:
    pat = (pattern or '').replace('\\', '/')
    if pat.startswith('**/'):
        name = pat[3:]
        return sorted(p for p in root.rglob(name) if p.is_file())
    return sorted(p for p in root.glob(pat) if p.is_file())


def _read_source_text(path: Path) -> Optional[str]:
    try:
        return path.read_text(encoding='utf-8', errors='replace')
    except OSError:
        return None


def _extract_switch_block_fields(block: str, field_patterns: Dict[str, List[str]]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for field, patterns in (field_patterns or {}).items():
        val = _first_match(block, patterns or [])
        if val:
            out[field] = val
    return out


def extract_appid_switch_key_map(
    text: str,
    *,
    field_patterns: Optional[Dict[str, List[str]]] = None,
) -> Dict[str, Dict[str, str]]:
    """Parse miniProgram appId switch blocks → per-app crypto constants."""
    field_patterns = field_patterns or {}
    found: Dict[str, Dict[str, str]] = {}
    for m in APPID_CASE_RE.finditer(text):
        app_id = m.group(1)
        start = m.end()
        next_case = APPID_CASE_RE.search(text, start)
        default_m = DEFAULT_CASE_RE.search(text, start)
        end = len(text)
        for candidate in (next_case.start() if next_case else None, default_m.start() if default_m else None):
            if candidate is not None:
                end = min(end, candidate)
        block = text[start:end]
        fields = _extract_switch_block_fields(block, field_patterns)
        if fields:
            fields['app_id'] = app_id
            found[app_id] = fields

    default_m = DEFAULT_CASE_RE.search(text)
    if default_m:
        fields = _extract_switch_block_fields(default_m.group(1), field_patterns)
        if fields:
            fields['app_id'] = 'default'
            found['default'] = fields
    return found


def _load_project_app_id(source_dir: Path, spec: Dict[str, Any]) -> Optional[str]:
    for rel in spec.get('app_id_files') or ['project.config.json']:
        path = source_dir / rel
        if not path.exists():
            continue
        try:
            doc = json.loads(path.read_text(encoding='utf-8'))
        except (json.JSONDecodeError, OSError):
            continue
        app_id = str(doc.get('appid') or doc.get('appId') or '').strip()
        if app_id.startswith('wx') and len(app_id) >= 16:
            return app_id
    return None


def _host_hints_from_pack(pack_dir: Optional[Path]) -> List[str]:
    hints: List[str] = []
    seen: set[str] = set()

    def _add_host(raw: str) -> None:
        host = str(raw).replace('https://', '').replace('http://', '').split('/')[0].lower()
        if host and host not in seen:
            seen.add(host)
            hints.append(host)

    pack_candidates: List[Path] = []
    if pack_dir:
        pack_candidates.append(Path(pack_dir))
        if Path(pack_dir).name.upper() == 'OUTPUT' and Path(pack_dir).parent:
            pack_candidates.append(Path(pack_dir).parent)

    try:
        from minidrifter.adapters.pack_resolver import resolve_pack_profile
        for cand in pack_candidates:
            prof = resolve_pack_profile(cand)
            for host in prof.get('host_hints') or []:
                _add_host(host)
    except Exception:
        pass

    if pack_dir:
        intake_path = Path(pack_dir) / 'baseline_intake_report.json'
        if intake_path.exists():
            try:
                doc = json.loads(intake_path.read_text(encoding='utf-8'))
                for cap in doc.get('captures') or []:
                    _add_host(cap.get('host') or '')
            except (json.JSONDecodeError, OSError):
                pass
    return hints


def _ranked_host_hints(pack_dir: Optional[Path]) -> List[str]:
    ranked: List[str] = []
    seen: set[str] = set()

    def _push(host: str) -> None:
        host = str(host).replace('https://', '').replace('http://', '').split('/')[0].lower()
        if host and host not in seen:
            seen.add(host)
            ranked.append(host)

    if pack_dir:
        intake_path = Path(pack_dir) / 'baseline_intake_report.json'
        if intake_path.exists():
            try:
                from collections import Counter
                doc = json.loads(intake_path.read_text(encoding='utf-8'))
                counts = Counter(
                    str(cap.get('host') or '').replace('https://', '').replace('http://', '').split('/')[0].lower()
                    for cap in doc.get('captures') or []
                    if cap.get('host')
                )
                for host, _ in counts.most_common():
                    _push(host)
            except (json.JSONDecodeError, OSError):
                pass
        # HAR under CRBD_validation / sibling capture dirs
        for pattern in (
            '**/CRBD_validation/trace/**/*.har',
            '../CRBD_validation/trace/**/*.har',
        ):
            try:
                root = Path(pack_dir)
                for har in list(root.glob(pattern))[:4] + list(root.parent.glob('CRBD_validation/trace/**/*.har'))[:4]:
                    if har.name.endswith('.bak') or not har.is_file():
                        continue
                    try:
                        from minidrifter.runtime.crypto.har_key_align import har_host_hints
                        for host in har_host_hints(har)[:8]:
                            _push(host)
                    except Exception:
                        continue
                    break
            except Exception:
                pass

    for host in _host_hints_from_pack(pack_dir):
        _push(host)
    return ranked


def _entry_has_cipher_keys(entry: Dict[str, str]) -> bool:
    return bool(entry.get('aes_key') and entry.get('aes_iv'))


def _entry_has_sm4_literals(entry: Dict[str, str]) -> bool:
    return bool(entry.get('f') and entry.get('l') and entry.get('g'))


BASELIFE_APPID_IF_RE = re.compile(r'if\s*\(\s*"(wx[a-f0-9]{16})"\s*==\s*p\s*\)', re.I)
HEX32_CAPTURE = r'([0-9a-fA-F]{32})'


def extract_baselife_appid_key_map(text: str) -> Dict[str, Dict[str, str]]:
    """Parse baselifeConfig per-appId SM4 literal triples (f,l,g,d,b,y)."""
    found: Dict[str, Dict[str, str]] = {}
    for m in BASELIFE_APPID_IF_RE.finditer(text):
        app_id = m.group(1)
        start = m.end()
        next_if = BASELIFE_APPID_IF_RE.search(text, start)
        else_m = re.search(r'\belse\b', text[start:])
        end = len(text)
        if next_if:
            end = min(end, next_if.start())
        if else_m:
            end = min(end, start + else_m.start())
        block = text[start:end]
        fields: Dict[str, str] = {'app_id': app_id}
        for name in ('f', 'l', 'g', 'd', 'b', 'y'):
            val = _first_match(block, [rf'\b{name}\s*=\s*"{HEX32_CAPTURE}"'])
            if val:
                fields[name] = val.lower()
        base_url = _first_match(block, [r'\bv\s*=\s*"([^"]+)"'])
        if base_url:
            fields['base_url'] = base_url
        if _entry_has_sm4_literals(fields):
            found[app_id] = fields
    return found


def _pick_baselife_appid_entry(
    key_map: Dict[str, Dict[str, str]],
    *,
    source_dir: Optional[Path] = None,
    pack_dir: Optional[Path] = None,
    spec: Optional[Dict[str, Any]] = None,
) -> Tuple[Optional[str], Dict[str, str]]:
    if not key_map:
        return None, {}
    spec = spec or {}
    host_cfg = spec.get('host_resolution') or {}
    hints = _ranked_host_hints(pack_dir) if host_cfg.get('prefer_pack_host_hints', True) else []

    if source_dir:
        app_id = _load_project_app_id(Path(source_dir), spec)
        entry = key_map.get(app_id or '')
        if app_id and _entry_has_sm4_literals(entry):
            return app_id, entry

    def _host_match_rank(entry: Dict[str, str]) -> int:
        base_url = str(entry.get('base_url') or '').lower()
        for idx, host in enumerate(hints):
            if host in base_url:
                return idx
        return len(hints) + 1

    complete = [
        (app_id, entry)
        for app_id, entry in key_map.items()
        if _entry_has_sm4_literals(entry)
    ]
    if not complete:
        return None, {}
    if hints:
        best = min(complete, key=lambda row: (_host_match_rank(row[1]), row[0]))
        if _host_match_rank(best[1]) <= len(hints):
            return best
    if len(complete) == 1:
        return complete[0]
    return complete[0]


def _pick_appid_switch_entry(
    key_map: Dict[str, Dict[str, str]],
    *,
    source_dir: Optional[Path] = None,
    pack_dir: Optional[Path] = None,
    spec: Optional[Dict[str, Any]] = None,
) -> Tuple[Optional[str], Dict[str, str]]:
    if not key_map:
        return None, {}
    spec = spec or {}
    host_cfg = spec.get('host_resolution') or {}
    hints = _ranked_host_hints(pack_dir) if host_cfg.get('prefer_pack_host_hints', True) else []

    if source_dir:
        app_id = _load_project_app_id(Path(source_dir), spec)
        entry = key_map.get(app_id or '')
        if app_id and _entry_has_cipher_keys(entry):
            return app_id, entry

    def _host_match_rank(entry: Dict[str, str]) -> int:
        base_url = str(entry.get('base_url') or '').lower()
        for idx, host in enumerate(hints):
            if host in base_url:
                return idx
        return len(hints) + 1

    complete = [
        (app_id, entry)
        for app_id, entry in key_map.items()
        if _entry_has_cipher_keys(entry) and app_id != 'default'
    ]
    if not complete:
        complete = [
            (app_id, entry)
            for app_id, entry in key_map.items()
            if _entry_has_cipher_keys(entry)
        ]
    if complete:
        if hints:
            best = min(complete, key=lambda row: (_host_match_rank(row[1]), row[0]))
            if _host_match_rank(best[1]) <= len(hints):
                return best
        if len(complete) == 1:
            return complete[0]
        non_default = [row for row in complete if row[0] != 'default']
        return non_default[0] if non_default else complete[0]

    fallback = host_cfg.get('fallback') or 'default_case'
    if fallback == 'default_case' and 'default' in key_map and _entry_has_cipher_keys(key_map['default']):
        return 'default', key_map['default']
    return None, {}


def collect_profile_source_texts(
    profile_id: str,
    *,
    wrapper_file: str = '',
    source_dir: Optional[Path] = None,
    snippet: str = '',
) -> List[Tuple[str, str]]:
    """Load wrapper + profile companion JS sources for key extraction."""
    texts = read_wrapper_js(wrapper_file, source_dir=source_dir, snippet=snippet)
    labels = {label for label, _ in texts}
    doc = load_crypto_profile_doc(profile_id)
    extraction = doc.get('key_extraction') or {}
    if source_dir:
        root = Path(source_dir)
        for pattern in extraction.get('companion_file_globs') or []:
            for path in _glob_source_files(root, pattern):
                label = str(path.relative_to(root)).replace('\\', '/')
                if label in labels:
                    continue
                body = _read_source_text(path)
                if body:
                    texts.append((label, body))
                    labels.add(label)
    return texts


def _extract_named_literals(text: str, spec: Dict[str, Any]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    markers = spec.get('module_markers') or []
    if markers and not any(m in text for m in markers):
        return out

    for rule in spec.get('literals') or []:
        name = rule.get('name') or rule.get('field')
        if not name:
            continue
        val = _first_match(text, rule.get('patterns') or [])
        if not val:
            continue
        min_len = rule.get('min_len')
        max_len = rule.get('max_len')
        if min_len and len(val) < min_len:
            continue
        if max_len and len(val) > max_len:
            continue
        out[name] = val

    alias = spec.get('aliases') or {}
    for target, source in alias.items():
        if target not in out and source in out:
            out[target] = out[source]
    return out


def extract_crypto_material(
    profile_id: str,
    js_text: str,
    *,
    source_label: str = '',
    source_dir: Optional[Path] = None,
    pack_dir: Optional[Path] = None,
    wrapper_file: str = '',
) -> Optional[CryptoMaterial]:
    """Extract keys/constants using packs/crypto_profiles/{profile_id}.json rules."""
    doc = load_crypto_profile_doc(profile_id)
    method = (doc.get('key_extraction') or {}).get('method') or 'utf8_parse_literals'
    transport = (doc.get('transport') or {}).get('style') or ''

    if method == 'utf8_parse_literals':
        keys = extract_wrapper_keys_from_js(js_text)
        if not keys or not keys.aes_key:
            md5 = extract_md5_aeskey_from_snippets(js_text)
            if md5:
                return CryptoMaterial(
                    profile_id=profile_id,
                    md5_aeskey=md5,
                    transport_style='header_query_encrypted',
                    extraction_method=method,
                    source_label=source_label,
                )
            return None
        return CryptoMaterial(
            profile_id=profile_id,
            aes_key=keys.aes_key.decode('utf-8', errors='replace'),
            aes_iv=keys.aes_iv.decode('utf-8', errors='replace'),
            md5_aeskey=keys.md5_aeskey or '',
            transport_style='header_query_encrypted',
            extraction_method=method,
            source_label=source_label,
        )

    if method == 'named_string_literals':
        spec = doc.get('key_extraction') or {}
        found = _extract_named_literals(js_text, spec)
        if not found:
            return None
        mat = CryptoMaterial(
            profile_id=profile_id,
            aes_key=found.get('aes_key') or found.get('ky') or '',
            cid=found.get('cid') or found.get('hp') or '',
            sign_key=found.get('sign_key') or found.get('aes_key') or found.get('ky') or '',
            sign_method=load_sign_method_from_profile(doc),
            api_host=found.get('api_host') or found.get('host') or '',
            transport_style=transport or 'form_cid_q_sign',
            extraction_method=method,
            source_label=source_label,
            extras={k: v for k, v in found.items() if k not in {'aes_key', 'ky', 'cid', 'hp', 'sign_key', 'api_host', 'host'}},
        )
        return mat if mat.replay_ready else mat

    if method == 'hmac_secret_literal':
        spec = doc.get('key_extraction') or {}
        found = _extract_named_literals(js_text, spec)
        if not found:
            return None
        sign_key = found.get('sign_key') or found.get('hmac_secret') or ''
        mat = CryptoMaterial(
            profile_id=profile_id,
            sign_key=sign_key,
            sign_method=load_sign_method_from_profile(doc),
            transport_style=transport or 'header_hmac_sign',
            extraction_method=method,
            source_label=source_label,
            extras={
                'hmac_secret': sign_key,
                'payload_builder': (doc.get('sign') or {}).get('payload_builder') or 'relative_path_merge_params',
                'sign_header': (doc.get('transport') or {}).get('sign_header') or 'Sign',
            },
        )
        return mat

    if method == 'baselife_appid_literals':
        spec = doc.get('key_extraction') or {}
        switch_markers = spec.get('switch_markers') or ['getPostDataSM4']
        texts = collect_profile_source_texts(
            profile_id,
            wrapper_file=wrapper_file,
            source_dir=source_dir,
            snippet=js_text if source_label.endswith('snippet') else '',
        )
        if not texts and js_text:
            texts = [(source_label or 'inline', js_text)]
        key_map: Dict[str, Dict[str, str]] = {}
        key_source = source_label
        for label, text in texts:
            if not any(marker in text for marker in switch_markers):
                continue
            merged = extract_baselife_appid_key_map(text)
            if merged:
                key_map.update(merged)
                key_source = label
        app_id, picked = _pick_baselife_appid_entry(
            key_map,
            source_dir=source_dir,
            pack_dir=pack_dir,
            spec=spec,
        )
        if not _entry_has_sm4_literals(picked):
            return None
        type2_hex = derive_triple_mix_key(picked['f'], picked['l'], picked['g'])
        type1_hex = ''
        if picked.get('d') and picked.get('b') and picked.get('y'):
            type1_hex = derive_triple_mix_key(picked['d'], picked['b'], picked['y'])
        return CryptoMaterial(
            profile_id=profile_id,
            api_host=picked.get('base_url') or '',
            transport_style=transport or 'form_sm4_cipherone_ciphertwo',
            extraction_method=method,
            source_label=key_source,
            extras={
                'app_id': app_id or '',
                'sm4_type2_key_hex': type2_hex,
                'sm4_type1_default_hex': type1_hex,
                'baselife_literals': {k: picked[k] for k in ('f', 'l', 'g', 'd', 'b', 'y') if picked.get(k)},
                'app_key_map': {k: v for k, v in key_map.items()},
            },
        )

    if method == 'des_ai_literal':
        # CryptoJS pattern: export ai → hex/string literal used as DES Utf8 key material
        des_key = ''
        m_ai = re.search(
            r'ai\s*:\s*function\s*\(\s*\)\s*\{\s*return\s+(\w+)\s*\}',
            js_text,
        )
        if m_ai:
            var = m_ai.group(1)
            m_val = re.search(
                rf'(?:^|[,;{{]\s*){re.escape(var)}\s*=\s*\"([0-9a-fA-F]{{8,64}})\"',
                js_text,
            )
            if m_val:
                des_key = m_val.group(1)
        if not des_key and 'DES.encrypt' in js_text:
            # Fallback: longest hex literal near DES.encrypt / .ai
            cands = re.findall(r'=\s*\"([0-9a-fA-F]{16,64})\"', js_text)
            if cands:
                des_key = max(cands, key=len)
        if not des_key:
            return None
        return CryptoMaterial(
            profile_id=profile_id,
            aes_key=des_key,
            transport_style=transport or 'form_des_params_encrypted',
            extraction_method=method,
            source_label=source_label,
            extras={'des_key': des_key},
        )

    if method == 'appid_switch_literals':
        spec = doc.get('key_extraction') or {}
        switch_markers = spec.get('switch_markers') or ['getBaseInfoModel']
        texts = collect_profile_source_texts(
            profile_id,
            wrapper_file=wrapper_file,
            source_dir=source_dir,
            snippet=js_text if source_label.endswith('snippet') else '',
        )
        if not texts and js_text:
            texts = [(source_label or 'inline', js_text)]
        key_map: Dict[str, Dict[str, str]] = {}
        key_source = source_label
        for label, text in texts:
            if not any(marker in text for marker in switch_markers):
                continue
            merged = extract_appid_switch_key_map(
                text,
                field_patterns=spec.get('switch_fields') or {},
            )
            if merged:
                key_map.update(merged)
                key_source = label
        app_id, picked = _pick_appid_switch_entry(
            key_map,
            source_dir=source_dir,
            pack_dir=pack_dir,
            spec=spec,
        )
        if not picked.get('aes_key') or not picked.get('aes_iv'):
            return None
        companion_literals: Dict[str, str] = {}
        if source_dir:
            doc = load_crypto_profile_doc(profile_id)
            extraction = doc.get('key_extraction') or {}
            root = Path(source_dir)
            for pattern in extraction.get('companion_file_globs') or []:
                for path in _glob_source_files(root, pattern):
                    norm_label = str(path.relative_to(root)).replace('\\', '/')
                    if not norm_label.endswith('constants.js'):
                        continue
                    body = _read_source_text(path)
                    if body:
                        companion_literals.update(_extract_named_literals(body, spec))
        return CryptoMaterial(
            profile_id=profile_id,
            aes_key=picked.get('aes_key') or '',
            aes_iv=picked.get('aes_iv') or '',
            api_host=picked.get('base_url') or '',
            transport_style=transport or 'form_cipherh5_encrypted',
            extraction_method=method,
            source_label=key_source,
            extras={
                'app_id': app_id or '',
                'sm4_router_key': picked.get('sm4_router_key') or '',
                'secret_one': companion_literals.get('secret_one') or '',
                'app_key_map': {k: v for k, v in key_map.items()},
            },
        )

    return None


def read_wrapper_js(
    wrapper_file: str,
    *,
    source_dir: Optional[Path] = None,
    snippet: str = '',
) -> List[tuple[str, str]]:
    texts: List[tuple[str, str]] = []
    wf = (wrapper_file or '').replace('\\', '/').strip()
    if source_dir and wf:
        root = Path(source_dir)
        candidates = [root / wf]
        if '/' in wf:
            candidates.append(root / wf.split('/')[-1])
        for candidate in candidates:
            if candidate.is_file():
                texts.append((str(candidate), candidate.read_text(encoding='utf-8', errors='replace')))
                break
    if snippet and len(snippet) > 40:
        texts.append(('request_wrappers.evidence.snippet', snippet))
    return texts
