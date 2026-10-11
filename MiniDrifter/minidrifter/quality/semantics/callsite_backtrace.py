# -*- coding: utf-8 -*-
"""P3: Obfuscation-tolerant callsite → page backtrace (webpack/sub-common/bundle)."""
from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from minidrifter.core.utils import normalize_rel, read_text
from minidrifter.materials.intake_param_hints import normalize_api_path
from minidrifter.optimizers.evidence import enrich_source_evidence, is_bundle_source
from minidrifter.quality.semantics.path_tokens import infer_path_semantic, page_token_overlap

CHUNK_PUSH_RE = re.compile(r'push\s*\(\s*\[\s*(\d+)\s*\]', re.I)
CHUNK_ARRAY_RE = re.compile(r'\[\s*(\d+)\s*\]')
SUB_COMMON_RE = re.compile(r'sub-common/([a-f0-9]{8,})\.js', re.I)
WEBPACK_DEPS_RE = re.compile(r'\.O\s*\(\s*0\s*,\s*\[([^\]]+)\]', re.I)
REQUIRE_SUBCOMMON_RE = re.compile(
    r'require\s*\(\s*["\'][./]*sub-common/([a-f0-9]{8,})\.js["\']\s*\)',
    re.I,
)
PAGE_PATH_RE = re.compile(r'((?:pages|package|third-platform)/[\w./-]+?)(?:\.js)?$')

EVIDENCE_WEIGHTS_P3 = {
    'api_call_site_direct': 0.95,
    'registry_callsite_source': 0.90,
    'chunk_require_backtrace': 0.82,
    'chunk_id_backtrace': 0.78,
    'offset_local_snippet': 0.80,
    'demand_graph_callsite_soft': 0.72,
    'obfuscated_callsite_soft': 0.65,
}

BUNDLE_MARKERS = ('sub-common/', 'vendors.js', 'common.js', 'taro.js', 'webpack')


def _load_json(path: Path) -> Any:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding='utf-8'))


def project_root_from_pack(pack_dir: Path) -> Optional[Path]:
    prof = _load_json(pack_dir / 'project_profile.json') or {}
    root = prof.get('project_root')
    if root and Path(root).is_dir():
        return Path(root)
    return None


def is_obfuscated_callsite_source(source: Optional[Dict[str, Any]]) -> bool:
    if not source:
        return False
    if is_bundle_source(source):
        return True
    fpath = (source.get('file') or '').replace('\\', '/').lower()
    return any(m in fpath for m in BUNDLE_MARKERS)


def page_id_from_file_path(fpath: str) -> Optional[str]:
    fpath = (fpath or '').replace('\\', '/')
    if '/pages/' not in fpath and not fpath.startswith('pages/'):
        if '/package/' not in fpath and not fpath.startswith('package/'):
            if '/third-platform/' not in fpath:
                return None
    m = PAGE_PATH_RE.search(fpath.rsplit('.', 1)[0])
    return m.group(1).rstrip('/') if m else None


def extract_callsite_signals(call: Dict[str, Any]) -> Dict[str, Any]:
    source = call.get('source') or {}
    blob = ' '.join([
        str(call.get('url_expr') or '')[:2000],
        str(source.get('snippet') or '')[:800],
        str(source.get('file') or ''),
    ])
    chunk_id = None
    m = CHUNK_PUSH_RE.search(blob)
    if m:
        chunk_id = m.group(1)
    else:
        m2 = CHUNK_ARRAY_RE.search(blob)
        if m2:
            chunk_id = m2.group(1)
    sub_hash = None
    sm = SUB_COMMON_RE.search(str(source.get('file') or ''))
    if sm:
        sub_hash = sm.group(1)
    return {
        'chunk_id': chunk_id,
        'sub_common_hash': sub_hash,
        'obfuscated': is_obfuscated_callsite_source(source),
        'url_key': call.get('url_key'),
        'resolved_url': call.get('resolved_url'),
    }


class ChunkPageIndex:
    """Scan page JS files for webpack sub-common require() and chunk dependency arrays."""

    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.hash_to_pages: Dict[str, List[str]] = {}
        self.chunk_to_pages: Dict[str, List[str]] = {}
        self._built = False

    def build(self) -> None:
        if self._built:
            return
        for js in self.project_root.rglob('*.js'):
            rel = normalize_rel(js, self.project_root).replace('\\', '/')
            if '/pages/' not in rel and not rel.startswith('pages/'):
                if '/third-platform/pages/' not in rel:
                    continue
            page_id = page_id_from_file_path(rel)
            if not page_id:
                continue
            try:
                text = read_text(js)
            except OSError:
                continue
            for hm in REQUIRE_SUBCOMMON_RE.finditer(text):
                self.hash_to_pages.setdefault(hm.group(1), [])
                if page_id not in self.hash_to_pages[hm.group(1)]:
                    self.hash_to_pages[hm.group(1)].append(page_id)
            for dm in WEBPACK_DEPS_RE.finditer(text):
                for cid in re.findall(r'\d+', dm.group(1)):
                    self.chunk_to_pages.setdefault(cid, [])
                    if page_id not in self.chunk_to_pages[cid]:
                        self.chunk_to_pages[cid].append(page_id)
        self._built = True


@lru_cache(maxsize=8)
def _get_chunk_index(project_root: str) -> ChunkPageIndex:
    idx = ChunkPageIndex(Path(project_root))
    idx.build()
    return idx


def _registry_page_for_call(
    call: Dict[str, Any],
    pack_dir: Path,
    norm_api: str,
) -> Optional[str]:
    registry = _load_json(pack_dir / 'url_registry.json') or {}
    entries = registry.get('entries') or {}
    url_key = call.get('url_key')
    if url_key and url_key in entries:
        src = (entries[url_key].get('source') or {})
        pg = page_id_from_file_path(str(src.get('file') or ''))
        if pg:
            return pg
    for _k, entry in entries.items():
        resolved = normalize_api_path(entry.get('resolved_url') or '')
        if resolved and (resolved == norm_api or norm_api in resolved):
            src = entry.get('source') or {}
            pg = page_id_from_file_path(str(src.get('file') or ''))
            if pg:
                return pg
    return None


def collect_callsite_page_candidates(
    call: Dict[str, Any],
    *,
    pack_dir: Path,
    norm_api: str,
    semantic: Dict[str, Any],
    project_root: Optional[Path] = None,
) -> List[Tuple[float, str, str, Dict[str, Any]]]:
    """Generic obfuscation-tolerant callsite → page candidates."""
    out: List[Tuple[float, str, str, Dict[str, Any]]] = []
    source = call.get('source') or {}
    signals = extract_callsite_signals(call)

    direct = page_id_from_file_path(str(source.get('file') or ''))
    if direct:
        w = EVIDENCE_WEIGHTS_P3['api_call_site_direct']
        if page_token_overlap(direct, semantic) >= 0.35:
            w += 0.05
        out.append((w, direct, 'api_call_site_direct', {'file': source.get('file')}))

    reg_page = _registry_page_for_call(call, pack_dir, norm_api)
    if reg_page:
        out.append((EVIDENCE_WEIGHTS_P3['registry_callsite_source'], reg_page, 'registry_callsite_source', {}))

    root = project_root or project_root_from_pack(pack_dir)
    if root and root.is_dir():
        idx = _get_chunk_index(str(root.resolve()))
        if signals.get('sub_common_hash'):
            for pg in idx.hash_to_pages.get(signals['sub_common_hash'], []):
                ov = page_token_overlap(pg, semantic)
                if ov >= 0.30:
                    conf = EVIDENCE_WEIGHTS_P3['chunk_require_backtrace'] + 0.15 * ov
                    out.append((conf, pg, 'chunk_require_backtrace', {
                        'hash': signals['sub_common_hash'], 'overlap': ov,
                    }))
        if signals.get('chunk_id'):
            for pg in idx.chunk_to_pages.get(signals['chunk_id'], []):
                ov = page_token_overlap(pg, semantic)
                if ov >= 0.28:
                    conf = EVIDENCE_WEIGHTS_P3['chunk_id_backtrace'] + 0.12 * ov
                    out.append((conf, pg, 'chunk_id_backtrace', {
                        'chunk_id': signals['chunk_id'], 'overlap': ov,
                    }))
        ev = enrich_source_evidence(
            root,
            call.get('resolved_url'),
            source,
            call.get('url_expr'),
        )
        focus_meta = ev.get('focus_meta') or {}
        resolved_file = str(focus_meta.get('resolved_file') or '')
        if resolved_file:
            rel = normalize_rel(Path(resolved_file), root).replace('\\', '/')
            pg = page_id_from_file_path(rel)
            if pg:
                out.append((EVIDENCE_WEIGHTS_P3['offset_local_snippet'], pg, 'offset_local_snippet', {
                    'strategy': focus_meta.get('strategy'),
                }))

    if signals.get('obfuscated') and not any(c[2].startswith('chunk_') for c in out):
        fpath = str(source.get('file') or '')
        pseudo = page_id_from_file_path(fpath)
        if pseudo and '/sub-common/' not in pseudo:
            ov = page_token_overlap(pseudo, semantic)
            if ov >= 0.25:
                out.append((EVIDENCE_WEIGHTS_P3['obfuscated_callsite_soft'], pseudo, 'obfuscated_callsite_soft', {
                    'overlap': ov,
                }))
        elif '/sub-common/' in fpath or '/common.js' in fpath.lower():
            out.append((0.30, fpath, 'bundle_only_callsite', {
                'reachable_page': None,
                'unresolved_bundle_callsite': True,
            }))

    return out


def url_matches_api(url: str, norm_path: str, tokens: set) -> bool:
    if not url or len(url) < 8:
        return False
    if url == norm_path or norm_path in url:
        return True
    tail = norm_path.rsplit('/', 1)[-1]
    if tail and len(tail) > 2 and tail in url:
        return True
    matched = sum(1 for t in tokens if len(t) > 3 and t in url)
    return matched >= 2


def resolve_page_via_callsite_backtrace(
    pack_dir: Path,
    api_path: str,
    *,
    api_id: Optional[str] = None,
    semantic: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    """P3 entry: resolve page from obfuscated callsites when path hints fail."""
    pack_dir = Path(pack_dir)
    norm = normalize_api_path(api_path)
    semantic = semantic or infer_path_semantic(api_path)
    tokens = set(semantic.get('path_tokens') or [])
    candidates: List[Tuple[float, str, str, Dict[str, Any]]] = []

    calls = _load_json(pack_dir / 'api_call_sites.json') or []
    if isinstance(calls, dict):
        calls = calls.get('api_call_sites') or calls.get('calls') or []

    project_root = project_root_from_pack(pack_dir)
    for call in calls:
        url = normalize_api_path((call.get('resolved_url') or call.get('url') or '').split('?', 1)[0])
        if not url_matches_api(url, norm, tokens):
            continue
        candidates.extend(collect_callsite_page_candidates(
            call, pack_dir=pack_dir, norm_api=norm, semantic=semantic, project_root=project_root,
        ))

    if api_id:
        full = _load_json(pack_dir / 'runtime_demand_graph.full.json') or {}
        for edge in full.get('edges') or []:
            if edge.get('from_api') != api_id and edge.get('from') != api_id:
                continue
            for ref in edge.get('evidence_refs') or []:
                if not isinstance(ref, str) or not ref.startswith('callsite:'):
                    continue
                m = re.search(r'((?:pages|package|third-platform)/[^:]+)\.js', ref.replace('\\', '/'))
                if m:
                    pg = m.group(1)
                    ov = page_token_overlap(pg, semantic)
                    if ov >= 0.30:
                        candidates.append((
                            EVIDENCE_WEIGHTS_P3['demand_graph_callsite_soft'] + 0.1 * ov,
                            pg, 'demand_graph_callsite_soft', {'overlap': ov},
                        ))

    if not candidates:
        return None
    candidates.sort(key=lambda x: x[0], reverse=True)
    best_score, page, evidence, meta = candidates[0]
    return {
        'page': page,
        'evidence': evidence,
        'confidence': round(min(best_score, 0.99), 2),
        'evidence_meta': meta,
        'graded': True,
        'p3_backtrace': True,
    }
