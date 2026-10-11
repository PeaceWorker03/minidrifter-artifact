# -*- coding: utf-8 -*-
from __future__ import annotations
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
import json
import re
from minidrifter.analyzers.credential import classify_credential
from minidrifter.core.utils import stable_id, tokenise_identifier, write_json, write_text
from minidrifter.optimizers.url_utils import (
    classify_url_type,
    clean_raw_url,
    host_score,
    is_engine_noise_path,
    is_frontend_route_path,
    normalize_endpoint,
    split_url,
    extract_urls_from_text,
    is_probable_url,
)
from minidrifter.quality.resolvers.host_pool import infer_host_for_path_pooled, resolve_host_pools
from minidrifter.quality.resolvers.url_role import classify_url_role
from minidrifter.optimizers.evidence import (
    enrich_source_evidence,
    infer_method_from_path,
    infer_method_from_slice,
    infer_wrapper_default_method,
    recover_params_from_slice,
)

METHODS = {'GET','POST','PUT','DELETE','PATCH','HEAD','OPTIONS'}
TOP_K_PARAM_RECOVERY = 200
SENSITIVE_RE = re.compile(r'(user|member|customer|balance|payment|pay|order|invoice|ticket|coupon|qrcode|verify|writeoff|device|vehicle|car|hicar|driver|license|idcard|rescue|account|deposit|credit|bank|phone|auth|login|session|door|lock|key|address|store|booking|price|cart)', re.I)


def is_business_operation(op: Dict[str, Any]) -> bool:
    """Business backend ops only — exclude frontend routes and non-business URL roles."""
    cls = op.get('url_classification') or {}
    if not cls.get('is_business_api'):
        return False
    if cls.get('url_type') in {'frontend_route', 'engine_or_bundle_noise', 'static_asset'}:
        return False
    ep = op.get('endpoint') or {}
    role = ep.get('url_role') or ''
    if role in {'frontend_route', 'third_party_sdk', 'telemetry'}:
        return False
    path = ep.get('path') or ep.get('original_url') or ''
    if is_frontend_route_path(path) or is_engine_noise_path(path):
        return False
    return True


def repair_business_api_pool(pack_dir) -> Dict[str, Any]:
    """Drop frontend/engine noise that leaked into business_api_operations.json."""
    from pathlib import Path

    pack_dir = Path(pack_dir)
    path = pack_dir / 'business_api_operations.json'
    if not path.exists():
        return {'changed': False, 'before': 0, 'after': 0}
    ops = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(ops, list):
        return {'changed': False, 'before': 0, 'after': 0}
    kept = [op for op in ops if is_business_operation(op)]
    changed = len(kept) != len(ops)
    if changed:
        write_json(path, kept)
    return {
        'changed': changed,
        'before': len(ops),
        'after': len(kept),
        'removed': len(ops) - len(kept),
    }


class StaticResultOptimizer:
    """Normalize, clean, deduplicate, rank and replay-plan raw MiniDrifter results.

    This layer intentionally runs *after* high-recall extraction. It does not remove raw evidence;
    it creates cleaner API operations for CWG/LLM/PoC stages.
    """
    def __init__(self, result: Dict[str, Any]):
        self.result = result
        self.profile = result.get('project_profile') or {}
        self.url_registry = result.get('url_registry') or {}
        self.api_calls = result.get('api_call_sites') or []
        self.dynamic = result.get('dynamic_api_candidates') or []
        self.crypto_cards = result.get('crypto_cards') or []
        self.wrappers = result.get('request_wrappers') or []
        self.api_cards = result.get('api_cards') or {}
        self.host_resolution: Dict[str, Any] = {}
        root = self.profile.get('project_root')
        self.project_root: Path | None = None
        if root:
            p = Path(str(root))
            if p.is_dir():
                self.project_root = p

    @staticmethod
    def load_output_dir(path: str | Path) -> Dict[str, Any]:
        p = Path(path)
        def j(name: str, default: Any):
            fp = p / name
            if not fp.exists():
                return default
            return json.loads(fp.read_text(encoding='utf-8'))
        api_cards = {
            'reached_api_cards': j('reached_api_cards.json', []),
            'registered_only_api_cards': j('registered_only_api_cards.json', []),
            'dynamic_api_cards': j('dynamic_api_cards.json', []),
            'all_api_cards': j('all_api_cards.json', []),
        }
        return {
            'project_profile': j('project_profile.json', {}),
            'page_surface': j('page_surface.json', {}),
            'events': j('events.json', []),
            'module_aliases': j('module_aliases.json', {}),
            'url_registry': j('url_registry.json', {}),
            'request_wrappers': j('request_wrappers.json', []),
            'crypto_cards': j('crypto_cards.json', []),
            'api_call_sites': j('api_call_sites.json', []),
            'dynamic_api_candidates': j('dynamic_api_candidates.json', []),
            'credential_candidates': j('credential_candidates.json', {}),
            'api_cards': api_cards,
            'replay_contracts': j('raw_replay_contracts.json', j('replay_contracts.json', [])),
        }

    def run(self) -> Dict[str, Any]:
        url_inventory = self.build_url_inventory()
        self.host_resolution = self.resolve_project_hosts(url_inventory)
        operations = self.build_normalized_operations(url_inventory)
        operations, shadow_merge = self.merge_shadow_unknown_operations(operations)
        business_ops = [op for op in operations if is_business_operation(op)]
        # Contract enrichment (method/params/headers/transforms) before ranking.
        from minidrifter.contract_enrichment import enrich_operations_for_contract, scan_project_identity_roots
        identity_roots = scan_project_identity_roots(self.project_root)
        business_ops, contract_enrichment = enrich_operations_for_contract(
            business_ops,
            api_calls=self.api_calls,
            wrappers=self.wrappers,
            project_root=self.project_root,
            identity_roots=identity_roots,
        )
        # Reflect enrichment back into full operations list for consistency.
        by_id = {op.get('operation_id'): op for op in business_ops}
        operations = [by_id.get(op.get('operation_id'), op) for op in operations]
        non_business = [u for u in url_inventory if not u.get('url_classification', {}).get('is_business_api')]
        method_inf = self.build_method_inference(operations)
        ranked = self.rank_candidates(business_ops)
        ranked = self.enrich_top_k_operations(ranked, limit=max(TOP_K_PARAM_RECOVERY, len(ranked)))
        crypto_core = self.cluster_crypto_cards()
        replay_contracts = self.build_replay_contracts(ranked, crypto_core)
        surface_shape = self.detect_surface_shape(url_inventory)
        registered_only_policy = self.build_registered_only_policy(surface_shape)
        dedup_report = self.build_dedup_report(url_inventory, operations, surface_shape, registered_only_policy)
        if shadow_merge.get('merged_shadow_unknown'):
            dedup_report['shadow_unknown_merge'] = shadow_merge
        dedup_report['contract_enrichment'] = contract_enrichment
        return {
            'url_inventory': url_inventory,
            'non_business_url_inventory': non_business,
            'host_resolution': self.host_resolution,
            'normalized_api_operations': operations,
            'business_api_operations': business_ops,
            'method_inference': method_inf,
            'ranked_api_candidates': ranked,
            'crypto_core_chains': crypto_core,
            'replay_contracts': replay_contracts,
            'dedup_report': dedup_report,
            'surface_shape': surface_shape,
            'registered_only_policy': registered_only_policy,
            'contract_enrichment': contract_enrichment,
            'top_sensitive_candidates_md': self.build_top_md(ranked),
        }

    def _enrich_inventory_item(self, item: Dict[str, Any]) -> Dict[str, Any]:
        raw_url = item.get('raw_url') or ''
        ev = enrich_source_evidence(
            self.project_root,
            raw_url,
            item.get('source'),
            item.get('url_expr'),
        )
        item['source'] = ev['source']
        item['focused_text'] = ev.get('focused_text') or ''
        item['focus_meta'] = ev.get('focus_meta') or {}
        item['recovered_params'] = ev.get('recovered_params') or []
        if item.get('surface_type') in {'embedded_literal', 'dynamic_embedded_literal'}:
            item['method'] = None
        return item

    def build_url_inventory(self) -> List[Dict[str, Any]]:
        inv: List[Dict[str, Any]] = []
        # registry entries
        for key, e in (self.url_registry.get('entries') or {}).items():
            url = e.get('resolved_url')
            if not is_probable_url(url):
                continue
            cls = classify_url_type(url, key, e.get('source', {}).get('file'))
            inv.append({
                'surface_id': stable_id('surf', 'registry', key, url, e.get('source', {}).get('file')),
                'surface_type': 'registry',
                'url_key': key,
                'raw_url': url,
                'source': e.get('source'),
                'use_count': e.get('use_count', 0),
                'url_classification': cls,
            })
        # concrete call sites
        for c in self.api_calls:
            url = c.get('resolved_url') or c.get('url_expr')
            if not url or not is_probable_url(url):
                continue
            cls = classify_url_type(url, c.get('url_key'), c.get('source', {}).get('file'))
            inv.append(self._enrich_inventory_item({
                'surface_id': stable_id('surf', 'call', c.get('api_call_id'), url),
                'surface_type': 'callsite',
                'api_call_id': c.get('api_call_id'),
                'url_key': c.get('url_key'),
                'raw_url': clean_raw_url(url),
                'method': c.get('method'),
                'callee': c.get('callee'),
                'url_expr': c.get('url_expr'),
                'data_keys': c.get('data_keys') or [],
                'header_keys': c.get('header_keys') or [],
                'description_arg': c.get('description_arg'),
                'source': c.get('source'),
                'url_classification': cls,
            }))
            # Also extract embedded endpoints from noisy long snippets or expressions.
            for eu in extract_urls_from_text(' '.join([str(c.get('url_expr') or ''), str(c.get('source', {}).get('snippet') or '')])):
                if eu == url or not is_probable_url(eu):
                    continue
                cls2 = classify_url_type(eu, c.get('url_key'), c.get('source', {}).get('file'))
                inv.append(self._enrich_inventory_item({
                    'surface_id': stable_id('surf', 'embedded', c.get('api_call_id'), eu),
                    'surface_type': 'embedded_literal',
                    'api_call_id': c.get('api_call_id'),
                    'url_key': c.get('url_key'),
                    'raw_url': clean_raw_url(eu),
                    'method': None,
                    'callee': c.get('callee'),
                    'url_expr': c.get('url_expr'),
                    'data_keys': c.get('data_keys') or [],
                    'header_keys': c.get('header_keys') or [],
                    'description_arg': c.get('description_arg'),
                    'source': c.get('source'),
                    'url_classification': cls2,
                }))
        # dynamic candidates with embedded URLs
        for c in self.dynamic:
            text = ' '.join(map(str, [c.get('url_expr') or '', c.get('source', {}).get('snippet') or '']))
            for eu in extract_urls_from_text(text):
                if not is_probable_url(eu):
                    continue
                cls = classify_url_type(eu, c.get('url_key'), c.get('source', {}).get('file'))
                inv.append(self._enrich_inventory_item({
                    'surface_id': stable_id('surf', 'dynamic', c.get('api_call_id'), eu),
                    'surface_type': 'dynamic_embedded_literal',
                    'api_call_id': c.get('api_call_id'),
                    'url_key': c.get('url_key'),
                    'raw_url': clean_raw_url(eu),
                    'method': None,
                    'callee': c.get('callee'),
                    'url_expr': c.get('url_expr'),
                    'data_keys': c.get('data_keys') or [],
                    'header_keys': c.get('header_keys') or [],
                    'description_arg': c.get('description_arg'),
                    'source': c.get('source'),
                    'url_classification': cls,
                }))
        # High-recall project path-literal scan (URL builders / config tables / concat suffixes).
        inv.extend(self._scan_project_path_literals())
        # de-dup inventory evidence-level but keep source_count.
        by_key: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
        for item in inv:
            key = (item.get('surface_type') or '', item.get('raw_url') or '', item.get('source', {}).get('file') or '')
            if key not in by_key:
                item['support_count'] = 1
                item['supporting_sources'] = [item.get('source')]
                by_key[key] = item
            else:
                by_key[key]['support_count'] += 1
                if len(by_key[key]['supporting_sources']) < 20:
                    by_key[key]['supporting_sources'].append(item.get('source'))
        return list(by_key.values())

    def _scan_project_path_literals(self) -> List[Dict[str, Any]]:
        """Recover backend API path literals from project JS (URL util / config tables).

        Complements registry/callsite recovery for apps that build URLs via string tables
        or concat suffixes (e.g. /shunke/..., /ems/search/...).
        """
        if not self.project_root or not self.project_root.is_dir():
            return []
        skip = {
            'node_modules', 'miniprogram_npm', '@babel', '@swc', 'OUTPUT',
            'CRBD_validation', 'intermediate-data', 'iconfont',
        }
        out: List[Dict[str, Any]] = []
        try:
            js_files = list(self.project_root.rglob('*.js'))
        except OSError:
            return []
        for js in js_files:
            if any(part in skip for part in js.parts):
                continue
            # Prefer source over decompile duplicates.
            if js.name.endswith('.prep.js'):
                continue
            try:
                if js.stat().st_size > 1_800_000:
                    continue
                text = js.read_text(encoding='utf-8', errors='ignore')
            except OSError:
                continue
            rel = str(js.relative_to(self.project_root)).replace('\\', '/')
            # Cap per-file extract work on huge bundles.
            if len(text) > 900_000:
                text = text[:900_000]
            for eu in extract_urls_from_text(text):
                if not is_probable_url(eu):
                    continue
                if is_frontend_route_path(eu) or is_engine_noise_path(eu):
                    continue
                cls = classify_url_type(eu, None, rel)
                if not cls.get('is_business_api') and cls.get('url_type') in {
                    'static_asset', 'telemetry_or_errorlog', 'frontend_route',
                    'engine_or_bundle_noise',
                    'third_party_or_telemetry', 'webview_h5_or_marketing', 'host_root_or_h5',
                }:
                    continue
                if not cls.get('is_business_api') and not str(eu).startswith('http'):
                    # keep only multi-segment relative paths
                    if str(eu).count('/') < 2:
                        continue
                out.append({
                    'surface_id': stable_id('surf', 'path_literal', eu, rel),
                    'surface_type': 'project_path_literal',
                    'url_key': None,
                    'raw_url': clean_raw_url(eu),
                    'source': {'file': rel, 'line': 0, 'snippet': eu[:120]},
                    'use_count': 0,
                    'url_classification': cls if cls.get('is_business_api') else {
                        **cls,
                        'is_business_api': True,
                        'noise_score': min(float(cls.get('noise_score') or 0.3), 0.3),
                        'reason': (cls.get('reason') or '') + '+path_literal_recall',
                    },
                })
        return out

    def _wrapper_scan_text(self) -> str:
        chunks: List[str] = []
        for w in self.wrappers:
            ev = w.get('evidence') or {}
            chunks.append(str(ev.get('snippet') or ''))
        if self.project_root:
            app_js = self.project_root / 'app.js'
            if app_js.exists():
                try:
                    chunks.append(app_js.read_text(encoding='utf-8', errors='replace')[:8000])
                except OSError:
                    pass
        return '\n'.join(chunks)

    def resolve_project_hosts(self, url_inventory: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Dual-pool host resolution — business_relative vs third_party_explicit."""
        host_constants = self.url_registry.get('host_constants') or {}
        pooled = resolve_host_pools(
            url_inventory,
            host_constants=host_constants,
            request_wrapper_text=self._wrapper_scan_text(),
            api_base_hosts=self.url_registry.get('api_base_hosts') or [],
        )
        pooled['schema_version'] = '1.1.0'
        pooled['resolution_framework'] = 'dual_pool_p0'
        return pooled

    def infer_host_for_path(self, raw_url: str) -> Tuple[Optional[str], Dict[str, Any]]:
        return infer_host_for_path_pooled(raw_url, self.host_resolution)

    def infer_method(self, item: Dict[str, Any]) -> Dict[str, Any]:
        surface = item.get('surface_type') or ''
        focused = ' '.join([
            str(item.get('focused_text') or ''),
            str(item.get('url_expr') or '')[:600],
            str(item.get('source', {}).get('snippet') or '')[:600],
        ])
        raw_url = item.get('raw_url') or ''
        _, path, _ = split_url(raw_url)

        from_focus = infer_method_from_slice(focused, raw_url)
        if from_focus and from_focus.get('method_confidence', 0) >= 0.88:
            return from_focus

        raw = (item.get('method') or '').upper()
        callee = (item.get('callee') or '').lower()
        if surface == 'callsite' and raw in METHODS and raw != 'UNKNOWN':
            return {'method': raw, 'method_source': 'explicit_or_extractor', 'method_confidence': 0.95}

        for m in ['get', 'post', 'put', 'delete', 'patch', 'head']:
            if callee.endswith('.' + m) or callee == m:
                return {'method': m.upper(), 'method_source': 'callee_name', 'method_confidence': 0.92}

        if from_focus:
            return from_focus

        wrapper_default = infer_wrapper_default_method(self.wrappers)
        data_keys = item.get('data_keys') or []
        if data_keys:
            return {'method': 'POST', 'method_source': 'data_payload_weak', 'method_confidence': 0.35}

        conv = infer_method_from_path(path)
        if conv and surface in {'embedded_literal', 'dynamic_embedded_literal', 'callsite', 'registry'}:
            return conv

        if wrapper_default:
            return wrapper_default

        return {'method': 'UNKNOWN', 'method_source': 'unresolved', 'method_confidence': 0.0}

    def build_normalized_operations(self, url_inventory: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        ops: Dict[str, Dict[str, Any]] = {}
        for item in url_inventory:
            cls = item.get('url_classification') or {}
            raw_url = item.get('raw_url') or ''
            if not raw_url:
                continue
            if cls.get('url_type') == 'frontend_route' or is_frontend_route_path(raw_url):
                continue
            if cls.get('url_type') in {'unknown'} and not cls.get('is_business_api'):
                # keep in inventory but do not promote unknown weak surfaces to operations.
                continue
            host, host_info = self.infer_host_for_path(raw_url)
            norm = normalize_endpoint(raw_url, host)
            role_info = classify_url_role(raw_url, inferred_host=norm.get('host'))
            norm['url_role'] = role_info.get('url_role')
            norm['host_pool'] = role_info.get('host_pool')
            norm['is_chain_eligible'] = role_info.get('is_chain_eligible')
            method_info = self.infer_method(item)
            endpoint_key = norm.get('endpoint_key')
            if not endpoint_key:
                continue
            # For operation-level de-dup, UNKNOWN should not split; but method should if known.
            op_method = method_info['method'] if method_info['method'] != 'UNKNOWN' else 'ANY'
            op_key = f'{op_method} {endpoint_key}'
            if op_key not in ops:
                ops[op_key] = {
                    'operation_id': stable_id('op', op_key),
                    'operation_key': op_key,
                    'endpoint': norm,
                    'method': method_info['method'],
                    'method_source': method_info['method_source'],
                    'method_confidence': method_info['method_confidence'],
                    'host_resolution': host_info,
                    'url_classification': cls,
                    'url_key_candidates': [],
                    'surface_types': Counter(),
                    'support_count': 0,
                    'supporting_callsites': [],
                    'supporting_sources': [],
                    'param_schema': set(),
                    'header_schema': set(),
                    'description_args': [],
                    'credential_roles': Counter(),
                    'risk_hints': set(),
                    'offset_local_evidence_count': 0,
                }
            rec = ops[op_key]
            st = item.get('surface_type') or 'unknown'
            conf = method_info['method_confidence']
            src = method_info['method_source']
            can_upgrade = conf > rec.get('method_confidence', 0)
            if can_upgrade and st in {'embedded_literal', 'dynamic_embedded_literal'}:
                if src in {'explicit_or_extractor', 'platform_default_weak'}:
                    can_upgrade = False
                elif conf < 0.88:
                    can_upgrade = False
            if can_upgrade:
                rec['method'] = method_info['method']
                rec['method_source'] = method_info['method_source']
                rec['method_confidence'] = method_info['method_confidence']
            rec['support_count'] += item.get('support_count', 1)
            rec['surface_types'][st] += 1
            if item.get('api_call_id') and len(rec['supporting_callsites']) < 50:
                rec['supporting_callsites'].append(item.get('api_call_id'))
            if item.get('source') and len(rec['supporting_sources']) < 25:
                rec['supporting_sources'].append(item.get('source'))
            if item.get('focus_meta', {}).get('strategy') == 'offset_local':
                rec.setdefault('offset_local_evidence_count', 0)
                rec['offset_local_evidence_count'] += 1
            for k in item.get('data_keys') or []:
                rec['param_schema'].add(k)
                rec['credential_roles'][classify_credential(k)] += 1
            for k in item.get('recovered_params') or []:
                rec['param_schema'].add(k)
                rec['credential_roles'][classify_credential(k)] += 1
            if item.get('url_key') and item.get('url_key') not in rec['url_key_candidates']:
                rec['url_key_candidates'].append(item.get('url_key'))
            for k in item.get('header_keys') or []:
                rec['header_schema'].add(k)
                rec['credential_roles'][classify_credential(k)] += 1
            if item.get('description_arg') and item.get('description_arg') not in rec['description_args'] and len(rec['description_args']) < 5:
                rec['description_args'].append(item.get('description_arg'))
        out: List[Dict[str, Any]] = []
        for rec in ops.values():
            rec['surface_types'] = dict(rec['surface_types'])
            rec['param_schema'] = sorted(rec['param_schema'])
            rec['header_schema'] = sorted(rec['header_schema'])
            rec['credential_roles'] = dict(rec['credential_roles'])
            if rec.get('method') == 'UNKNOWN':
                conv = infer_method_from_path(rec.get('endpoint', {}).get('path'))
                if conv:
                    rec['method'] = conv['method']
                    rec['method_source'] = conv['method_source']
                    rec['method_confidence'] = conv['method_confidence']
            rec['evidence_quality'] = self._evidence_quality(rec)
            roles = set(rec['credential_roles'].keys())
            if 'object_credential' in roles:
                rec['risk_hints'].add('subject_object_binding_required')
                rec['risk_hints'].add('object_id_replaceable_candidate')
            if 'capability_credential' in roles:
                rec['risk_hints'].add('capability_credential_generation_or_consumption')
            if 'signature_or_crypto_material' in roles:
                rec['risk_hints'].add('signature_or_crypto_replay_required')
            text = ' '.join([rec['endpoint'].get('normalized_url') or '', ' '.join(rec['url_key_candidates']), ' '.join(rec['description_args'])])
            if SENSITIVE_RE.search(text):
                rec['risk_hints'].add('sensitive_business_api')
            if rec['surface_types'].get('registry', 0) and not rec['supporting_callsites']:
                rec['risk_hints'].add('orphan_api_candidate')
            rec['risk_hints'] = sorted(rec['risk_hints'])
            rec['replay_readiness'] = self._replay_readiness(rec)
            out.append(rec)
        out.sort(key=lambda x: (-int(x.get('url_classification', {}).get('is_business_api', False)), x.get('endpoint', {}).get('endpoint_key') or ''))
        return out

    def merge_shadow_unknown_operations(
        self, operations: List[Dict[str, Any]]
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """Merge UNKNOWN ops into same-path high-confidence GET/POST; keep evidence, drop shadow card."""
        by_endpoint: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for op in operations:
            ek = (op.get('endpoint') or {}).get('endpoint_key')
            if ek:
                by_endpoint[ek].append(op)

        out: List[Dict[str, Any]] = []
        report: Dict[str, Any] = {
            'merged_shadow_unknown': 0,
            'removed_operation_ids': [],
            'affected_endpoints': [],
            'examples': [],
            'before': {
                'operation_cards': len(operations),
                'method_unknown': sum(1 for o in operations if o.get('method') == 'UNKNOWN'),
                'business_operations': sum(
                    1 for o in operations if o.get('url_classification', {}).get('is_business_api')
                ),
            },
        }

        for ek, group in by_endpoint.items():
            known = [
                o for o in group
                if o.get('method') not in ('UNKNOWN',) and float(o.get('method_confidence') or 0) >= 0.55
            ]
            unknowns = [o for o in group if o.get('method') == 'UNKNOWN']

            if known and unknowns:
                report['affected_endpoints'].append(ek)
                if len(report['examples']) < 12:
                    report['examples'].append({
                        'endpoint_key': ek,
                        'known_methods': [o.get('method') for o in known],
                        'shadow_unknown_count': len(unknowns),
                    })
                kept_ids: Set[str] = set()
                for target in known:
                    if target['operation_id'] in kept_ids:
                        continue
                    for u in unknowns:
                        target['support_count'] = target.get('support_count', 0) + u.get('support_count', 0)
                        for cs in u.get('supporting_callsites') or []:
                            if cs not in (target.get('supporting_callsites') or []):
                                target.setdefault('supporting_callsites', []).append(cs)
                        for src in u.get('supporting_sources') or []:
                            if src not in (target.get('supporting_sources') or []):
                                target.setdefault('supporting_sources', []).append(src)
                        for k in u.get('url_key_candidates') or []:
                            if k not in (target.get('url_key_candidates') or []):
                                target.setdefault('url_key_candidates', []).append(k)
                        merged_st = Counter(target.get('surface_types') or {})
                        merged_st.update(u.get('surface_types') or {})
                        target['surface_types'] = dict(merged_st)
                        merged_hints = set(target.get('risk_hints') or [])
                        merged_hints.update(u.get('risk_hints') or [])
                        target['risk_hints'] = sorted(merged_hints)
                        target.setdefault('merged_shadow_unknown_ids', []).append(u.get('operation_id'))
                        report['removed_operation_ids'].append(u.get('operation_id'))
                        report['merged_shadow_unknown'] += 1
                    target['replay_readiness'] = self._replay_readiness(target)
                    out.append(target)
                    kept_ids.add(target['operation_id'])
                for o in group:
                    if o.get('method') != 'UNKNOWN' and o['operation_id'] not in kept_ids:
                        out.append(o)
                        kept_ids.add(o['operation_id'])
            else:
                out.extend(group)

        report['after'] = {
            'operation_cards': len(out),
            'method_unknown': sum(1 for o in out if o.get('method') == 'UNKNOWN'),
            'business_operations': sum(
                1 for o in out if o.get('url_classification', {}).get('is_business_api')
            ),
        }
        return out, report

    def build_method_inference(self, operations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return [{
            'operation_id': op['operation_id'],
            'operation_key': op['operation_key'],
            'method': op['method'],
            'method_source': op['method_source'],
            'method_confidence': op['method_confidence'],
        } for op in operations]

    def rank_candidates(self, operations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        ranked = []
        for op in operations:
            url = op.get('endpoint', {}).get('normalized_url') or ''
            tokens = tokenise_identifier(' '.join([url, ' '.join(op.get('url_key_candidates') or []), ' '.join(op.get('description_args') or [])]))
            token_text = ' '.join(tokens)
            surface_types = op.get('surface_types') or {}
            embedded = int(surface_types.get('embedded_literal', 0)) + int(surface_types.get('dynamic_embedded_literal', 0))
            callsite = int(surface_types.get('callsite', 0))
            registry = int(surface_types.get('registry', 0))

            score = 0.0
            score += 18.0 if op.get('url_classification', {}).get('is_business_api') else 0.0
            score += min(8.0, op.get('support_count', 0) / 4.0)
            score += 10.0 if SENSITIVE_RE.search(token_text) else 0.0
            roles = op.get('credential_roles') or {}
            score += 14.0 if roles.get('object_credential') else 0.0
            score += 9.0 if roles.get('capability_credential') else 0.0
            score += 6.0 if roles.get('subject_credential') else 0.0
            score += 5.0 if roles.get('signature_or_crypto_material') else 0.0
            score += min(8.0, len(op.get('param_schema') or []) * 2.0)
            score += min(6.0, len(op.get('description_args') or []) * 2.0)

            eq = float(op.get('evidence_quality', {}).get('score', 0))
            score += eq
            score += min(4.0, callsite * 1.5)
            score -= min(12.0, embedded * 1.25)
            if embedded and not callsite:
                score -= 4.0

            mconf = float(op.get('method_confidence') or 0.0)
            if op.get('method') in METHODS and op.get('method') != 'UNKNOWN':
                score += 3.0
            if mconf >= 0.9:
                score += 7.0
            elif mconf >= 0.6:
                score += 3.0
            elif op.get('method') == 'UNKNOWN':
                score -= 4.0

            score += 4.0 * float(op.get('host_resolution', {}).get('confidence') or 0.0)
            if registry and not callsite and not embedded:
                score += 2.5
            score -= 10.0 * float(op.get('url_classification', {}).get('noise_score') or 0.0)
            if len(url) > 240:
                score -= 8.0

            op2 = dict(op)
            op2['rank_score'] = round(score, 3)
            op2['rank_reason'] = self._rank_reason(op2)
            ranked.append(op2)
        ranked.sort(key=lambda x: (x.get('rank_score', 0), x.get('support_count', 0)), reverse=True)
        for i, op in enumerate(ranked, start=1):
            op['rank'] = i
        return ranked

    def enrich_top_k_operations(self, ranked: List[Dict[str, Any]], limit: int = TOP_K_PARAM_RECOVERY) -> List[Dict[str, Any]]:
        if not self.project_root:
            return ranked
        for op in ranked[:limit]:
            path = op.get('endpoint', {}).get('path') or op.get('endpoint', {}).get('original_url')
            if not path:
                continue
            params = set(op.get('param_schema') or [])
            for src in op.get('supporting_sources') or []:
                ev = enrich_source_evidence(self.project_root, path, src, None)
                for k in ev.get('recovered_params') or []:
                    params.add(k)
                slice_method = infer_method_from_slice(ev.get('focused_text') or '', path)
                if slice_method and slice_method.get('method_confidence', 0) > float(op.get('method_confidence') or 0):
                    op['method'] = slice_method['method']
                    op['method_source'] = slice_method['method_source']
                    op['method_confidence'] = slice_method['method_confidence']
            if params:
                op['param_schema'] = sorted(params)
                cred = Counter()
                for k in params:
                    cred[classify_credential(k)] += 1
                op['credential_roles'] = dict(cred)
                if cred.get('object_credential'):
                    hints = set(op.get('risk_hints') or [])
                    hints.update(['subject_object_binding_required', 'object_id_replaceable_candidate'])
                    op['risk_hints'] = sorted(hints)
            op['replay_readiness'] = self._replay_readiness(op)
        return ranked

    def _evidence_quality(self, op: Dict[str, Any]) -> Dict[str, Any]:
        surface_types = op.get('surface_types') or {}
        callsite = int(surface_types.get('callsite', 0))
        embedded = int(surface_types.get('embedded_literal', 0)) + int(surface_types.get('dynamic_embedded_literal', 0))
        score = 0.0
        reasons: List[str] = []
        if callsite:
            score += 8.0
            reasons.append('has_callsite')
        if op.get('offset_local_evidence_count'):
            score += 6.0
            reasons.append('offset_local_snippet')
        if any((s.get('evidence_strategy') == 'offset_local') for s in (op.get('supporting_sources') or [])):
            score += 4.0
            reasons.append('focused_bundle_evidence')
        if embedded and not callsite:
            score -= 5.0
            reasons.append('embedded_only_penalty')
        if op.get('param_schema'):
            score += 2.0
            reasons.append('has_param_schema')
        return {'score': round(score, 3), 'reasons': reasons}

    def _replay_readiness(self, op: Dict[str, Any]) -> Dict[str, Any]:
        blockers: List[str] = []
        if op.get('method') == 'UNKNOWN':
            blockers.append('method_unresolved')
        elif float(op.get('method_confidence') or 0) < 0.6:
            blockers.append('method_low_confidence')
        host_conf = float(op.get('host_resolution', {}).get('confidence') or 0)
        if host_conf <= 0:
            blockers.append('host_unresolved')
        elif host_conf < 0.55:
            blockers.append('host_low_confidence')
        st = op.get('surface_types') or {}
        if (st.get('embedded_literal') or st.get('dynamic_embedded_literal')) and not st.get('callsite'):
            blockers.append('bundle_embedded_only')
        if op.get('credential_roles', {}).get('signature_or_crypto_material'):
            blockers.append('crypto_transform_required')
        if not op.get('param_schema') and SENSITIVE_RE.search(op.get('endpoint', {}).get('path') or ''):
            blockers.append('param_schema_empty')

        if 'host_unresolved' in blockers:
            readiness = 'blocked'
        elif blockers:
            readiness = 'partial'
        else:
            readiness = 'ready'

        next_step = 'authorized_readonly_replay'
        if readiness == 'blocked':
            next_step = 'resolve_host_or_endpoint_first'
        elif 'crypto_transform_required' in blockers:
            next_step = 'node_bridge_crypto_first'
        elif 'method_unresolved' in blockers or 'param_schema_empty' in blockers:
            next_step = 'llm_or_runtime_enrichment'

        return {
            'readiness': readiness,
            'blockers': blockers,
            'suggested_next_step': next_step,
        }

    def detect_surface_shape(self, url_inventory: List[Dict[str, Any]]) -> str:
        reg_entries = self.url_registry.get('count', len(self.url_registry.get('entries', {})))
        inv_registry = sum(1 for u in url_inventory if u.get('surface_type') == 'registry')
        inv_embedded = sum(1 for u in url_inventory if u.get('surface_type') in {'embedded_literal', 'dynamic_embedded_literal'})
        inv_callsite = sum(1 for u in url_inventory if u.get('surface_type') == 'callsite')
        if reg_entries >= 40 and inv_registry >= 30:
            return 'registry_rich'
        if inv_embedded >= max(80, inv_registry * 4) and inv_callsite < inv_embedded:
            return 'bundle_inline'
        return 'mixed'

    def build_registered_only_policy(self, surface_shape: str) -> Dict[str, Any]:
        raw_cards = self.api_cards.get('registered_only_api_cards') or []
        actionable = surface_shape == 'registry_rich'
        business_like = 0
        for c in raw_cards:
            url = (c.get('endpoint') or {}).get('resolved_url') or ''
            if c.get('url_classification', {}).get('is_business_api'):
                business_like += 1
            elif re.search(r'(1hai|Wechat/|carrctapi|/action/|/resource/)', url, re.I):
                business_like += 1
        return {
            'surface_shape': surface_shape,
            'actionable': actionable,
            'raw_count': len(raw_cards),
            'business_like_count': business_like,
            'downstream_use': 'include_in_llm_and_binding_review' if actionable else 'informational_only_ignore_for_bundle_projects',
            'note': 'Registered-only cards are meaningful only for registry-rich mini-programs.',
        }

    def _rank_reason(self, op: Dict[str, Any]) -> List[str]:
        reasons = []
        if op.get('url_classification', {}).get('is_business_api'):
            reasons.append('business_backend_api')
        if op.get('credential_roles', {}).get('object_credential'):
            reasons.append('has_object_credential')
        if op.get('credential_roles', {}).get('capability_credential'):
            reasons.append('has_capability_credential')
        if op.get('method_confidence', 0) >= 0.9:
            reasons.append('method_high_confidence')
        elif op.get('method_confidence', 0) >= 0.6:
            reasons.append('method_convention_or_medium_confidence')
        if op.get('host_resolution', {}).get('confidence', 0) >= 0.8:
            reasons.append('host_high_confidence')
        if op.get('support_count', 0) > 1:
            reasons.append('multi_source_support')
        if op.get('param_schema'):
            reasons.append('has_param_schema')
        eq = op.get('evidence_quality') or {}
        for r in eq.get('reasons') or []:
            if r in {'has_callsite', 'offset_local_snippet', 'focused_bundle_evidence'}:
                reasons.append(r)
        if (op.get('surface_types') or {}).get('embedded_literal') and not (op.get('surface_types') or {}).get('callsite'):
            reasons.append('embedded_literal_only')
        return reasons

    def cluster_crypto_cards(self) -> Dict[str, Any]:
        buckets = {'core_request_encryptors': [], 'core_header_signers': [], 'core_response_decryptors': [], 'auxiliary_crypto_candidates': []}
        seen = set()
        for c in self.crypto_cards:
            text = ' '.join(map(str, [c.get('function'), c.get('file'), c.get('operation'), c.get('stage'), c.get('algorithm_hints')]))
            key = stable_id('crypto_cluster_item', c.get('file'), c.get('function'), c.get('operation'), c.get('stage'))
            if key in seen:
                continue
            seen.add(key)
            small = {k: c.get(k) for k in ['crypto_id','file','function','direction','stage','operation','algorithm_hints','source'] if k in c}
            low = text.lower()
            if 'decrypt' in low or c.get('operation') == 'decrypt':
                buckets['core_response_decryptors'].append(small)
            elif any(x in low for x in ['authorization','appidentity','sign','md5','hmac']) or c.get('operation') in {'sign_or_header_transform','hash'}:
                buckets['core_header_signers'].append(small)
            elif any(x in low for x in ['encrypt','aes','des','rsa','base64']) or c.get('operation') == 'encrypt':
                buckets['core_request_encryptors'].append(small)
            else:
                buckets['auxiliary_crypto_candidates'].append(small)
        for k in buckets:
            buckets[k] = buckets[k][:80]
        buckets['counts'] = {k: len(v) for k, v in buckets.items() if isinstance(v, list)}
        return buckets

    def build_replay_contracts(self, ranked: List[Dict[str, Any]], crypto_core: Dict[str, Any], limit: int = 200) -> List[Dict[str, Any]]:
        contracts = []
        for op in ranked[:limit]:
            params = op.get('param_schema') or []
            headers = op.get('header_schema') or []
            mutation_points = []
            for p in params:
                role = classify_credential(p)
                if role in {'object_credential','capability_credential'}:
                    mutation_points.append({'field': p, 'role': role, 'mutate_at_stage': 'plain_stage', 'strategy': 'replace_with_owned_account_or_owned_object_value'})
            contracts.append({
                'contract_id': stable_id('replay', op.get('operation_id')),
                'operation_id': op.get('operation_id'),
                'rank': op.get('rank'),
                'rank_score': op.get('rank_score'),
                'endpoint': op.get('endpoint'),
                'method': op.get('method'),
                'method_confidence': op.get('method_confidence'),
                'host_resolution': op.get('host_resolution'),
                'replay_readiness': op.get('replay_readiness'),
                'plain_request_shape': {
                    'query_or_body_params': [{p: f'<{classify_credential(p)}>'} for p in params],
                    'headers': [{h: f'<{classify_credential(h)}>'} for h in headers],
                    'notes': 'Mutate only in the plain stage. Recompute encryption/signature/header transforms after mutation.',
                },
                'mutation_points': mutation_points,
                'request_transform_chain': {
                    'core_request_encryptors': crypto_core.get('core_request_encryptors', [])[:5],
                    'core_header_signers': crypto_core.get('core_header_signers', [])[:5],
                },
                'response_transform_chain': {
                    'core_response_decryptors': crypto_core.get('core_response_decryptors', [])[:5],
                },
                'suggested_replay_backend': 'node_bridge_reuse_original_js_first; python_port_after_transform_is_confirmed',
                'safety_policy': {
                    'mode': 'authorized_non_destructive_validation',
                    'requires_owned_accounts': True,
                    'no_mass_enumeration': True,
                    'prefer_read_only_methods_first': True,
                },
            })
        return contracts

    def build_dedup_report(
        self,
        url_inventory: List[Dict[str, Any]],
        operations: List[Dict[str, Any]],
        surface_shape: str,
        registered_only_policy: Dict[str, Any],
    ) -> Dict[str, Any]:
        raw_surfaces = len(url_inventory)
        callsite_surfaces = sum(1 for u in url_inventory if u.get('surface_type') == 'callsite')
        embedded_surfaces = sum(1 for u in url_inventory if u.get('surface_type') in {'embedded_literal', 'dynamic_embedded_literal'})
        business_surfaces = sum(1 for u in url_inventory if u.get('url_classification', {}).get('is_business_api'))
        readiness_counts = Counter((op.get('replay_readiness') or {}).get('readiness') for op in operations)
        return {
            'raw_url_surfaces': raw_surfaces,
            'raw_callsite_surfaces': callsite_surfaces,
            'embedded_literal_surfaces': embedded_surfaces,
            'business_url_surfaces': business_surfaces,
            'normalized_api_operations': len(operations),
            'business_api_operations': sum(1 for op in operations if op.get('url_classification', {}).get('is_business_api')),
            'reduction_ratio_from_raw_surfaces': round(1 - (len(operations) / raw_surfaces), 4) if raw_surfaces else 0,
            'method_counts_after_inference': dict(Counter(op.get('method') for op in operations)),
            'method_source_counts': dict(Counter(op.get('method_source') for op in operations)),
            'url_type_counts': dict(Counter(u.get('url_classification', {}).get('url_type') for u in url_inventory)),
            'surface_shape': surface_shape,
            'registered_only_policy': registered_only_policy,
            'replay_readiness_counts': dict(readiness_counts),
        }

    def build_top_md(self, ranked: List[Dict[str, Any]], n: int = 80) -> str:
        lines = ['# Top Sensitive API Candidates', '']
        lines.append('| Rank | Score | Method | Readiness | Endpoint | Roles | Reasons |')
        lines.append('|---:|---:|---|---|---|---|---|')
        for op in ranked[:n]:
            endpoint = op.get('endpoint', {}).get('normalized_url') or ''
            roles = ', '.join(k for k,v in (op.get('credential_roles') or {}).items() if v)
            reasons = ', '.join(op.get('rank_reason') or [])
            readiness = (op.get('replay_readiness') or {}).get('readiness') or '-'
            lines.append(f"| {op.get('rank')} | {op.get('rank_score')} | {op.get('method')} | {readiness} | `{endpoint}` | {roles} | {reasons} |")
        return '\n'.join(lines) + '\n'


def write_optimizer_outputs(output_dir: str | Path, opt: Dict[str, Any]) -> None:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    file_map = {
        'url_inventory.json': opt.get('url_inventory'),
        'non_business_url_inventory.json': opt.get('non_business_url_inventory'),
        'host_resolution.json': opt.get('host_resolution'),
        'normalized_api_operations.json': opt.get('normalized_api_operations'),
        'business_api_operations.json': opt.get('business_api_operations'),
        'method_inference.json': opt.get('method_inference'),
        'ranked_api_candidates.json': opt.get('ranked_api_candidates'),
        'crypto_core_chains.json': opt.get('crypto_core_chains'),
        'replay_contracts.json': opt.get('replay_contracts'),
        'dedup_report.json': opt.get('dedup_report'),
    }
    for name, data in file_map.items():
        write_json(out / name, data)
    write_text(out / 'top_sensitive_candidates.md', opt.get('top_sensitive_candidates_md') or '')
    dedup = opt.get('dedup_report') or {}
    shadow = dedup.get('shadow_unknown_merge') or {}
    if shadow.get('before') and shadow.get('after'):
        from minidrifter.core.pack_meta import unknown_merge_report_name
        write_json(out / unknown_merge_report_name(out), {
            'schema_version': '1.0.0',
            'before': shadow['before'],
            'after': shadow['after'],
            'merged_shadow_unknown': shadow.get('merged_shadow_unknown', 0),
            'affected_endpoint_count': len(shadow.get('affected_endpoints') or []),
            'examples': shadow.get('examples') or [],
            'removed_operation_ids': shadow.get('removed_operation_ids') or [],
        })
