# -*- coding: utf-8 -*-
"""Config-driven domain UNKNOWN refinement — method, side_effect, produces, workflow."""
from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

SIDE_EFFECT_MAP = {
    'S0_read_only': {'category': 'read_only', 'auto_execute_allowed': True, 'taxonomy': 'S0_read_only'},
    'S1_query_like_post': {'category': 'query_like_post', 'auto_execute_allowed': False, 'taxonomy': 'S1_query_like_post'},
    'S2_light_state_change': {'category': 'light_state_change', 'auto_execute_allowed': False, 'taxonomy': 'S2_light_state_change'},
    'S3_state_changing': {'category': 'state_changing', 'auto_execute_allowed': False, 'taxonomy': 'S3_state_changing'},
    'S4_high_risk_business_action': {'category': 'payment_related', 'auto_execute_allowed': False, 'taxonomy': 'S4_high_risk_business_action'},
}

PACKS_DIR = Path(__file__).resolve().parent / 'domain_packs'


@dataclass
class DomainPack:
    domain_id: str
    display_name: str
    default_domain_label: str
    path_include: re.Pattern[str]
    path_exclude: re.Pattern[str]
    method_rules: Dict[str, Dict[str, Any]]
    side_effect_rules: List[Dict[str, Any]]
    replay_block_patterns: List[re.Pattern[str]]
    priority_reasons: Dict[str, str]
    produces_rules: List[Tuple[re.Pattern[str], List[str]]]
    workflow: Dict[str, Any]
    raw: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def load(cls, path: Path) -> 'DomainPack':
        data = json.loads(path.read_text(encoding='utf-8'))
        method_rules = {}
        for key, rule in (data.get('method_rules') or {}).items():
            method_rules[key] = {
                **rule,
                'compiled': re.compile(rule['pattern'], re.I),
            }
        produces = [
            (re.compile(r['pattern'], re.I), list(r['fields']))
            for r in (data.get('produces_rules') or [])
        ]
        block_patterns = []
        for pat in data.get('replay_block_patterns') or []:
            if pat in method_rules:
                block_patterns.append(method_rules[pat]['compiled'])
            else:
                block_patterns.append(re.compile(pat, re.I))
        return cls(
            domain_id=data['domain_id'],
            display_name=data.get('display_name') or data['domain_id'],
            default_domain_label=data.get('default_domain_label') or data['domain_id'],
            path_include=re.compile(data['path_include'], re.I),
            path_exclude=re.compile(data['path_exclude'], re.I),
            method_rules=method_rules,
            side_effect_rules=data.get('side_effect_rules') or [],
            replay_block_patterns=block_patterns,
            priority_reasons=data.get('priority_reasons') or {},
            produces_rules=produces,
            workflow=data.get('workflow') or {},
            raw=data,
        )


def list_domain_packs() -> List[str]:
    return sorted(p.stem for p in PACKS_DIR.glob('*.json') if not p.name.startswith('_'))


def load_domain_pack(domain_id: str) -> DomainPack:
    path = PACKS_DIR / f'{domain_id}.json'
    if not path.exists():
        raise FileNotFoundError(f'domain pack not found: {domain_id} ({path})')
    return DomainPack.load(path)


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def is_domain_path(path: str, pack: DomainPack) -> bool:
    if not path or pack.path_exclude.search(path):
        return False
    return bool(pack.path_include.search(path))


def _endpoint_key(op: Dict[str, Any]) -> str:
    return (op.get('endpoint') or {}).get('endpoint_key') or ''


def _path(op: Dict[str, Any]) -> str:
    return (op.get('endpoint') or {}).get('path') or ''


def _priority_reason(path: str, pack: DomainPack) -> str:
    for key, rule in pack.method_rules.items():
        if rule['compiled'].search(path):
            return pack.priority_reasons.get(key) or pack.priority_reasons.get('default', 'domain path keyword')
    return pack.priority_reasons.get('default', 'domain path keyword')


def collect_domain_unknown_candidates(
    operations: List[Dict[str, Any]],
    pack: DomainPack,
    cards_by_id: Optional[Dict[str, Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    cards_by_id = cards_by_id or {}
    out = []
    for op in operations:
        if op.get('method') != 'UNKNOWN':
            continue
        path = _path(op)
        if not is_domain_path(path, pack):
            continue
        cid = op.get('operation_id')
        card = cards_by_id.get(cid) or {}
        domain = (
            (card.get('semantic') or {}).get('business_domain')
            or (op.get('url_classification') or {}).get('domain')
            or pack.default_domain_label
        )
        out.append({
            'operation_id': cid,
            'path': path,
            'old_method': 'UNKNOWN',
            'domain': domain,
            'domain_pack': pack.domain_id,
            'operation_semantics': (card.get('semantic') or {}).get('operation_semantics', 'unknown'),
            'evidence_sources': (op.get('supporting_sources') or [])[:5],
            'supporting_callsites': (op.get('supporting_callsites') or [])[:5],
            'surface_types': op.get('surface_types') or {},
            'priority_reason': _priority_reason(path, pack),
        })
    out.sort(key=lambda x: x['path'])
    return out


def _known_methods_on_path(endpoint_key: str, all_ops: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [
        o for o in all_ops
        if _endpoint_key(o) == endpoint_key
        and o.get('method') not in ('UNKNOWN', 'ANY')
        and float(o.get('method_confidence') or 0) >= 0.55
    ]


def _match_method_rule(path: str, pack: DomainPack) -> Optional[Dict[str, Any]]:
    for key in ('post_s4', 'post_s3', 'post_s1', 'get', 'default_post'):
        rule = pack.method_rules.get(key)
        if rule and rule['compiled'].search(path):
            return {
                'method': rule['method'],
                'method_source': rule.get('source', 'domain_path_verb_e3'),
                'method_confidence': float(rule.get('confidence', 0.6)),
                'evidence_tier': 'E3',
                'rule_key': key,
            }
    for key, rule in pack.method_rules.items():
        if key in ('post_s4', 'post_s3', 'post_s1', 'get', 'default_post'):
            continue
        if rule['compiled'].search(path):
            return {
                'method': rule['method'],
                'method_source': rule.get('source', 'domain_path_verb_e3'),
                'method_confidence': float(rule.get('confidence', 0.6)),
                'evidence_tier': 'E3',
                'rule_key': key,
            }
    return None


def infer_method_for_op(op: Dict[str, Any], all_ops: List[Dict[str, Any]], pack: DomainPack) -> Dict[str, Any]:
    path = _path(op)
    ek = _endpoint_key(op)

    known = _known_methods_on_path(ek, all_ops)
    if known:
        best = max(known, key=lambda o: float(o.get('method_confidence') or 0))
        return {
            'method': best['method'],
            'method_source': 'same_path_known_method_e1',
            'method_confidence': max(0.92, float(best.get('method_confidence') or 0.92)),
            'evidence_tier': 'E1',
        }

    st = op.get('surface_types') or {}
    if st.get('callsite') and float(op.get('method_confidence') or 0) >= 0.85:
        m = op.get('method')
        if m and m != 'UNKNOWN':
            return {
                'method': m,
                'method_source': 'callsite_evidence_e2',
                'method_confidence': float(op.get('method_confidence') or 0.85),
                'evidence_tier': 'E2',
            }

    matched = _match_method_rule(path, pack)
    if matched:
        return matched

    return {
        'method': None,
        'method_source': 'unresolved',
        'method_confidence': 0.0,
        'evidence_tier': 'none',
    }


def _side_effect_for_path(path: str, method: str, pack: DomainPack) -> Dict[str, Any]:
    rule_key = None
    for key, rule in pack.method_rules.items():
        if rule['compiled'].search(path):
            rule_key = key
            break

    for rule in pack.side_effect_rules:
        match = rule.get('match')
        if match == rule_key or match == f'method:{method}':
            tax = rule['taxonomy']
            se = SIDE_EFFECT_MAP.get(tax, SIDE_EFFECT_MAP['S1_query_like_post']).copy()
            se['inference_source'] = f'domain_refinement_{pack.domain_id}'
            return se
        also = rule.get('also_if')
        if also and re.search(also, path, re.I):
            tax = rule['taxonomy']
            se = SIDE_EFFECT_MAP.get(tax, SIDE_EFFECT_MAP['S2_light_state_change']).copy()
            se['inference_source'] = f'domain_refinement_{pack.domain_id}'
            return se
        if rule.get('default'):
            se = SIDE_EFFECT_MAP[rule['default']].copy()
            se['inference_source'] = f'domain_refinement_{pack.domain_id}'
            return se

    se = SIDE_EFFECT_MAP['S1_query_like_post'].copy()
    se['inference_source'] = f'domain_refinement_{pack.domain_id}'
    return se


def auto_replay_allowed(side_effect: Dict[str, Any], path: str, pack: DomainPack) -> bool:
    tax = side_effect.get('taxonomy') or ''
    if tax not in {'S0_read_only', 'S1_query_like_post'}:
        return False
    for pat in pack.replay_block_patterns:
        if pat.search(path):
            return False
    return side_effect.get('auto_execute_allowed', False) or tax == 'S0_read_only'


def build_produces_edges(candidates: List[Dict[str, Any]], pack: DomainPack) -> List[Dict[str, Any]]:
    edges = []
    seen: Set[Tuple[str, str]] = set()
    for c in candidates:
        path = c.get('path') or ''
        oid = c.get('operation_id')
        for pat, fields in pack.produces_rules:
            if pat.search(path):
                for fname in fields:
                    key = (oid, fname)
                    if key in seen:
                        continue
                    seen.add(key)
                    edges.append({
                        'type': 'produces',
                        'edge_type': 'produces',
                        'from_api': oid,
                        'from': oid,
                        'to_field': fname,
                        'to': fname,
                        'confidence': 0.55,
                        'evidence_level': 'static_candidate',
                        'evidence_type': f'domain_refinement_path_rule_{pack.domain_id}',
                        'domain_pack': pack.domain_id,
                        'source_material': None,
                        'phase': 'pre_baseline_candidate',
                    })
    return edges


def build_workflow_plan(
    candidates: List[Dict[str, Any]],
    patches: List[Dict[str, Any]],
    pack: DomainPack,
) -> Dict[str, Any]:
    wf = pack.workflow
    get_rule = pack.method_rules.get(wf.get('entrypoint_rule', 'get'))
    defer_rule = wf.get('deferred_rule', '')
    defer_re = re.compile(defer_rule, re.I) if defer_rule else None
    blocked_pat = wf.get('blocked_name_pattern', '')
    blocked_re = re.compile(blocked_pat, re.I) if blocked_pat else None

    patch_by_path = {p['path']: p for p in patches}
    entrypoints = []
    deferred_actions = []
    blocked = []
    first_hop_fields: Set[str] = set()

    for c in candidates:
        path = c['path']
        p = patch_by_path.get(path) or {}
        se = p.get('side_effect_taxonomy') or ''
        if get_rule and get_rule['compiled'].search(path) and se in {'S0_read_only', 'S1_query_like_post'}:
            entrypoints.append(path)
        if defer_re and defer_re.search(path):
            deferred_actions.append(path)
        if not p.get('auto_replay_allowed', False) and blocked_re and blocked_re.search(path):
            blocked.append(path.split('/')[-1].lower())

    for _, fields in pack.produces_rules:
        first_hop_fields.update(fields)

    return {
        'schema_version': '1.0.0',
        'domain_id': pack.domain_id,
        'generated_at': _utc_now(),
        'entrypoints': sorted(set(entrypoints))[:20],
        'first_hop_fields': sorted(first_hop_fields),
        'deferred_actions': sorted(set(deferred_actions))[:25],
        'blocked_for_auto_replay': sorted(set(blocked)),
        'workflow_chain': wf.get('chain') or [],
    }


def apply_domain_patches(
    operations: List[Dict[str, Any]],
    cards: List[Dict[str, Any]],
    pack: DomainPack,
    *,
    dry_run: bool = False,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any]]:
    cards_by_id = {c['card_id']: c for c in cards if c.get('card_id')}
    candidates = collect_domain_unknown_candidates(operations, pack, cards_by_id)

    patches: List[Dict[str, Any]] = []
    op_by_id = {o['operation_id']: o for o in operations if o.get('operation_id')}

    for cand in candidates:
        op = op_by_id.get(cand['operation_id'])
        if not op:
            continue
        minfo = infer_method_for_op(op, operations, pack)
        if not minfo.get('method'):
            patches.append({**cand, 'patched': False, 'still_unknown': True})
            continue

        method = minfo['method']
        side = _side_effect_for_path(cand['path'], method, pack)
        replay_ok = auto_replay_allowed(side, cand['path'], pack)

        patch = {
            **cand,
            'patched': True,
            'new_method': method,
            'method_source': minfo['method_source'],
            'method_confidence': minfo['method_confidence'],
            'evidence_tier': minfo['evidence_tier'],
            'side_effect_taxonomy': side.get('taxonomy'),
            'side_effect_category': side.get('category'),
            'auto_replay_allowed': replay_ok,
        }
        patches.append(patch)

        if dry_run:
            continue

        op['method'] = method
        op['method_source'] = minfo['method_source']
        op['method_confidence'] = minfo['method_confidence']
        op['domain_refinement'] = {
            'domain_id': pack.domain_id,
            'evidence_tier': minfo['evidence_tier'],
            'patched_at': _utc_now(),
        }
        op['replay_readiness'] = _replay_readiness_after_patch(op, side, pack.domain_id)

        card = cards_by_id.get(cand['operation_id'])
        if card and (card.get('provenance') or {}).get('card_kind') == 'operation':
            http = (card.setdefault('static', {})).setdefault('http', {})
            http['method'] = method
            http['method_trust_tier'] = 'high' if minfo['evidence_tier'] == 'E1' else (
                'medium' if minfo['evidence_tier'] == 'E3' else 'low'
            )
            replay = card.setdefault('replay', {})
            replay['side_effect'] = {
                'category': side['category'],
                'auto_execute_allowed': replay_ok,
                'inference_source': side['inference_source'],
                'taxonomy': side.get('taxonomy'),
            }
            card.setdefault('ranking', {})['domain_refinement'] = pack.domain_id

    produces = build_produces_edges(candidates, pack)
    workflow = build_workflow_plan(candidates, patches, pack)

    patched_ok = [p for p in patches if p.get('patched')]
    report = {
        'schema_version': '1.0.0',
        'domain_id': pack.domain_id,
        'generated_at': _utc_now(),
        'total_unknown_candidates': len(candidates),
        'method_resolved': len(patched_ok),
        'side_effect_labeled': len(patched_ok),
        'deferred_workflow_objects_added': len(produces),
        'auto_replay_allowed': sum(1 for p in patched_ok if p.get('auto_replay_allowed')),
        'auto_replay_blocked_by_side_effect': sum(1 for p in patched_ok if not p.get('auto_replay_allowed')),
        'still_unknown': sum(1 for p in patches if not p.get('patched')),
        'evidence_tier_histogram': dict(Counter(p.get('evidence_tier') for p in patched_ok)),
        'side_effect_histogram': dict(Counter(p.get('side_effect_taxonomy') for p in patched_ok)),
        'samples': patched_ok[:12],
    }

    return operations, cards, patches, {
        'patch_report': report,
        'workflow_plan': workflow,
        'produces_edges': produces,
        'candidates': candidates,
    }


def _replay_readiness_after_patch(op: Dict[str, Any], side: Dict[str, Any], domain_id: str) -> Dict[str, Any]:
    blockers = []
    if op.get('method') == 'UNKNOWN':
        blockers.append('method_unresolved')
    if side.get('taxonomy') in {'S3_state_changing', 'S4_high_risk_business_action'}:
        blockers.append('side_effect_too_high_for_auto_replay')
    if op.get('credential_roles', {}).get('signature_or_crypto_material'):
        blockers.append('crypto_transform_required')
    readiness = 'partial' if blockers else 'ready'
    return {'readiness': readiness, 'blockers': blockers, 'next_step': f'domain_refinement_patched_{domain_id}'}


def run_domain_refinement(
    output_dir: Path,
    *,
    domain_ids: Optional[List[str]] = None,
    dry_run: bool = False,
    write_candidates: bool = True,
) -> Dict[str, Any]:
    output_dir = Path(output_dir)
    ops = json.loads((output_dir / 'business_api_operations.json').read_text(encoding='utf-8'))
    cards = json.loads((output_dir / 'api_cards.json').read_text(encoding='utf-8'))

    domain_ids = domain_ids or list_domain_packs()
    before_unknown = sum(1 for o in ops if o.get('method') == 'UNKNOWN')

    per_domain: Dict[str, Any] = {}
    all_produces: List[Dict[str, Any]] = []

    for did in domain_ids:
        pack = load_domain_pack(did)
        before_domain = len(collect_domain_unknown_candidates(
            ops, pack, {c['card_id']: c for c in cards if c.get('card_id')}
        ))
        ops, cards, patches, extras = apply_domain_patches(ops, cards, pack, dry_run=dry_run)
        after_domain = sum(1 for p in patches if not p.get('patched'))

        per_domain[did] = {
            'before_unknown': before_domain,
            'still_unknown': after_domain,
            'patch_report': extras['patch_report'],
        }
        all_produces.extend(extras['produces_edges'])

        if not dry_run:
            from minidrifter.core.utils import write_json
            write_json(output_dir / f'{did}_unknown_candidates.json', extras['candidates'])
            write_json(output_dir / f'{did}_unknown_patch_report.json', extras['patch_report'])
            write_json(output_dir / f'{did}_workflow_plan.json', extras['workflow_plan'])
            write_json(output_dir / f'{did}_produces_edges.json', {
                'schema_version': '1.0.0',
                'domain_id': did,
                'generated_at': _utc_now(),
                'edges': extras['produces_edges'],
            })
        elif write_candidates:
            from minidrifter.core.utils import write_json as wj
            wj(output_dir / f'{did}_unknown_candidates.json', extras['candidates'])

    after_unknown = sum(1 for o in ops if o.get('method') == 'UNKNOWN')

    summary = {
        'schema_version': '1.0.0',
        'generated_at': _utc_now(),
        'domains_run': domain_ids,
        'before_method_unknown': before_unknown,
        'after_method_unknown': after_unknown,
        'per_domain': per_domain,
        'total_produces_edges': len(all_produces),
        'dry_run': dry_run,
    }

    if not dry_run:
        from minidrifter.core.utils import write_json
        write_json(output_dir / 'business_api_operations.json', ops)
        write_json(output_dir / 'api_cards.json', cards)
        write_json(output_dir / 'domain_refinement_report.json', summary)

    return summary
