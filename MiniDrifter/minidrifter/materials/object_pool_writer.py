# -*- coding: utf-8
"""Persist harvested objects and build baseline_unlock_matrix for downstream schedulers."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from minidrifter.business_chain.chain_semantic_scorer import field_binding_risk_tier
from minidrifter.core.utils import write_json
from minidrifter.graph.semantic_workflow_graph import infer_domain_from_path
from minidrifter.materials.intake_param_hints import normalize_api_path
from minidrifter.materials.object_harvester import (
    harvest_objects_from_captures,
    merge_harvest_into_aggregate,
)

SCHEMA_VERSION = '1.0.0'


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _load_json(path: Path) -> Any:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding='utf-8'))


def pool_has(field: str, pool: Set[str], values: Dict[str, Any]) -> bool:
    if not field:
        return True
    if field in pool or field in values:
        return True
    fl = field.lower()
    if fl in {k.lower() for k in pool}:
        return True
    try:
        from minidrifter.classification.sensitive_field_normalizer import pool_has_canonical
        if pool_has_canonical(field, pool, values):
            return True
    except Exception:
        pass
    aliases = {
        'userid': {'uid', 'userid', 'user_id', 'memberid'},
        'openid': {'openid', 'open_id'},
        'orderid': {'orderid', 'order_id'},
        'phone': {'phone', 'mobile'},
        'taskid': {'taskid', 'task_id'},
    }
    for alt in aliases.get(fl, set()):
        if alt in {k.lower() for k in pool} or alt in {k.lower() for k in values}:
            return True
    return False


def load_baseline_field_pool(pack_dir: Path) -> Dict[str, Any]:
    """Unified field pool: runtime context + intake aggregate + object_pool."""
    pack_dir = Path(pack_dir)
    ctx = _load_json(pack_dir / 'baseline_runtime_context.json') or {}
    intake = _load_json(pack_dir / 'baseline_intake_report.json') or {}
    obj_doc = _load_json(pack_dir / 'object_pool.json') or {}
    agg = (intake.get('decrypted_fields_aggregate') or {}).get('fields') or {}
    harvest = intake.get('harvested_objects') or {}
    values: Dict[str, Any] = {}
    sources: Dict[str, str] = {}

    for k, ent in (ctx.get('resolved_fields') or {}).items():
        if isinstance(ent, dict) and ent.get('value') not in (None, ''):
            values[k] = ent['value']
            sources[k] = ent.get('source') or 'baseline_runtime_context'
    for k, v in agg.items():
        if v not in (None, '') and k not in values:
            values[k] = v
            sources[k] = 'decrypted_fields_aggregate'
    for k, v in (harvest.get('fields') or {}).items():
        if v not in (None, '') and k not in values:
            values[k] = v
            sources[k] = (harvest.get('field_sources') or {}).get(k, 'object_harvester')
    for obj in obj_doc.get('objects') or []:
        f = obj.get('field')
        v = obj.get('value')
        if f and v not in (None, '') and f not in values:
            values[f] = v
            src = obj.get('source') or {}
            sources[f] = f"{src.get('capture', '')}::{src.get('api', '')}::{src.get('response_path', '')}"

    return {
        'fields': values,
        'field_names': set(values.keys()),
        'sources': sources,
        'objects': obj_doc.get('objects') or harvest.get('objects') or [],
    }


def enrich_intake_with_object_harvest(
    intake_report: Dict[str, Any],
    *,
    pack_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    """Run harvest on captures and merge into decrypted_fields_aggregate."""
    captures = intake_report.get('captures') or []
    harvest = harvest_objects_from_captures(captures, pack_dir=pack_dir)
    intake_report['harvested_objects'] = harvest
    agg = intake_report.get('decrypted_fields_aggregate') or {'fields': {}, 'sources': {}}
    intake_report['decrypted_fields_aggregate'] = merge_harvest_into_aggregate(agg, harvest)
    return intake_report


def merge_harvest_into_runtime_context(
    ctx: Dict[str, Any],
    harvest: Dict[str, Any],
) -> Dict[str, Any]:
    resolved = dict(ctx.get('resolved_fields') or {})
    for k, v in (harvest.get('fields') or {}).items():
        if v in (None, ''):
            continue
        if k in resolved and resolved[k].get('value') == v:
            continue
        src = (harvest.get('field_sources') or {}).get(k, 'object_harvester')
        resolved[k] = {
            'value': str(v),
            'source': src,
            'status': 'resolved_via_object_harvest',
        }
    ctx['resolved_fields'] = resolved
    ctx['field_count'] = len(resolved)
    ctx['object_harvest_count'] = harvest.get('object_count', 0)
    return ctx


_POOL_OBJECT_PATH_HINTS: Dict[str, Tuple[str, ...]] = {
    'orderId': ('orderdetail', 'cardorder', 'cancelconfirm', 'routing', 'returnedorder'),
    'taskId': ('pickuptask', 'deposit/task', 'task/'),
    'deptId': ('deptdetail', 'deptguidedetail', 'querydept', 'listandmap'),
    'memberId': ('memberidentity', 'identitycard'),
}


def _pool_unlocked_materialized_apis(pack_dir: Path, pool: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Materialized replay-ready APIs unlocked by current object pool (beyond static risk list)."""
    pack_dir = Path(pack_dir)
    tmpl_doc = _load_json(pack_dir / 'materialized_api_templates.json') or {}
    values = pool['fields']
    field_names = pool['field_names']
    out: List[Dict[str, Any]] = []
    seen: Set[str] = set()

    for row in tmpl_doc.get('ready_for_replay') or []:
        if row.get('status') != 'materialized_with_crypto_profile':
            continue
        path = normalize_api_path(row.get('path') or '')
        api_id = row.get('api_id') or ''
        if not path or path in seen:
            continue
        low = path.lower()
        required: List[str] = []
        skip = False
        for field, hints in _POOL_OBJECT_PATH_HINTS.items():
            if not any(h in low for h in hints):
                continue
            if not pool_has(field, field_names, values):
                skip = True
                break
            required.append(field)
        if skip or not required:
            continue
        seen.add(path)
        domain = infer_domain_from_path(path)
        out.append({
            'api': path,
            'api_id': api_id,
            'domain': domain,
            'required_objects': required,
            'status': 'pool_unlocked_materialized',
            'satisfied_by': {f: pool['sources'].get(f) for f in required if f in values},
            'rule_score': 72.0,
            'materialized': True,
            'replay_ready': True,
            'probe_eligible': True,
            'source': 'object_pool_materialized',
        })
    out.sort(key=lambda x: -(x.get('rule_score') or 0))
    return out


def build_baseline_unlock_matrix(pack_dir: Path) -> Dict[str, Any]:
    """Runnable/blocked chains and probe APIs from unified object pool."""
    pack_dir = Path(pack_dir)
    pool = load_baseline_field_pool(pack_dir)
    values = pool['fields']
    field_names = pool['field_names']

    chains_doc = _load_json(pack_dir / 'business_chains.json') or {}
    rank_doc = _load_json(pack_dir / 'chain_rank_plan.json') or {}
    risk_doc = _load_json(pack_dir / 'binding_risk_candidates.json') or {}
    cards_ir = _load_json(pack_dir / 'universal_ir' / 'universal_api_cards.json') or {}
    cards_by_path = {}
    for card in (cards_ir.get('items') or cards_ir.get('cards') or []):
        p = normalize_api_path(card.get('path') or '')
        if p:
            cards_by_path[p] = card

    chains_by_id = {c['chain_id']: c for c in (chains_doc.get('chains') or []) if c.get('chain_id')}
    ranked_ids = [r.get('chain_id') for r in (rank_doc.get('top_chains') or []) if r.get('chain_id')]

    def _chain_required_fields(chain: Dict[str, Any]) -> List[str]:
        return list(dict.fromkeys(
            (chain.get('binding_fields') or [])
            + (chain.get('objects') or [])
            + (chain.get('primary_mutation_targets') or [])
        ))

    runnable: List[Dict[str, Any]] = []
    blocked: List[Dict[str, Any]] = []
    seen_chain: Set[str] = set()

    for cid in ranked_ids + [c for c in chains_by_id if c not in ranked_ids]:
        if cid in seen_chain:
            continue
        seen_chain.add(cid)
        chain = chains_by_id.get(cid)
        if not chain:
            continue
        req = _chain_required_fields(chain)
        missing = [f for f in req if not pool_has(f, field_names, values)]
        domain = chain.get('domain') or infer_domain_from_path(chain.get('entry_path') or '')
        target = normalize_api_path(chain.get('target_path') or '')
        entry = normalize_api_path(chain.get('entry_path') or '')
        satisfied = {
            f: pool['sources'].get(f) or values.get(f)
            for f in req if f in values or pool_has(f, field_names, values)
        }
        row = {
            'chain_id': cid,
            'domain': domain,
            'entry_api': entry,
            'entry_path': chain.get('entry_path'),
            'consumer_api': target,
            'target_path': chain.get('target_path'),
            'required_objects': req,
            'risk_tier': chain.get('binding_risk_tier') or field_binding_risk_tier(req[0] if req else ''),
            'hop_count': len(chain.get('hops') or []),
        }
        if missing:
            blocked.append({
                **row,
                'status': 'blocked',
                'missing_fields': missing,
            })
        else:
            runnable.append({
                **row,
                'status': 'runnable',
                'satisfied_by': satisfied,
            })

    unlocked_probes: List[Dict[str, Any]] = []
    blocked_probes: List[Dict[str, Any]] = []
    for cand in (risk_doc.get('candidates') or []):
        if not cand.get('probe_eligible'):
            continue
        path = normalize_api_path(cand.get('path') or '')
        domain = infer_domain_from_path(path)
        id_fields: List[str] = []
        for sig in cand.get('risk_signals') or []:
            if isinstance(sig, str) and sig.startswith('identity_params:'):
                id_fields.extend(x.strip() for x in sig.split(':', 1)[1].split(',') if x.strip())
        card = cards_by_path.get(path) or {}
        for p in card.get('params') or []:
            name = p.get('name') if isinstance(p, dict) else None
            if name and name.endswith('Id') or (name and name.lower().endswith('id')):
                id_fields.append(name)
        id_fields = list(dict.fromkeys(id_fields))
        if domain == 'order' and not id_fields:
            id_fields = ['orderId']
        missing = [f for f in id_fields if not pool_has(f, field_names, values)]
        row = {
            'api': path,
            'api_id': cand.get('api_id'),
            'domain': domain,
            'required_objects': id_fields,
            'rule_score': cand.get('rule_score'),
            'verification_intent': cand.get('verification_intent'),
        }
        if missing:
            blocked_probes.append({**row, 'status': 'blocked', 'missing_fields': missing})
        else:
            unlocked_probes.append({**row, 'status': 'probe_eligible', 'satisfied_by': {
                f: pool['sources'].get(f) for f in id_fields if f in values
            }})

    domain_gaps: Dict[str, Dict[str, Any]] = {}
    for row in blocked:
        dom = row.get('domain') or 'general'
        miss = row.get('missing_fields') or []
        blob = domain_gaps.setdefault(dom, {'missing_fields': set(), 'chains': 0, 'chain_ids': []})
        blob['missing_fields'].update(miss)
        blob['chains'] += 1
        blob['chain_ids'].append(row.get('chain_id'))
    for row in blocked_probes:
        dom = row.get('domain') or 'general'
        miss = row.get('missing_fields') or []
        blob = domain_gaps.setdefault(dom, {'missing_fields': set(), 'chains': 0, 'blocked_apis': []})
        blob['missing_fields'].update(miss)
        blob.setdefault('blocked_apis', []).append(row.get('api'))

    deferred_gaps: List[Dict[str, Any]] = []
    for dom, blob in sorted(domain_gaps.items(), key=lambda x: -x[1].get('chains', 0)):
        fields = sorted(blob.get('missing_fields') or [])
        if not fields:
            continue
        deferred_gaps.append({
            'domain': dom,
            'missing_fields': fields,
            'estimated_unlock': {
                'chains': blob.get('chains', 0),
                'high_risk_apis': len(blob.get('blocked_apis') or []),
            },
            'blocked_apis': (blob.get('blocked_apis') or [])[:8],
            'sample_chain_ids': (blob.get('chain_ids') or [])[:6],
        })

    pool_unlocked = _pool_unlocked_materialized_apis(pack_dir, pool)

    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': _utc_now(),
        'pack_dir': str(pack_dir),
        'pool_field_count': len(values),
        'pool_object_count': len(pool.get('objects') or []),
        'summary': {
            'runnable_chain_count': len(runnable),
            'blocked_chain_count': len(blocked),
            'unlocked_probe_count': len(unlocked_probes),
            'pool_unlocked_materialized_count': len(pool_unlocked),
            'blocked_probe_count': len(blocked_probes),
            'deferred_domain_count': len(deferred_gaps),
        },
        'runnable_chains': runnable[:80],
        'blocked_chains': blocked[:40],
        'unlocked_probe_apis': unlocked_probes[:40],
        'pool_unlocked_materialized_apis': pool_unlocked[:30],
        'blocked_probe_apis': blocked_probes[:40],
        'deferred_material_gaps': deferred_gaps,
    }


def write_baseline_object_artifacts(
    pack_dir: Path,
    intake_report: Dict[str, Any],
    ctx: Optional[Dict[str, Any]] = None,
) -> Dict[str, str]:
    """Write object_pool.json, aggregate_materials.json, unlock matrix; update ctx."""
    pack_dir = Path(pack_dir)
    harvest = intake_report.get('harvested_objects') or {}
    paths: Dict[str, str] = {}

    obj_path = pack_dir / 'object_pool.json'
    write_json(obj_path, {
        'schema_version': SCHEMA_VERSION,
        'generated_at': _utc_now(),
        'object_count': harvest.get('object_count', 0),
        'objects': harvest.get('objects') or [],
        'fields': harvest.get('fields') or {},
        'field_sources': harvest.get('field_sources') or {},
    })
    paths['object_pool'] = str(obj_path)

    agg_path = pack_dir / 'aggregate_materials.json'
    write_json(agg_path, {
        'schema_version': SCHEMA_VERSION,
        'generated_at': _utc_now(),
        'fields': (intake_report.get('decrypted_fields_aggregate') or {}).get('fields') or {},
        'sources': (intake_report.get('decrypted_fields_aggregate') or {}).get('sources') or {},
        'harvested_objects': harvest.get('objects') or [],
        'field_count': (intake_report.get('decrypted_fields_aggregate') or {}).get('field_count', 0),
    })
    paths['aggregate_materials'] = str(agg_path)

    if ctx is not None:
        ctx = merge_harvest_into_runtime_context(ctx, harvest)
        write_json(pack_dir / 'baseline_runtime_context.json', ctx)
        paths['baseline_runtime_context'] = str(pack_dir / 'baseline_runtime_context.json')

    matrix = build_baseline_unlock_matrix(pack_dir)
    matrix_path = pack_dir / 'baseline_unlock_matrix.json'
    write_json(matrix_path, matrix)
    paths['baseline_unlock_matrix'] = str(matrix_path)

    try:
        from minidrifter.graph.object_flow_chain_synthesizer import write_object_flow_artifacts
        of_paths = write_object_flow_artifacts(pack_dir)
        paths.update(of_paths)
    except Exception:
        pass
    try:
        from minidrifter.materials.object_flow_anchor_materializer import inject_object_flow_anchors
        anchor_report = inject_object_flow_anchors(pack_dir, write=True)
        if anchor_report.get('injected_count'):
            paths['object_flow_anchor_materialization'] = str(
                pack_dir / 'object_flow_anchor_materialization.json'
            )
    except Exception:
        pass
    try:
        from minidrifter.orchestration.coverage_frontier import write_coverage_frontier
        fp = write_coverage_frontier(pack_dir)
        paths['coverage_frontier'] = str(fp)
    except Exception:
        pass
    return paths
