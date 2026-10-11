# -*- coding: utf-8
"""Batch chain verification — risk-aware breadth across unique consumer targets."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from minidrifter.business_chain.chain_intake import validate_uploaded_material_against_chain
from minidrifter.business_chain.chain_run_context import load_chain_registry, load_json
from minidrifter.core.utils import write_json
from minidrifter.graph.semantic_workflow_graph import infer_domain_from_path
from minidrifter.materials.intake_param_hints import normalize_api_path
from minidrifter.materials.object_pool_writer import load_baseline_field_pool
from minidrifter.orchestration.binding_coverage_report import (
    build_binding_coverage_report,
    write_binding_coverage_report,
)
from minidrifter.business_chain.high_risk_api_chain_ranker import rank_object_flow_chains
from minidrifter.verification.chain_strict_runner import run_chain_strict_verification
from minidrifter.verification.hop_policy import is_success_status


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _risk_scores_by_path(pack_dir: Path) -> Dict[str, float]:
    doc = load_json(pack_dir / 'binding_risk_candidates.json') or {}
    out: Dict[str, float] = {}
    for row in doc.get('candidates') or []:
        path = normalize_api_path(row.get('path') or '')
        if not path:
            continue
        score = float(row.get('combined_score') or row.get('rule_score') or 0)
        probe = 1.15 if row.get('probe_eligible') else 1.0
        mat = 1.08 if row.get('materialized') and row.get('replay_ready') else 1.0
        out[path] = max(out.get(path, 0), score * probe * mat)
    return out


def _baseline_binding_fields(pack_dir: Path) -> Set[str]:
    pool = load_baseline_field_pool(pack_dir)
    return set(pool.get('field_names') or set(pool.get('fields') or {}))


def _material_readiness_score(
    pack_dir: Path,
    chain: Dict[str, Any],
    *,
    alias_map: Dict[str, Any],
    baseline_fields: Set[str],
) -> float:
    score = float(chain.get('score') or 0.0)
    cid = chain.get('chain_id')
    if cid:
        v = validate_uploaded_material_against_chain(pack_dir, chain_id=cid)
        if v.get('valid'):
            score += 0.45
        elif v.get('auth_ok') and not v.get('missing_binding'):
            score += 0.25
    entry = normalize_api_path(chain.get('entry_path') or '')
    for alias in (alias_map.get('aliases') or []):
        if normalize_api_path(alias.get('static_api') or '') == entry:
            score += 0.3
            break
    for bf in (chain.get('binding_fields') or []):
        if bf in baseline_fields:
            score += 0.12
    if chain.get('entry_runtime_replay_ready'):
        score += 0.08
    if chain.get('consumer_runtime_replay_ready'):
        score += 0.12
    return score


def _chain_priority_score(
    pack_dir: Path,
    chain: Dict[str, Any],
    *,
    risk_by_path: Dict[str, float],
    alias_map: Dict[str, Any],
    baseline_fields: Set[str],
) -> float:
    """Risk-first: prioritize high-score consumer targets that can run with current baseline."""
    target = normalize_api_path(chain.get('target_path') or '')
    risk = risk_by_path.get(target, 0.0)
    material = _material_readiness_score(
        pack_dir, chain, alias_map=alias_map, baseline_fields=baseline_fields,
    )
    tier = chain.get('binding_risk_tier') or 'medium'
    tier_bonus = {'high': 0.35, 'medium': 0.12, 'low': 0.04}.get(tier, 0.0)
    rank_bonus = max(0.0, 0.25 - (float(chain.get('rank') or 50) - 1) * 0.01)
    domain = chain.get('domain') or infer_domain_from_path(chain.get('entry_path') or '')
    diversity_bonus = {'order': 0.08, 'task': 0.06, 'member': 0.05}.get(domain, 0.0)
    return risk * 0.55 + material * 0.35 + tier_bonus + rank_bonus + diversity_bonus


def _chain_consumer_domain(chain: Dict[str, Any]) -> str:
    target = chain.get('target_path') or chain.get('consumer_api') or ''
    dom = infer_domain_from_path(target)
    if dom != 'general':
        return dom
    return chain.get('domain') or infer_domain_from_path(chain.get('entry_path') or '') or 'general'


def _apply_domain_quota(
    chains: List[Dict[str, Any]],
    *,
    max_chains: int,
    max_per_domain: int = 5,
    max_domain_share: float = 0.4,
) -> List[Dict[str, Any]]:
    """Limit single-domain dominance; prefer breadth across business domains."""
    if not chains:
        return []
    cap = max(1, int(max_chains * max_domain_share))
    per_domain_cap = min(max_per_domain, cap)
    picked: List[Dict[str, Any]] = []
    domain_counts: Dict[str, int] = {}
    for chain in chains:
        dom = _chain_consumer_domain(chain)
        if domain_counts.get(dom, 0) >= per_domain_cap:
            continue
        picked.append(chain)
        domain_counts[dom] = domain_counts.get(dom, 0) + 1
        if len(picked) >= max_chains:
            return picked
    for chain in chains:
        if chain in picked:
            continue
        picked.append(chain)
        if len(picked) >= max_chains:
            break
    return picked


def _best_chain_per_semantic_key(
    pack_dir: Path,
    candidates: List[Dict[str, Any]],
    *,
    risk_by_path: Dict[str, float],
    alias_map: Dict[str, Any],
    baseline_fields: Set[str],
    max_per_consumer: int = 3,
) -> List[Dict[str, Any]]:
    """Highest-priority chain per semantic dedupe key; cap duplicates per consumer."""
    from minidrifter.orchestration.frontier_scheduler import chain_dedupe_key

    by_key: Dict[tuple, tuple] = {}
    for chain in candidates:
        key = chain_dedupe_key(chain)
        pri = _chain_priority_score(
            pack_dir, chain,
            risk_by_path=risk_by_path,
            alias_map=alias_map,
            baseline_fields=baseline_fields,
        )
        prev = by_key.get(key)
        if prev is None or pri > prev[0]:
            by_key[key] = (pri, chain)

    ordered = sorted(by_key.values(), key=lambda x: x[0], reverse=True)
    picked: List[Dict[str, Any]] = []
    consumer_counts: Dict[str, int] = {}
    for _, chain in ordered:
        consumer = chain_dedupe_key(chain)[0]
        if consumer_counts.get(consumer, 0) >= max_per_consumer:
            continue
        picked.append(chain)
        consumer_counts[consumer] = consumer_counts.get(consumer, 0) + 1
    return picked


def _best_chain_per_target(
    pack_dir: Path,
    candidates: List[Dict[str, Any]],
    *,
    risk_by_path: Dict[str, float],
    alias_map: Dict[str, Any],
    baseline_fields: Set[str],
) -> List[Dict[str, Any]]:
    """One highest-priority chain per unique consumer target_path."""
    by_target: Dict[str, tuple] = {}
    for chain in candidates:
        target = normalize_api_path(chain.get('target_path') or '')
        if not target:
            continue
        pri = _chain_priority_score(
            pack_dir, chain,
            risk_by_path=risk_by_path,
            alias_map=alias_map,
            baseline_fields=baseline_fields,
        )
        prev = by_target.get(target)
        if prev is None or pri > prev[0]:
            by_target[target] = (pri, chain)
    ordered = sorted(by_target.values(), key=lambda x: x[0], reverse=True)
    return [c for _, c in ordered]


def _chain_entry_runnable(
    pack_dir: Path,
    chain: Dict[str, Any],
    *,
    alias_map: Dict[str, Any],
) -> bool:
    """Skip chains whose entry cannot run with current baseline captures."""
    cid = chain.get('chain_id')
    if cid:
        v = validate_uploaded_material_against_chain(pack_dir, chain_id=cid)
        if v.get('valid'):
            return True
    entry = normalize_api_path(chain.get('entry_path') or '')
    for alias in (alias_map.get('aliases') or []):
        if normalize_api_path(alias.get('static_api') or '') == entry:
            return True
    if chain.get('entry_runtime_replay_ready'):
        return True
    if chain.get('chain_source') == 'runtime_object_flow' and chain.get('runtime_status') == 'runnable':
        return True
    plan = load_json(pack_dir / 'chain_material_request_plan.json') or {}
    for row in plan.get('satisfied_by_baseline') or []:
        if entry and entry in {
            normalize_api_path(p)
            for p in (row.get('example_paths') or [])
            if p
        }:
            return True
        static_entry = row.get('entry_api') or row.get('static_entry')
        if static_entry and chain.get('entry_api') == static_entry:
            return True
    return False


def _select_object_flow_chains(
    pack_dir: Path,
    *,
    max_chains: int,
    exclude_targets: Optional[Set[str]] = None,
) -> List[Dict[str, Any]]:
    """Phase A2 — runtime object-flow chains from object_flow_chains.json."""
    pack_dir = Path(pack_dir)
    flow_doc = load_json(pack_dir / 'object_flow_chains.json') or {}
    baseline_fields = _baseline_binding_fields(pack_dir)
    risk_by_path = _risk_scores_by_path(pack_dir)
    exclude = exclude_targets or set()

    pool: List[Dict[str, Any]] = []
    for chain in flow_doc.get('chains') or []:
        if chain.get('runtime_status') != 'runnable':
            continue
        target = normalize_api_path(chain.get('target_path') or '')
        if not target or target in exclude:
            continue
        if chain.get('object_flow', {}).get('already_in_static_chains'):
            continue
        v = validate_uploaded_material_against_chain(pack_dir, chain_id=chain.get('chain_id'))
        if not v.get('valid'):
            continue
        pool.append(dict(chain))

    risk_scores = _risk_scores_by_path(pack_dir)
    scored = rank_object_flow_chains(pool, risk_by_path={
        k: v * 100 for k, v in risk_scores.items()
    })
    picked = _apply_domain_quota(scored, max_chains=max_chains, max_per_domain=4)
    for c in picked:
        c['campaign_phase'] = 'A2'
    return picked[:max_chains]


def _select_static_batch_chains(
    pack_dir: Path,
    rank_plan: Dict[str, Any],
    chains_by_id: Dict[str, Dict[str, Any]],
    *,
    max_chains: int,
    dedupe_by: str = 'target_path',
    rank_limit: int = 40,
) -> List[Dict[str, Any]]:
    alias_map = load_json(pack_dir / 'runtime_alias_map.json') or {}
    baseline_fields = _baseline_binding_fields(pack_dir)
    risk_by_path = _risk_scores_by_path(pack_dir)

    pool: List[Dict[str, Any]] = []
    seen_cids: Set[str] = set()
    unlock = load_json(pack_dir / 'baseline_unlock_matrix.json') or {}

    def _add_chain(chain: Dict[str, Any]) -> None:
        cid = chain.get('chain_id')
        if not cid or cid in seen_cids:
            return
        if not _chain_entry_runnable(pack_dir, chain, alias_map=alias_map):
            return
        seen_cids.add(cid)
        pool.append(chain)

    for ranked_row in (rank_plan.get('top_chains') or [])[:rank_limit]:
        cid = ranked_row.get('chain_id')
        chain = dict(chains_by_id.get(cid) or ranked_row)
        chain.setdefault('rank', ranked_row.get('rank'))
        _add_chain(chain)

    for row in (unlock.get('runnable_chains') or [])[:60]:
        cid = row.get('chain_id')
        chain = dict(chains_by_id.get(cid) or {})
        if chain:
            _add_chain(chain)

    if dedupe_by in {'semantic', 'consumer_anchor'}:
        picked = _best_chain_per_semantic_key(
            pack_dir, pool,
            risk_by_path=risk_by_path,
            alias_map=alias_map,
            baseline_fields=baseline_fields,
        )
        picked = _apply_domain_quota(
            picked, max_chains=max_chains, max_per_domain=max(2, int(max_chains * 0.3)),
        )
        for c in picked:
            c.setdefault('campaign_phase', 'A')
        return picked[:max_chains]

    if dedupe_by == 'target_path':
        picked = _best_chain_per_target(
            pack_dir, pool,
            risk_by_path=risk_by_path,
            alias_map=alias_map,
            baseline_fields=baseline_fields,
        )
        picked = _apply_domain_quota(picked, max_chains=max_chains)
        for c in picked:
            c.setdefault('campaign_phase', 'A')
        return picked[:max_chains]

    scored: List[tuple] = []
    for chain in pool:
        scored.append((
            _chain_priority_score(
                pack_dir, chain,
                risk_by_path=risk_by_path,
                alias_map=alias_map,
                baseline_fields=baseline_fields,
            ),
            chain,
        ))
    scored.sort(key=lambda x: x[0], reverse=True)

    seen: Set[str] = set()
    picked: List[Dict[str, Any]] = []
    key_field = 'entry_api' if dedupe_by == 'entry' else 'target_path'
    for _, chain in scored:
        if len(picked) >= max_chains:
            break
        key = chain.get(key_field) or chain.get('entry_path') or chain.get('target_path')
        if key in seen:
            continue
        seen.add(str(key))
        picked.append(chain)
    for c in picked:
        c.setdefault('campaign_phase', 'A')
    return picked


def _select_batch_chains(
    pack_dir: Path,
    rank_plan: Dict[str, Any],
    chains_by_id: Dict[str, Dict[str, Any]],
    *,
    max_chains: int,
    dedupe_by: str = 'target_path',
    rank_limit: int = 40,
) -> List[Dict[str, Any]]:
    return _select_static_batch_chains(
        pack_dir, rank_plan, chains_by_id,
        max_chains=max_chains, dedupe_by=dedupe_by, rank_limit=rank_limit,
    )


def _build_risk_coverage(
    pack_dir: Path,
    chain_results: List[Dict[str, Any]],
    probe_results: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    risk_doc = load_json(pack_dir / 'binding_risk_candidates.json') or {}
    probe_apis = [
        c for c in (risk_doc.get('candidates') or [])
        if c.get('probe_eligible')
    ]
    tested_targets = {
        normalize_api_path(r.get('target_path') or '')
        for r in chain_results
        if r.get('reached_m7') or r.get('verdict') in {
            'chain_completed_no_drift', 'chain_binding_drift',
        }
    }
    object_flow_m7 = {
        normalize_api_path(r.get('target_path') or '')
        for r in chain_results
        if r.get('campaign_phase') == 'A2' and r.get('reached_m7')
    }
    attempted_targets = {
        normalize_api_path(r.get('target_path') or '') for r in chain_results
    }
    direct_m7: Set[str] = set()
    direct_attempted: Set[str] = set()
    for pr in probe_results or []:
        p = normalize_api_path(pr.get('path') or '')
        if not p:
            continue
        direct_attempted.add(p)
        if pr.get('reached_m7'):
            direct_m7.add(p)

    covered: List[Dict[str, Any]] = []
    attempted: List[Dict[str, Any]] = []
    uncovered: List[Dict[str, Any]] = []
    for row in sorted(probe_apis, key=lambda x: -(x.get('combined_score') or 0)):
        path = normalize_api_path(row.get('path') or '')
        item = {
            'path': row.get('path'),
            'api_id': row.get('api_id'),
            'rule_score': row.get('rule_score'),
            'materialized': row.get('materialized'),
            'replay_ready': row.get('replay_ready'),
        }
        if path in tested_targets:
            via = 'object_flow_chain' if path in object_flow_m7 else 'chain'
            covered.append({**item, 'status': 'm7_reached', 'via': via})
        elif path in direct_m7:
            covered.append({**item, 'status': 'm7_reached', 'via': 'direct_probe'})
        elif path in attempted_targets or path in direct_attempted:
            via = 'direct_probe' if path in direct_attempted else 'chain'
            attempted.append({**item, 'status': 'attempted_not_m7', 'via': via})
        else:
            uncovered.append({**item, 'status': 'not_in_batch'})

    return {
        'probe_eligible_total': len(probe_apis),
        'covered_count': len(covered),
        'attempted_count': len(attempted),
        'uncovered_count': len(uncovered),
        'direct_probe_count': len(probe_results or []),
        'direct_probe_m7': len(direct_m7),
        'covered': covered,
        'attempted': attempted,
        'uncovered': uncovered[:15],
    }


def _run_chain_candidate(
    pack_dir: Path,
    chain: Dict[str, Any],
    *,
    mode: str,
    source_dir: Optional[Path],
    base_url: Optional[str],
    only_safe: bool,
    verbose: bool,
) -> Dict[str, Any]:
    cid = chain.get('chain_id') or ''
    session = run_chain_strict_verification(
        pack_dir,
        mode=mode,
        chain_id=cid,
        source_dir=source_dir,
        base_url=base_url,
        only_safe=only_safe,
        skip_preflight=True,
        verbose=verbose,
    )
    strict = load_json(pack_dir / 'chain_strict_report.json') or {}
    hops = strict.get('hop_results') or []
    hops_ok = sum(1 for h in hops if is_success_status(h.get('status') or ''))
    verdict = session.get('verdict') or strict.get('verdict')
    diff_exports = session.get('binding_evidence_diff_exports') or strict.get('binding_evidence_diff_exports') or []
    m7_results = load_json(pack_dir / 'consumer_m7_results.json') or {}
    m7_row = (m7_results.get('results') or [{}])[-1] if m7_results.get('results') else {}
    binding_status = None
    if diff_exports:
        try:
            import json as _json
            summary_path = Path(diff_exports[0]) / 'summary.json'
            if summary_path.exists():
                binding_status = _json.loads(summary_path.read_text(encoding='utf-8')).get('binding_status')
        except Exception:
            binding_status = None
    reached_m7 = bool(m7_results.get('results')) or verdict in {
        'chain_completed_no_drift', 'chain_binding_drift', 'chain_binding_drift_hypothesis',
    } or (
        not strict.get('stopped_early') and bool(strict.get('primary_findings'))
    )
    cov = session.get('coverage') or {}
    return {
        'chain_id': cid,
        'chain_source': chain.get('chain_source') or 'static_page_event_flow',
        'campaign_phase': chain.get('campaign_phase') or 'A',
        'entry_path': chain.get('entry_path') or strict.get('entry_path'),
        'target_path': chain.get('target_path') or strict.get('target_path'),
        'verdict': verdict,
        'hops_completed': hops_ok,
        'hops_total': len(chain.get('hops') or hops),
        'reached_m7': reached_m7,
        'm7_outcome': m7_row.get('call_outcome'),
        'binding_status': binding_status,
        'evidence_diff_path': diff_exports[0] if diff_exports else None,
        'wire_mutation_valid': binding_status not in {None, 'invalid_test'},
        'http_calls': cov.get('http_calls') or 0,
        'findings': len(strict.get('primary_findings') or []),
        'covered_via': (
            'object_flow_chain' if chain.get('campaign_phase') == 'A2' and reached_m7
            else 'static_chain' if reached_m7 else None
        ),
    }


def run_chain_batch_verification(
    pack_dir: Path,
    *,
    mode: str = 'dry-run',
    max_chains: int = 15,
    max_http: int = 250,
    source_dir: Optional[Path] = None,
    base_url: Optional[str] = None,
    only_safe: bool = True,
    verbose: bool = True,
    dedupe_by: str = 'semantic',
    rank_limit: int = 80,
    max_risk_probes: int = 15,
    risk_probe: bool = True,
    campaign_source: str = 'rank_plan',
) -> Dict[str, Any]:
    pack_dir = Path(pack_dir)
    chains_doc = load_json(pack_dir / 'business_chains.json')
    rank_doc = load_json(pack_dir / 'chain_rank_plan.json')
    by_id = load_chain_registry(pack_dir)

    frontier_plan_path = None
    if campaign_source == 'frontier':
        from minidrifter.orchestration.frontier_scheduler import (
            select_chains_from_frontier_plan,
            write_campaign_frontier_plan,
        )
        frontier_plan_path = write_campaign_frontier_plan(pack_dir, max_chains=max_chains)
        candidates = select_chains_from_frontier_plan(pack_dir)
        static_candidates = [c for c in candidates if c.get('campaign_phase') != 'A2']
        flow_candidates = [c for c in candidates if c.get('campaign_phase') == 'A2']
        if not static_candidates and not flow_candidates:
            static_candidates = candidates
    else:
        static_max = max(3, int(max_chains * 0.45))
        flow_max = max(2, max_chains - static_max)

        static_candidates = _select_static_batch_chains(
            pack_dir, rank_doc, by_id,
            max_chains=static_max,
            dedupe_by=dedupe_by,
            rank_limit=rank_limit,
        )
        static_targets = {
            normalize_api_path(c.get('target_path') or '') for c in static_candidates
        }
        flow_candidates = _select_object_flow_chains(
            pack_dir, max_chains=flow_max, exclude_targets=static_targets,
        )
    candidates = static_candidates + flow_candidates

    chain_results: List[Dict[str, Any]] = []
    http_used = 0
    findings_total = 0

    if verbose:
        print(
            f'[MiniDrifter:chain_batch] phaseA={len(static_candidates)} '
            f'phaseA2={len(flow_candidates)} budget={max_http} mode={mode}',
            flush=True,
        )
        for i, c in enumerate(candidates):
            print(
                f'  [{i+1}] phase={c.get("campaign_phase","A")} '
                f'target={c.get("target_path")} entry={c.get("entry_path")}',
                flush=True,
            )

    for i, chain in enumerate(candidates):
        if http_used >= max_http:
            break
        if verbose:
            print(
                f'[MiniDrifter:chain_batch] run {i+1}/{len(candidates)} '
                f'phase={chain.get("campaign_phase","A")} '
                f'chain={chain.get("chain_id")} target={chain.get("target_path")}',
                flush=True,
            )
        row = _run_chain_candidate(
            pack_dir, chain,
            mode=mode, source_dir=source_dir, base_url=base_url,
            only_safe=only_safe, verbose=verbose,
        )
        http_used += row.get('http_calls') or 0
        findings_total += row.get('findings') or 0
        chain_results.append(row)

    covered_paths = {
        normalize_api_path(r.get('target_path') or '')
        for r in chain_results
        if r.get('reached_m7')
    }
    object_flow_covered = {
        normalize_api_path(r.get('target_path') or '')
        for r in chain_results
        if r.get('campaign_phase') == 'A2' and r.get('reached_m7')
    }
    probe_doc: Dict[str, Any] = {'results': [], 'http_calls_total': 0}
    sensitive_read_doc: Dict[str, Any] = {'results': [], 'http_calls_total': 0}
    if http_used < max_http:
        from minidrifter.verification.sensitive_read_runner import run_sensitive_read_batch

        sensitive_read_doc = run_sensitive_read_batch(
            pack_dir,
            covered_paths=covered_paths | object_flow_covered,
            mode=mode,
            max_reads=min(12, max_risk_probes),
            max_http=max(20, (max_http - http_used) // 2),
            source_dir=source_dir,
            base_url=base_url,
            only_safe=only_safe,
            subject_override=True,
            max_subject_override=3,
            verbose=verbose,
        )
        http_used += sensitive_read_doc.get('http_calls_total') or 0
        sensitive_paths = {
            normalize_api_path(r.get('path') or '')
            for r in (sensitive_read_doc.get('results') or [])
            if r.get('path')
        }
        covered_paths |= sensitive_paths

    if risk_probe and http_used < max_http:
        from minidrifter.verification.risk_probe_runner import run_risk_probe_batch

        probe_doc = run_risk_probe_batch(
            pack_dir,
            covered_paths=covered_paths | object_flow_covered,
            mode=mode,
            max_probes=max_risk_probes,
            max_http=max_http - http_used,
            source_dir=source_dir,
            base_url=base_url,
            only_safe=only_safe,
            verbose=verbose,
        )
        http_used += probe_doc.get('http_calls_total') or 0
        findings_total += probe_doc.get('findings_total') or 0

    probe_results = probe_doc.get('results') or []
    risk_coverage = _build_risk_coverage(pack_dir, chain_results, probe_results)

    batch_doc = {
        'schema_version': '1.0.0',
        'generated_at': _utc_now(),
        'verify_mode': 'chain_batch',
        'campaign_source': campaign_source,
        'dedupe_by': dedupe_by,
        'rank_limit': rank_limit,
        'max_chains': max_chains,
        'max_http': max_http,
        'http_calls_total': http_used,
        'chains_run': len(chain_results),
        'findings_total': findings_total,
        'campaign_frontier_plan': str(frontier_plan_path) if frontier_plan_path else None,
        'campaign_phases': {
            'A_static': len(static_candidates),
            'A2_object_flow': len(flow_candidates),
            'C_sensitive_read': len(sensitive_read_doc.get('results') or []),
            'C2_subject_override': len(sensitive_read_doc.get('subject_override_results') or []),
            'B_direct_probe': len(probe_doc.get('results') or []),
        },
        'chain_coverage': {
            'static_chains_attempted': sum(1 for r in chain_results if r.get('campaign_phase') == 'A'),
            'static_chains_m7': sum(1 for r in chain_results if r.get('campaign_phase') == 'A' and r.get('reached_m7')),
            'object_flow_chains_synthesized': len((load_json(pack_dir / 'object_flow_chains.json') or {}).get('chains') or []),
            'object_flow_chains_attempted': sum(1 for r in chain_results if r.get('campaign_phase') == 'A2'),
            'object_flow_chains_m7': sum(1 for r in chain_results if r.get('campaign_phase') == 'A2' and r.get('reached_m7')),
            'direct_probe_attempted': len(probe_doc.get('results') or []),
            'direct_probe_m7': sum(1 for pr in (probe_doc.get('results') or []) if pr.get('reached_m7')),
        },
        'chain_results': chain_results,
        'risk_coverage': risk_coverage,
        'risk_probe': probe_doc,
        'sensitive_read': sensitive_read_doc,
        'subject_override': {
            'results': sensitive_read_doc.get('subject_override_results') or [],
            'subject_override': sensitive_read_doc.get('subject_override') or {},
        },
        'status': 'completed',
    }
    write_json(pack_dir / 'chain_batch_report.json', batch_doc)

    coverage = build_binding_coverage_report(
        pack_dir, batch_results=chain_results, http_budget=max_http,
    )
    coverage['risk_coverage'] = risk_coverage
    write_binding_coverage_report(pack_dir, coverage)

    try:
        from minidrifter.orchestration.coverage_frontier import write_coverage_frontier
        frontier_path = write_coverage_frontier(pack_dir)
    except Exception:
        frontier_path = None

    drift = sum(1 for r in chain_results if r.get('verdict') in {'chain_binding_drift', 'chain_binding_drift_hypothesis'})
    drift_strong = sum(1 for r in chain_results if r.get('verdict') == 'chain_binding_drift')
    batch_verdict = (
        'chain_binding_drift' if drift_strong
        else 'chain_binding_drift_hypothesis' if drift
        else 'completed'
    )
    return {
        'status': 'completed',
        'verify_mode': 'chain_batch',
        'verdict': batch_verdict,
        'http_calls_total': http_used,
        'chains_run': len(chain_results),
        'findings_total': findings_total,
        'chain_results': chain_results,
        'risk_coverage': risk_coverage,
        'risk_probe': probe_doc,
        'binding_coverage_report': str(pack_dir / 'binding_coverage_report.json'),
        'coverage_frontier': str(frontier_path) if frontier_path else None,
        'coverage': {
            'http_calls': http_used,
            'chains_run': len(chain_results),
            'chains_reached_m7': sum(1 for r in chain_results if r.get('reached_m7')),
            'risk_probes_run': len(probe_results),
            'risk_probes_m7': probe_doc.get('probes_reached_m7', 0),
            'findings_confirmed': findings_total,
            'risk_covered': risk_coverage.get('covered_count'),
            'risk_uncovered': risk_coverage.get('uncovered_count'),
        },
        'search_session': {
            'verify_mode': 'chain_batch',
            'status': 'completed',
            'verdict': batch_verdict,
            'coverage': {
                'http_calls': http_used,
                'chains_run': len(chain_results),
            },
        },
    }
