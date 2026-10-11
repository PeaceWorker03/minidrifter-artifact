# -*- coding: utf-8 -*-
"""Project-level binding drift coverage report — breadth + depth metrics."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from minidrifter.core.utils import write_json


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _load_json(path: Path) -> Any:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding='utf-8'))


def _chain_verdict_label(verdict: Optional[str]) -> str:
    if verdict in {'chain_binding_drift', 'binding_drift'}:
        return 'drift'
    if verdict in {'chain_completed_no_drift', 'completed_no_drift', 'clean'}:
        return 'clean'
    if verdict in {'waiting_for_entry_capture'}:
        return 'deferred'
    if verdict in {'chain_blocked', 'stopped', 'blocked'}:
        return 'blocked'
    return 'unknown'


def build_binding_coverage_report(
    pack_dir: Path,
    *,
    batch_results: Optional[List[Dict[str, Any]]] = None,
    search_session: Optional[Dict[str, Any]] = None,
    http_budget: Optional[int] = None,
) -> Dict[str, Any]:
    """Aggregate static chains vs verified chains into one coverage document."""
    pack_dir = Path(pack_dir)
    chains_doc = _load_json(pack_dir / 'business_chains.json') or {}
    rank_doc = _load_json(pack_dir / 'chain_rank_plan.json') or {}
    plan_doc = _load_json(pack_dir / 'chain_material_request_plan.json') or {}
    registry = _load_json(pack_dir / 'finding_registry.json') or {}
    ctx = _load_json(pack_dir / 'baseline_runtime_context.json') or {}
    intake = _load_json(pack_dir / 'baseline_intake_report.json') or {}
    batch_doc = _load_json(pack_dir / 'chain_batch_report.json') or {}
    risk_probe_doc = _load_json(pack_dir / 'risk_probe_report.json') or {}
    sensitive_read_doc = _load_json(pack_dir / 'sensitive_read_report.json') or {}
    subject_override_doc = _load_json(pack_dir / 'subject_override_report.json') or {}
    subject_wire_doc = _load_json(pack_dir / 'subject_wire_candidates.json') or {}
    subject_gap_doc = _load_json(pack_dir / 'subject_wire_gap_plan.json') or {}
    if not subject_override_doc.get('results'):
        subject_override_doc = {
            'results': sensitive_read_doc.get('subject_override_results') or [],
            'subject_override': (
                sensitive_read_doc.get('subject_override')
                or (batch_doc.get('subject_override') or {}).get('subject_override')
                or {}
            ),
        }
    frontier_doc = _load_json(pack_dir / 'coverage_frontier.json') or {}
    flow_doc = _load_json(pack_dir / 'object_flow_chains.json') or {}

    static_count = chains_doc.get('chain_count') or len(chains_doc.get('chains') or [])
    ranked = rank_doc.get('top_chains') or []
    ranked_count = len(ranked)

    chain_rows: List[Dict[str, Any]] = []
    if batch_results:
        for row in batch_results:
            chain_rows.append(row)
    elif batch_doc.get('chain_results'):
        chain_rows = list(batch_doc.get('chain_results') or [])

    if not chain_rows:
        strict = _load_json(pack_dir / 'chain_strict_report.json') or {}
        if strict.get('chain_id'):
            chain_rows.append({
                'chain_id': strict.get('chain_id'),
                'verdict': strict.get('verdict'),
                'entry_path': strict.get('entry_path'),
                'target_path': strict.get('target_path'),
                'hops_completed': sum(
                    1 for h in (strict.get('hop_results') or [])
                    if h.get('status') in {'business_success', 'hop_skipped'}
                ),
                'hops_total': len(strict.get('hop_results') or []),
                'reached_m7': not strict.get('stopped_early'),
                'http_calls': (strict.get('coverage') or {}).get('http_calls'),
            })

    attempted = len(chain_rows)
    reached_m7 = sum(1 for r in chain_rows if r.get('reached_m7'))
    drift = sum(1 for r in chain_rows if _chain_verdict_label(r.get('verdict')) == 'drift')
    clean = sum(1 for r in chain_rows if _chain_verdict_label(r.get('verdict')) == 'clean')
    deferred = sum(1 for r in chain_rows if _chain_verdict_label(r.get('verdict')) == 'deferred')
    blocked = sum(1 for r in chain_rows if _chain_verdict_label(r.get('verdict')) == 'blocked')

    findings = registry.get('findings') or []
    if not findings:
        findings = (_load_json(pack_dir / 'finding_registry.json') or {}).get('items') or []
    primary_findings = [
        f for f in findings
        if f.get('finding_tier') in {'F2_chain_consumer_binding_drift', 'F3_capability_consumer_binding_drift'}
        or f.get('status') in {'confirmed', 'hypothesis'}
    ]

    cov = (search_session or {}).get('coverage') or {}
    http_used = cov.get('http_calls')
    if http_used is None and batch_doc.get('http_calls_total') is not None:
        http_used = batch_doc.get('http_calls_total')
    if http_used is None:
        http_used = sum(r.get('http_calls') or 0 for r in chain_rows)

    plan_doc = _load_json(pack_dir / 'chain_material_request_plan.json') or {}
    agg_fields = ((intake or {}).get('decrypted_fields_aggregate') or {}).get('fields') or {}
    pool_keys = set(agg_fields.keys()) | {
        k for k, v in (ctx.get('resolved_fields') or {}).items()
        if isinstance(v, dict) and v.get('value') not in (None, '')
    }
    deferred_gaps: List[Dict[str, Any]] = []
    unlock = _load_json(pack_dir / 'baseline_unlock_matrix.json') or {}
    if unlock.get('deferred_material_gaps'):
        deferred_gaps = list(unlock.get('deferred_material_gaps') or [])
    if not deferred_gaps:
        try:
            from minidrifter.business_chain.baseline_capture_strategy import deferred_gaps_from_strategy
            deferred_gaps = deferred_gaps_from_strategy(pack_dir)
        except Exception:
            deferred_gaps = []
    if not deferred_gaps:
        for req in (plan_doc.get('requests') or []):
            if not req.get('minimum'):
                continue
            paths = req.get('example_paths') or []
            fields = req.get('target_fields') or req.get('binding_fields') or []
            missing = [f for f in fields if f not in pool_keys]
            if missing:
                deferred_gaps.append({
                    'request_id': req.get('request_id'),
                    'entry_paths': paths,
                    'missing_fields': missing,
                    'why_needed': req.get('why_needed'),
                    'priority': req.get('priority'),
                })

    report = {
        'schema_version': '1.0.0',
        'generated_at': _utc_now(),
        'pack_dir': str(pack_dir),
        'static_chain_count': static_count,
        'ranked_chain_count': ranked_count,
        'material_plan_requests': plan_doc.get('request_count'),
        'chains_attempted': attempted,
        'chains_reached_m7': reached_m7,
        'chains_binding_drift': drift,
        'chains_clean': clean,
        'chains_deferred': deferred,
        'chains_blocked': blocked,
        'primary_findings_count': len(primary_findings),
        'http_budget': http_budget,
        'http_budget_used': http_used,
        'baseline_field_count': ctx.get('field_count'),
        'crypto_replay_ready': ctx.get('crypto_replay_ready'),
        'chain_results': chain_rows,
        'chain_coverage': batch_doc.get('chain_coverage') or {
            'static_chains_total': static_count,
            'static_chains_attempted': sum(
                1 for r in chain_rows if r.get('campaign_phase', 'A') == 'A'
            ),
            'static_chains_m7': sum(
                1 for r in chain_rows if r.get('campaign_phase', 'A') == 'A' and r.get('reached_m7')
            ),
            'object_flow_chains_synthesized': len(flow_doc.get('chains') or []),
            'object_flow_chains_attempted': sum(
                1 for r in chain_rows if r.get('campaign_phase') == 'A2'
            ),
            'object_flow_chains_m7': sum(
                1 for r in chain_rows if r.get('campaign_phase') == 'A2' and r.get('reached_m7')
            ),
            'direct_probe_attempted': (batch_doc.get('risk_probe') or {}).get('probes_run', 0),
            'direct_probe_m7': (batch_doc.get('risk_probe') or {}).get('probes_reached_m7', 0),
        },
        'campaign_phases': batch_doc.get('campaign_phases') or {},
        'coverage_frontier_summary': frontier_doc.get('summary') or {},
        'deferred_material_gaps': deferred_gaps,
        'satisfied_by_baseline': plan_doc.get('satisfied_by_baseline') or [],
        'satisfied_count': plan_doc.get('satisfied_count', len(plan_doc.get('satisfied_by_baseline') or [])),
        'search_verdict': (search_session or {}).get('verdict'),
        'risk_coverage': batch_doc.get('risk_coverage') or risk_probe_doc.get('risk_coverage'),
        'risk_probe': batch_doc.get('risk_probe') or risk_probe_doc,
        'sensitive_read': batch_doc.get('sensitive_read') or sensitive_read_doc,
        'subject_override': subject_override_doc.get('subject_override') or {},
        'subject_wire_mining': subject_wire_doc.get('summary') or {},
        'subject_wire_candidates': subject_wire_doc.get('candidates') or [],
        'subject_wire_gap': subject_gap_doc.get('summary') or {},
        'subject_wire_gap_plan': subject_gap_doc.get('gaps') or [],
        'subject_wire_gap_categories': subject_gap_doc.get('recommended_capture_categories') or [],
        'summary': (
            f'静态 {static_count} 链 / 已验 {attempted} / M7 {reached_m7} / '
            f'漂移 {drift} / 干净 {clean} / 待材料 {deferred} / HTTP {http_used}'
        ),
    }
    risk = report.get('risk_coverage') or {}
    if risk.get('direct_probe_m7'):
        report['summary'] += (
            f' / 高危覆盖 {risk.get("covered_count", 0)}/{risk.get("probe_eligible_total", 0)}'
            f' (直探 {risk.get("direct_probe_m7", 0)})'
        )
    report['wire_mutation_audit'] = _build_wire_mutation_audit(pack_dir, chain_rows)
    report['evidence_buckets'] = _summarize_evidence_buckets(report['wire_mutation_audit'])
    try:
        from minidrifter.classification.api_plane_classifier import build_plane_coverage_stats
        report['plane_coverage'] = build_plane_coverage_stats(
            pack_dir,
            batch_doc=batch_doc,
            risk_probe_doc=risk_probe_doc,
            sensitive_read_doc=batch_doc.get('sensitive_read') or sensitive_read_doc,
            subject_override_doc=subject_override_doc,
        ).get('plane_coverage') or {}
    except Exception:
        report['plane_coverage'] = {}

    try:
        from minidrifter.verification.reporting.sensitive_binding_coverage import (
            build_sensitive_api_coverage_records,
            summarize_sensitive_api_coverage,
        )
        sensitive_records = build_sensitive_api_coverage_records(pack_dir)
        report['sensitive_api_coverage'] = {
            'summary': summarize_sensitive_api_coverage(sensitive_records),
            'records': sensitive_records,
        }
    except Exception:
        report['sensitive_api_coverage'] = {'summary': {}, 'records': []}

    return report


def _build_wire_mutation_audit(pack_dir: Path, chain_rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    import json as _json

    audit: List[Dict[str, Any]] = []
    diff_root = Path(pack_dir) / 'binding_evidence_diff'
    for row in chain_rows:
        if not row.get('reached_m7') and not row.get('evidence_diff_path'):
            continue
        entry: Dict[str, Any] = {
            'chain_id': row.get('chain_id'),
            'consumer_api': row.get('target_path'),
            'entry_path': row.get('entry_path'),
            'm7_outcome': row.get('m7_outcome'),
            'binding_status': row.get('binding_status'),
            'verdict': row.get('verdict'),
        }
        diff_path = row.get('evidence_diff_path')
        if diff_path:
            summary = Path(diff_path) / 'summary.json'
            if summary.exists():
                try:
                    doc = _json.loads(summary.read_text(encoding='utf-8'))
                    req = doc.get('request_diff') or {}
                    rd = doc.get('response_diff') or {}
                    entry.update({
                        'object_anchor': doc.get('object_anchor'),
                        'm0_wire': req.get('m0_request'),
                        'm7_wire': req.get('m7_request'),
                        'changed_fields': req.get('changed_fields'),
                        'credential_same': req.get('credential_anchor_same'),
                        'binding_status': doc.get('binding_status') or entry.get('binding_status'),
                        'conclusion': doc.get('interpretation'),
                        'mutated_object_returned': rd.get('mutated_object_returned'),
                        'anchor_mutation_ignored': rd.get('anchor_mutation_ignored'),
                    })
                except Exception:
                    pass
        audit.append(entry)
    if not audit and diff_root.exists():
        for summary in sorted(diff_root.glob('*/summary.json')):
            try:
                doc = _json.loads(summary.read_text(encoding='utf-8'))
                req = doc.get('request_diff') or {}
                audit.append({
                    'finding_id': doc.get('finding_id'),
                    'chain_id': doc.get('chain_id'),
                    'consumer_api': doc.get('consumer_api'),
                    'object_anchor': doc.get('object_anchor'),
                    'm0_wire': req.get('m0_request'),
                    'm7_wire': req.get('m7_request'),
                    'changed_fields': req.get('changed_fields'),
                    'binding_status': doc.get('binding_status'),
                    'conclusion': doc.get('interpretation'),
                })
            except Exception:
                continue
    return audit


def _summarize_evidence_buckets(audit: List[Dict[str, Any]]) -> Dict[str, int]:
    buckets = {
        'verified_clean': 0,
        'verified_drift': 0,
        'verified_weak_signal': 0,
        'inconclusive': 0,
        'invalid_test': 0,
        'anchor_mutation_accepted': 0,
    }
    for row in audit:
        st = row.get('binding_status') or 'inconclusive'
        if st in {'credential_bound_clean', 'anchor_mutation_accepted'}:
            buckets['verified_clean' if st == 'credential_bound_clean' else 'anchor_mutation_accepted'] += 1
        elif st == 'likely_binding_drift':
            buckets['verified_weak_signal'] += 1
        elif st == 'explicit_subject_object_mismatch':
            buckets['verified_drift'] += 1
        elif st == 'invalid_test':
            buckets['invalid_test'] += 1
        else:
            buckets['inconclusive'] += 1
    return buckets


def write_binding_coverage_report(
    pack_dir: Path,
    report: Optional[Dict[str, Any]] = None,
    **kwargs: Any,
) -> Path:
    pack_dir = Path(pack_dir)
    doc = report or build_binding_coverage_report(pack_dir, **kwargs)
    out = pack_dir / 'binding_coverage_report.json'
    write_json(out, doc)
    md_path = pack_dir / 'binding_coverage_report.md'
    md_path.write_text(_render_coverage_md(doc), encoding='utf-8')
    return out


def _render_coverage_md(doc: Dict[str, Any]) -> str:
    lines = [
        '# MiniDrifter 绑定漂移覆盖报告',
        '',
        f"**生成时间**：{doc.get('generated_at', '')}",
        '',
        '## 总览',
        '',
        f"- 静态恢复链数：**{doc.get('static_chain_count', 0)}**",
        f"- 排序待验链数：**{doc.get('ranked_chain_count', 0)}**",
        f"- 本轮尝试验证：**{doc.get('chains_attempted', 0)}**",
        f"- 到达 M7：**{doc.get('chains_reached_m7', 0)}**",
        f"- 绑定漂移：**{doc.get('chains_binding_drift', 0)}**",
        f"- 无漂移：**{doc.get('chains_clean', 0)}**",
        f"- 待入口材料：**{doc.get('chains_deferred', 0)}**",
        f"- 阻断：**{doc.get('chains_blocked', 0)}**",
        f"- HTTP 消耗：**{doc.get('http_budget_used', 0)}** / {doc.get('http_budget') or '—'}",
        '',
        f"> {doc.get('summary', '')}",
        '',
    ]
    cov = doc.get('chain_coverage') or {}
    if cov:
        lines.extend([
            '## 链级覆盖（静态 / 对象流 / 直探）',
            '',
            f"- 静态链总数：**{cov.get('static_chains_total', doc.get('static_chain_count', 0))}**",
            f"- 静态链已验 / M7：**{cov.get('static_chains_attempted', 0)}** / **{cov.get('static_chains_m7', 0)}**",
            f"- 对象流链合成：**{cov.get('object_flow_chains_synthesized', 0)}**",
            f"- 对象流链已验 / M7：**{cov.get('object_flow_chains_attempted', 0)}** / **{cov.get('object_flow_chains_m7', 0)}**",
            f"- 直探已验 / M7：**{cov.get('direct_probe_attempted', 0)}** / **{cov.get('direct_probe_m7', 0)}**",
            '',
        ])
    pc = doc.get('plane_coverage') or {}
    if pc:
        lines.extend([
            '## 敏感 API 平面覆盖（P4）',
            '',
            '| 平面 | 检出 | 材料化 | 已执行 | M0敏感读 | Live M0 | Baseline M0 | M7敏感读 | 变异测试 | Subject尝试 | Subject敏感成功 |',
            '|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|',
        ])
        for plane_id, row in sorted(pc.items(), key=lambda kv: -(kv[1].get('detected') or 0)):
            lines.append(
                f"| {row.get('label', plane_id)} | {row.get('detected', 0)} | "
                f"{row.get('materialized', 0)} | {row.get('executed', 0)} | "
                f"{row.get('sensitive_read_m0_success', 0)} | "
                f"{row.get('live_sensitive_read_m0_success', 0)} | "
                f"{row.get('baseline_sensitive_read_m0_success', 0)} | "
                f"{row.get('sensitive_read_m7_success', 0)} | "
                f"{row.get('sensitive_mutation_tested', 0)} | "
                f"{row.get('subject_override_attempted', 0)} | "
                f"{row.get('subject_override_sensitive_success', 0)} |"
            )
        lines.append('')
    so = doc.get('subject_override') or {}
    sac = doc.get('sensitive_api_coverage') or {}
    sac_summary = sac.get('summary') or {}
    sac_records = sac.get('records') or []
    if sac_summary:
        lines.extend([
            '## Sensitive API Binding Coverage（实验口径）',
            '',
            f"- 跟踪 API：**{sac_summary.get('api_count', 0)}**",
            f"- Live M0 成功：**{sac_summary.get('live_m0_success', 0)}**",
            f"- Baseline M0 成功：**{sac_summary.get('baseline_m0_success', 0)}**",
            f"- 签名约束跳过：**{sac_summary.get('signature_bound_skip', 0)}**",
            f"- 结论 inconclusive：**{sac_summary.get('subject_override_inconclusive', 0)}**",
            f"- drift / clean / not_tested：**{sac_summary.get('drift', 0)}** / "
            f"**{sac_summary.get('clean', 0)}** / **{sac_summary.get('not_tested', 0)}**",
            '',
            '> 本节仅汇总既有产物，不发起新的动态请求。',
            '',
        ])
        if sac_records:
            lines.extend([
                '| Rank | API | Replay | M0 | 敏感响应 | M7可测性 | 安全结论 | 阻塞原因 |',
                '|---|---|---|---|---|---|---|---|',
            ])
            for row in sac_records[:20]:
                sens = '✓' if row.get('sensitive_response_observed') else '—'
                lines.append(
                    f"| {row.get('target_rank', '—')} | `{row.get('static_path', '—')}` | "
                    f"{row.get('replay_coverage_status', '—')} | {row.get('m0_status', '—')} | {sens} | "
                    f"{row.get('binding_testability_status', '—')} | {row.get('security_conclusion', '—')} | "
                    f"{row.get('block_reason') or '—'} |"
                )
            lines.append('')
    if so:
        lines.extend([
            '## Sensitive Subject Override（P4-fix-5）',
            '',
            f"- 检出目标：**{so.get('targets_detected', 0)}**",
            f"- 已尝试：**{so.get('attempted', 0)}**",
            f"- Wire 变异有效：**{so.get('wire_mutation_valid', 0)}**",
            f"- 阻断：**{so.get('blocked', 0)}**",
            f"- 忽略（仍返回原 subject 数据）：**{so.get('ignored', 0)}**",
            f"- 接受但无敏感字段：**{so.get('accepted_no_sensitive', 0)}**",
            f"- 接受且含敏感字段：**{so.get('accepted_sensitive', 0)}**",
            f"- 跳过（请求无 subject 字段）：**{so.get('skipped_no_wire_subject', 0)}**",
            f"- 无效测试：**{so.get('invalid_test', 0)}**",
            f"- 不确定：**{so.get('inconclusive', 0)}**",
            f"- 高危候选 finding：**{so.get('findings', 0)}**",
            '',
        ])
    sw = doc.get('subject_wire_mining') or {}
    sw_candidates = doc.get('subject_wire_candidates') or []
    if sw or sw_candidates:
        lines.extend([
            '## Subject Wire Candidate Mining（P4-fix-5.1）',
            '',
            f"- 扫描抓包：**{sw.get('captures_scanned', 0)}**",
            f"- Wire subject 候选：**{sw.get('candidates_total', 0)}**",
            f"- 可变异候选：**{sw.get('candidates_mutation_allowed', 0)}**",
            f"- Credential-bound 敏感读（无 wire subject）：**{sw.get('credential_bound_sensitive_reads', 0)}**",
            '',
        ])
        if sw_candidates:
            lines.append('| API | Wire subject | 平面 | M0 live | priority |')
            lines.append('|---|---|---|---:|---:|')
            for c in sw_candidates[:12]:
                fields = ', '.join(
                    f"`{f.get('field')}`"
                    for f in (c.get('wire_subject_fields') or [])
                    if f.get('mutation_allowed')
                ) or '—'
                lines.append(
                    f"| `{c.get('path', '—')}` | {fields} | {c.get('plane', '—')} | "
                    f"{'✓' if c.get('m0_live_success') else '—'} | {c.get('priority', 0)} |"
                )
            lines.append('')
        if int(sw.get('candidates_mutation_allowed') or 0) == 0:
            lines.extend([
                '> 所选敏感读 API 的请求 wire 未暴露可变异 subject identifier；'
                '视为 credential-bound sensitive read，仅报告 M0 敏感读证据。',
                '',
            ])
    sg = doc.get('subject_wire_gap') or {}
    sg_cats = doc.get('subject_wire_gap_categories') or []
    sg_gaps = doc.get('subject_wire_gap_plan') or []
    if sg or sg_cats or sg_gaps:
        lines.extend([
            '## Subject Wire Gap（P4-fix-5.2）',
            '',
            f"- 静态含 subject 字段的敏感 API：**{sg.get('static_subject_like_sensitive_apis', 0)}**",
            f"- Baseline 已覆盖 wire subject：**{sg.get('covered_by_baseline_wire_subject', 0)}**",
            f"- Credential-bound 敏感读：**{sg.get('credential_bound_sensitive_reads', 0)}**",
            f"- 未覆盖高优先级缺口：**{sg.get('uncovered_high_priority', 0)}**",
            f"- 建议补抓类别：**{sg.get('recommended_capture_categories', 0)}**",
            '',
        ])
        if sg_cats:
            lines.append('| 类别 | 代表 API | subject 字段 | 建议补抓 | priority |')
            lines.append('|---|---|---|---:|---:|')
            for cat in sg_cats[:10]:
                fields = ', '.join(f"`{f}`" for f in (cat.get('static_subject_fields') or [])[:3]) or '—'
                lines.append(
                    f"| {cat.get('plane', '—')} | `{cat.get('representative_api', '—')}` | "
                    f"{fields} | {cat.get('recommended_capture', '—')} | {cat.get('top_priority', 0)} |"
                )
            lines.append('')
        elif int(sg.get('uncovered_high_priority') or 0) == 0:
            lines.extend([
                '> 静态扫描未发现「高敏平面 + 请求 schema 含 subject 字段 + baseline 未覆盖」的读接口缺口；'
                '当前单账号材料已足够解释 subject override 不可测原因。',
                '',
            ])
    fs = doc.get('coverage_frontier_summary') or {}
    if fs:
        lines.extend([
            '## 覆盖前沿（Coverage Frontier）',
            '',
            f"- L0 静态恢复：**{fs.get('L0_static_recovered', 0)}**",
            f"- L1 已 materialize：**{fs.get('L1_materialized', 0)}**",
            f"- L2 可运行（Large-scale Eligible）：**{fs.get('L2_runnable', 0)}**",
            f"- L3 达 M0：**{fs.get('L3_reached_m0', 0)}**",
            f"- L4 达 M7：**{fs.get('L4_reached_m7', 0)}**",
            f"- 缺材料 blocked：**{fs.get('blocked_missing_material_count', 0)}**",
            f"- 安全策略 blocked：**{fs.get('safety_blocked_count', 0)}**",
            f"- 低价值跳过：**{fs.get('low_value_skipped_count', 0)}**",
            f"- 已解锁未调度链：**{fs.get('unlocked_unscheduled_chain_count', 0)}**",
            '',
        ])
    gaps = doc.get('deferred_material_gaps') or []
    if gaps:
        lines.extend(['## 仍缺的入口级材料（Campaign 后一次性汇总）', ''])
        for g in gaps:
            dom = g.get('domain') or g.get('request_id') or '—'
            fields = ', '.join(g.get('missing_fields') or []) or '—'
            unlock = g.get('estimated_unlock') or {}
            chains_n = unlock.get('chains', g.get('chains'))
            apis = g.get('blocked_apis') or g.get('entry_paths') or []
            api_txt = ', '.join(f'`{a}`' for a in apis[:5]) if apis else '—'
            rec = g.get('recommended_capture') or g.get('why_needed') or ''
            line = f"- **{dom}** 缺 `{fields}`"
            if chains_n:
                line += f'（约 {chains_n} 链'
                if unlock.get('high_risk_apis'):
                    line += f' / {unlock["high_risk_apis"]} 高危 API'
                line += '）'
            if api_txt != '—':
                line += f' · 阻塞 {api_txt}'
            if rec:
                line += f' · 建议 {rec}'
            lines.append(line)
        lines.append('')

    risk = doc.get('risk_coverage') or {}
    if risk.get('probe_eligible_total'):
        lines.extend([
            '## 高危 API 覆盖（probe_eligible）',
            '',
            f"- 可探测高危 API：**{risk.get('probe_eligible_total', 0)}**",
            f"- M7 已覆盖：**{risk.get('covered_count', 0)}**",
            f"- 已尝试未达 M7：**{risk.get('attempted_count', 0)}**",
            f"- 本轮未纳入：**{risk.get('uncovered_count', 0)}**",
        ])
        if risk.get('direct_probe_count'):
            lines.append(
                f"- 链外直探：**{risk.get('direct_probe_count', 0)}** "
                f"（M7 成功 {risk.get('direct_probe_m7', 0)}）"
            )
        lines.append('')

    probe_doc = doc.get('risk_probe') or {}
    probe_rows = probe_doc.get('results') or []
    if probe_rows:
        lines.extend(['### 链外直探结果', '', '| path | M0 | M7 | status |', '|---|---|---|---|'])
        for pr in probe_rows[:20]:
            lines.append(
                f"| `{pr.get('path', '—')}` | {pr.get('m0_outcome', '—')} | "
                f"{pr.get('m7_count', 0)} | {pr.get('status', '—')} |"
            )
        lines.append('')

    if risk.get('probe_eligible_total'):
        uncovered = risk.get('uncovered') or []
        if uncovered:
            lines.append('### 仍未覆盖的高危 API（Top）')
            lines.append('')
            for u in uncovered[:10]:
                lines.append(
                    f"- `{u.get('path')}` score={u.get('rule_score')} "
                    f"materialized={u.get('materialized')}"
                )
            lines.append('')

        lines.append('')

    buckets = doc.get('evidence_buckets') or {}
    if buckets:
        lines.extend([
            '## Clean / Blocked / Drift 证据桶',
            '',
            f"- verified_clean：**{buckets.get('verified_clean', 0)}**",
            f"- anchor_mutation_accepted（服务端阻断）：**{buckets.get('anchor_mutation_accepted', 0)}**",
            f"- verified_weak_signal：**{buckets.get('verified_weak_signal', 0)}**",
            f"- verified_drift：**{buckets.get('verified_drift', 0)}**",
            f"- invalid_test（wire 未变异）：**{buckets.get('invalid_test', 0)}**",
            f"- inconclusive：**{buckets.get('inconclusive', 0)}**",
            '',
        ])

    audit = doc.get('wire_mutation_audit') or []
    if audit:
        lines.extend(['## Wire-Level Mutation Audit', ''])
        for row in audit[:25]:
            anchor = row.get('object_anchor') or '—'
            m0 = row.get('m0_wire') or '—'
            m7 = row.get('m7_wire') or '—'
            lines.append(
                f"- **{row.get('chain_id', '—')}** `{row.get('consumer_api', '—')}` "
                f"anchor=`{anchor}` M0={m0} M7={m7} "
                f"changed={row.get('changed_fields')} status=`{row.get('binding_status')}`"
            )
            if row.get('conclusion'):
                lines.append(f"  - {row['conclusion']}")
        lines.append('')

    if fs.get('unlocked_unscheduled_chain_count') is not None:
        lines.extend([
            '## Next Campaign Frontier',
            '',
            f"- 已解锁未调度链：**{fs.get('unlocked_unscheduled_chain_count', 0)}**",
            '- 建议：`run-closed-loop --campaign-source frontier --max-chains 40`',
            '',
        ])

    rows = doc.get('chain_results') or []
    if rows:
        lines.extend(['## 链级结果', '', '| chain_id | entry | verdict | hops | M7 |', '|---|---|---|---|---|'])
        for r in rows[:30]:
            lines.append(
                f"| {r.get('chain_id', '—')} | `{r.get('entry_path', '—')}` | "
                f"{r.get('verdict', '—')} | {r.get('hops_completed', '?')}/{r.get('hops_total', '?')} | "
                f"{'✓' if r.get('reached_m7') else '—'} |"
            )
        lines.append('')
    return '\n'.join(lines)
