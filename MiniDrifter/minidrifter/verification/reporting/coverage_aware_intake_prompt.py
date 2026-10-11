# -*- coding: utf-8 -*-
"""Coverage-aware chain intake prompt — unblock materials, not duplicate baselines."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from minidrifter.core.utils import write_json
from minidrifter.materials.intake_param_hints import normalize_api_path

SCHEMA_VERSION = '1.0.0'

SIGNATURE_UNBLOCK_MATERIALS: List[Dict[str, str]] = [
    {
        'id': 'signature_generation_logic',
        'label_zh': '前端签名生成逻辑（JavaScript 函数或 wrapper，可重算 signature）',
        'label_en': 'Frontend signature generation logic (JS function or wrapper)',
    },
    {
        'id': 'valid_mutated_capture',
        'label_zh': '同一 API 在变异 subject 字段后的合法抓包（后端接受）',
        'label_en': 'Valid capture of the same API after changing the subject field',
    },
    {
        'id': 'signing_inputs',
        'label_zh': '签名重算材料：secret、salt、timestamp、nonce、token、参数排序规则、覆盖字段列表',
        'label_en': 'Signing inputs: secret, salt, timestamp, nonce, token, param order, covered fields',
    },
    {
        'id': 'signature_disabled_test_env',
        'label_zh': '签名校验关闭或支持重算的测试环境',
        'label_en': 'Test environment with signature verification disabled or recompute supported',
    },
]

DO_NOT_REQUEST_DEFAULT: List[Dict[str, str]] = [
    {'id': 'duplicate_baseline_capture', 'label_zh': '重复的普通 baseline 抓包'},
    {'id': 'same_apiToken', 'label_zh': '已导入 baseline 中已有的 apiToken'},
    {'id': 'same_customerId', 'label_zh': '已导入 baseline 中已有的 customerId / userId'},
    {'id': 'manual_reused_signature_mutation', 'label_zh': '复用旧 signature 的手工 subject 变异请求'},
]

BASELINE_SUFFICIENT_REPLAY = frozenset({
    'live_m0_success',
    'baseline_m0_success',
})

PRIORITY_RANKS = frozenset({'P1', 'P2', 'P3', 'P4', 'P5'})

# Core sensitive APIs for operator-facing summary (not every static P1/P2 path).
FOCUS_API_TOKENS: Tuple[Tuple[str, str], ...] = (
    ('P1', 'personalcore'),
    ('P2', 'address/list'),
    ('P3', 'remain/money'),
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _load_coverage_doc(pack_dir: Path) -> Dict[str, Any]:
    pack_dir = Path(pack_dir)
    path = pack_dir / 'sensitive_binding_coverage_report.json'
    if path.exists():
        return json.loads(path.read_text(encoding='utf-8'))
    try:
        from minidrifter.verification.reporting.sensitive_binding_coverage import (
            build_sensitive_binding_coverage_report,
        )
        return build_sensitive_binding_coverage_report(pack_dir)
    except Exception:
        return {}


def baseline_sufficient_paths(pack_dir: Path) -> Set[str]:
    """Paths where baseline capture + M0 replay evidence is already sufficient."""
    doc = _load_coverage_doc(pack_dir)
    records = list(doc.get('records') or [])
    focus = _focus_coverage_rows(records)
    scan = focus if focus else records
    out: Set[str] = set()
    for row in scan:
        replay = row.get('replay_coverage_status') or ''
        m0 = row.get('m0_status') or ''
        if replay in BASELINE_SUFFICIENT_REPLAY or m0 in BASELINE_SUFFICIENT_REPLAY:
            norm = normalize_api_path(row.get('static_path') or '')
            if norm:
                out.add(norm)
        elif row.get('capture_matched') and row.get('sensitive_response_observed'):
            if m0 in {'live_m0_success', 'baseline_m0_success', 'm0_ok_no_sensitive'}:
                norm = normalize_api_path(row.get('static_path') or '')
                if norm:
                    out.add(norm)
    return out


def _build_intake_item(row: Dict[str, Any]) -> Dict[str, Any]:
    path = row.get('static_path') or ''
    replay = row.get('replay_coverage_status') or ''
    m0 = row.get('m0_status') or ''
    testability = row.get('binding_testability_status') or ''
    conclusion = row.get('security_conclusion') or ''
    block = row.get('block_reason') or ''

    baseline_sufficient = (
        replay in BASELINE_SUFFICIENT_REPLAY
        or m0 in BASELINE_SUFFICIENT_REPLAY
        or (
            row.get('capture_matched')
            and row.get('sensitive_response_observed')
            and str(row.get('business_status') or '') == 'business_success'
        )
    )

    item: Dict[str, Any] = {
        'api': path,
        'target_rank': row.get('target_rank'),
        'business_label': row.get('business_label'),
        'baseline_sufficient': baseline_sufficient,
        'replay_coverage_status': replay,
        'm0_status': m0,
        'sensitive_response_observed': bool(row.get('sensitive_response_observed')),
        'binding_testability_status': testability,
        'security_conclusion': conclusion,
        'block_reason': block or None,
        'subject_candidates': [
            f.get('field') for f in (row.get('subject_candidates') or []) if f.get('field')
        ],
        'm7_execute_allowed': False,
    }

    if testability == 'safety_gate_skip':
        item['missing_material_type'] = 'safety_gated_dry_run_only'
        item['prompt_action'] = 'dry_run_only_note'
        item['required_materials'] = []
        item['do_not_request'] = [d['id'] for d in DO_NOT_REQUEST_DEFAULT]
        item['operator_note_zh'] = '该接口为状态变更/支付类，MiniDrifter 默认不执行 live M7，仅生成 dry-run 计划。'
        return item

    if testability == 'signature_bound_skip' or block == 'signature_not_recomputable':
        item['missing_material_type'] = 'signature_recompute_material'
        item['prompt_action'] = 'signature_unblock_request'
        item['required_materials'] = [m['id'] for m in SIGNATURE_UNBLOCK_MATERIALS]
        item['do_not_request'] = [d['id'] for d in DO_NOT_REQUEST_DEFAULT]
        if baseline_sufficient:
            item['do_not_request'].append('duplicate_baseline_capture')
        item['operator_note_zh'] = (
            'baseline 与 M0 replay 已足够；阻塞点为 signature 不可重算，'
            '需提供可解除 signature_bound_skip 的材料后方可执行 M7 subject override。'
        )
        return item

    if testability == 'missing_material_skip' or replay in {'no_capture', 'm0_failed'}:
        item['missing_material_type'] = 'baseline_capture'
        item['prompt_action'] = 'material_request'
        item['required_materials'] = ['baseline_capture_with_response']
        item['do_not_request'] = []
        item['operator_note_zh'] = '缺少可 replay 的 baseline 抓包或必要运行态字段。'
        return item

    if baseline_sufficient and testability == 'subject_candidate_found':
        item['missing_material_type'] = 'signature_recompute_material'
        item['prompt_action'] = 'signature_unblock_request'
        item['required_materials'] = [m['id'] for m in SIGNATURE_UNBLOCK_MATERIALS]
        item['do_not_request'] = [d['id'] for d in DO_NOT_REQUEST_DEFAULT]
        return item

    item['missing_material_type'] = None
    item['prompt_action'] = 'no_action'
    item['required_materials'] = []
    item['do_not_request'] = []
    return item


def _focus_coverage_rows(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Pick the canonical P1–P3 operator-facing APIs from coverage records."""
    by_norm = {normalize_api_path(r.get('static_path') or ''): r for r in records}
    picked: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    for rank, token in FOCUS_API_TOKENS:
        for norm, row in by_norm.items():
            if token in norm and norm not in seen:
                copy = dict(row)
                copy['target_rank'] = rank
                picked.append(copy)
                seen.add(norm)
                break
    return picked


def build_coverage_aware_intake_doc(pack_dir: Path) -> Dict[str, Any]:
    """Structured coverage-aware intake items for chain_intake_prompt + JSON export."""
    pack_dir = Path(pack_dir)
    cov = _load_coverage_doc(pack_dir)
    records = list(cov.get('records') or [])

    priority_rows = [r for r in records if (r.get('target_rank') or '') in PRIORITY_RANKS]
    priority_rows.sort(key=lambda r: (r.get('target_rank') or 'P9', r.get('static_path') or ''))
    other_rows = [
        r for r in records
        if (r.get('target_rank') or '') not in PRIORITY_RANKS
        and r.get('binding_testability_status') in {
            'signature_bound_skip', 'safety_gate_skip', 'missing_material_skip',
        }
    ]

    items = [_build_intake_item(r) for r in priority_rows + other_rows[:8]]
    focus_rows = _focus_coverage_rows(records)
    focus_items = [_build_intake_item(r) for r in focus_rows]
    signature_blocked = [i for i in items if i.get('prompt_action') == 'signature_unblock_request']
    safety_gated = [i for i in items if i.get('prompt_action') == 'dry_run_only_note']
    material_needed = [i for i in items if i.get('prompt_action') == 'material_request']

    subject_fields: Set[str] = set()
    for row in priority_rows:
        for f in row.get('subject_candidates') or []:
            if f.get('field'):
                subject_fields.add(str(f['field']))

    sig_profile_path = pack_dir / 'signature_profile.json'
    sig_profile: Dict[str, Any] = {}
    if sig_profile_path.exists():
        try:
            loaded = json.loads(sig_profile_path.read_text(encoding='utf-8'))
            if isinstance(loaded, dict):
                sig_profile = loaded
        except json.JSONDecodeError:
            sig_profile = {}

    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': _utc_now(),
        'pack_dir': str(pack_dir),
        'coverage_summary': cov.get('summary') or {},
        'global_block_reason': (
            'signature_not_recomputable'
            if signature_blocked
            else None
        ),
        'm7_execute_policy': 'disabled_unless_can_recompute_signature',
        'subject_wire_fields_detected': sorted(subject_fields),
        'items': items,
        'focus_items': focus_items,
        'focus_apis': [i.get('api') for i in focus_items],
        'signature_unblock_materials': SIGNATURE_UNBLOCK_MATERIALS,
        'signature_profile_mining': {
            'profile_id': sig_profile.get('signature_profile_id'),
            'can_recompute_signature': sig_profile.get('can_recompute_signature'),
            'confidence': sig_profile.get('confidence'),
            'reason': sig_profile.get('reason'),
            'primary_wrapper': (sig_profile.get('static_evidence') or {}).get('primary_wrapper'),
            'verification_matched': (sig_profile.get('verification') or {}).get('matched_count'),
            'verification_samples': (sig_profile.get('verification') or {}).get('sample_count'),
        } if sig_profile else None,
        'do_not_request_defaults': DO_NOT_REQUEST_DEFAULT,
        'counts': {
            'baseline_sufficient': sum(1 for i in items if i.get('baseline_sufficient')),
            'signature_unblock': len(signature_blocked),
            'safety_gated': len(safety_gated),
            'material_needed': len(material_needed),
        },
    }


def write_coverage_aware_intake_doc(pack_dir: Path) -> Path:
    pack_dir = Path(pack_dir)
    doc = build_coverage_aware_intake_doc(pack_dir)
    out = pack_dir / 'coverage_aware_intake.json'
    write_json(out, doc)
    return out


def _sens_label(observed: bool) -> str:
    return '已观测' if observed else '—'


def _replay_label(status: str) -> str:
    mapping = {
        'live_m0_success': 'live M0 成功',
        'baseline_m0_success': 'baseline M0 成功',
        'capture_exact_matched': '抓包 exact 对齐',
        'capture_fallback_matched': '抓包 fallback 对齐',
        'no_capture': '无抓包',
        'm0_failed': 'M0 失败',
    }
    return mapping.get(status, status or '—')


def _testability_label(status: str) -> str:
    mapping = {
        'signature_bound_skip': '签名不可重算（跳过 M7）',
        'safety_gate_skip': '安全策略拦截',
        'missing_material_skip': '缺材料',
        'subject_candidate_found': '已发现 subject 字段',
        'mutation_dry_run_planned': 'M7 dry-run 已规划',
        'no_subject_candidate': '无 wire subject',
    }
    return mapping.get(status, status or '—')


def _conclusion_label(status: str) -> str:
    mapping = {
        'inconclusive': 'inconclusive（不可下结论）',
        'not_tested': 'not_tested（未测）',
        'clean': 'clean',
        'drift': 'drift',
    }
    return mapping.get(status, status or '—')


def render_coverage_aware_intake_section(pack_dir: Path) -> List[str]:
    """Markdown lines (Chinese) for chain_intake_prompt.md."""
    doc = build_coverage_aware_intake_doc(pack_dir)
    if not doc.get('items'):
        return []

    items = doc.get('items') or []
    focus_items = doc.get('focus_items') or []
    if not focus_items:
        focus_items = [
            i for i in items
            if any(tok in normalize_api_path(i.get('api') or '') for _, tok in FOCUS_API_TOKENS)
        ]
    priority = focus_items if focus_items else items[:5]

    lines = [
        '## 1.5 敏感 API 验证状态（Coverage-Aware）',
        '',
        'MiniDrifter 已完成 baseline 导入、exact replay 对齐与敏感读覆盖分析。**下列核心敏感 API 的 baseline 请求材料已足够**，'
        '请勿重复提供相同 baseline 抓包（除非 token / session 已过期）。',
        '',
        '### 核心敏感 API（P1–P3）',
        '',
        '| 优先级 | API | Replay | 敏感证据 | 绑定可测性 | 安全结论 |',
        '|---|---|---|---|---|---|',
    ]
    for row in priority:
        lines.append(
            f"| {row.get('target_rank', '—')} | `{row.get('api', '—')}` | "
            f"{_replay_label(row.get('m0_status') or row.get('replay_coverage_status') or '')} | "
            f"{_sens_label(bool(row.get('sensitive_response_observed')))} | "
            f"{_testability_label(row.get('binding_testability_status') or '')} | "
            f"{_conclusion_label(row.get('security_conclusion') or '')} |"
        )
    lines.append('')

    wire_fields = doc.get('subject_wire_fields_detected') or []
    if wire_fields:
        fields_txt = '、'.join(f'`{f}`' for f in wire_fields[:8])
        lines.extend([
            f'已在请求 wire 上识别 subject 相关字段：{fields_txt}。',
            '但这些字段所在请求的 **signature 当前无法重算**，因此 MiniDrifter **不会**对这些 API 执行 subject override 变异（M7 execute）。',
            '',
        ])

    if doc.get('global_block_reason') == 'signature_not_recomputable':
        lines.extend([
            '### 当前阻塞原因',
            '',
            '**`signature_not_recomputable`**',
            '',
            '含义：MiniDrifter 可以按抓包 **原样 replay（M0）**，但在不能重算 signature 的情况下，'
            '**无法安全地**变异 `userId` / `customerId` / `loginCustomerId` 等 subject 字段。'
            '若复用旧 signature 修改这些字段，请求大概率无效，**不能**作为授权绑定证据。',
            '',
            '### 可解除 M7 subject override 阻塞的材料（任选其一）',
            '',
        ])
        for i, mat in enumerate(SIGNATURE_UNBLOCK_MATERIALS, 1):
            lines.append(f'{i}. {mat["label_zh"]}')
        mining = doc.get('signature_profile_mining') or {}
        if mining.get('profile_id'):
            lines.extend([
                '',
                '### P5 签名 profile mining（已运行）',
                '',
                f'- profile：`{mining.get("profile_id")}` · confidence={mining.get("confidence")}',
                f'- can_recompute_signature：`{mining.get("can_recompute_signature")}` · reason：`{mining.get("reason")}`',
                f'- 静态 wrapper：`{mining.get("primary_wrapper") or "—"}`',
                f'- 抓包校验：{mining.get("verification_matched")}/{mining.get("verification_samples")} matched',
                '',
            ])
        lines.append('')

    baseline_ok = [i for i in focus_items if i.get('baseline_sufficient')]
    if not baseline_ok:
        baseline_ok = [i for i in priority if i.get('baseline_sufficient')]
    if baseline_ok:
        lines.extend([
            '### 当前不需要的材料',
            '',
            '以下材料**暂不需要**：',
            '',
        ])
        for row in baseline_ok:
            lines.append(f'- `{row.get("api")}` 的重复 baseline 抓包')
        lines.extend([
            '- 重复提交 baseline 中已有的 `apiToken` / `customerId` / `userId`',
            '- 手工执行「改 subject 字段但复用旧 signature」的请求',
            '',
        ])

    safety = [i for i in items if i.get('prompt_action') == 'dry_run_only_note']
    if safety:
        lines.extend([
            '### 安全策略（Safety-Gated）',
            '',
            '以下状态变更 / 支付类接口默认 **不执行 live M7**，仅生成 dry-run 计划：',
            '',
        ])
        for row in safety:
            lines.append(f'- `{row.get("api")}` — {row.get("operator_note_zh", '')}')
        lines.append('')

    lines.extend([
        '> 详见：`sensitive_binding_coverage_report.md` · `coverage_aware_intake.json`',
        '',
    ])
    return lines


def path_is_baseline_sufficient(pack_dir: Path, api_path: str) -> bool:
    return normalize_api_path(api_path) in baseline_sufficient_paths(pack_dir)
