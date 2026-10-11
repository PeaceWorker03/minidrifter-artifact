# -*- coding: utf-8 -*-
"""Batch baseline import — universal scan, manifest, incremental supplement."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from minidrifter.core.utils import write_json
from minidrifter.materials.baseline_intake import build_intake_report, split_multi_raw_http
from minidrifter.orchestration.console.display import artifact, panel, status
from minidrifter.orchestration.console.workspace_layout import (
    EXTRA_CAPTURES_FILE,
    HOW_TO_ADD_FILE,
    MANIFEST_FILE,
    ProjectLayout,
    SUPPLEMENT_NEEDED_FILE,
    list_baseline_capture_files,
    rel_display,
    sync_baseline_to_pack,
)

PLACEHOLDER_SUFFIXES = ('.example', '.placeholder', '.sample', '.md')
SKIP_NAMES = frozenset({'readme.txt', 'how_to_add.md', 'supplement_needed.md'})


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _load_json(path: Path) -> Any:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding='utf-8'))


def _har_to_raw_http_bundle(
    text: str,
    *,
    max_entries: int = 200,
    max_body_chars: int = 32_000,
) -> Tuple[str, int, List[str]]:
    """Convert a HAR JSON document into concatenated Raw HTTP for intake."""
    from minidrifter.materials.har_sequence import (
        filter_har_entries,
        har_entry_to_raw_http_chunk,
        looks_like_har,
    )
    if not looks_like_har(text):
        return '', 0, []
    har = json.loads(text)
    entries = filter_har_entries(har.get('log', {}).get('entries') or [], api_only=True)[:max_entries]
    chunks: List[str] = []
    for e in entries:
        # Truncate oversized response bodies (JS/HTML) to keep intake tractable
        resp = e.get('response') or {}
        content = resp.get('content') or {}
        body = content.get('text') or ''
        if isinstance(body, str) and len(body) > max_body_chars:
            content = dict(content)
            content['text'] = body[:max_body_chars] + '\n/* truncated_for_intake */'
            resp = dict(resp)
            resp['content'] = content
            e = dict(e)
            e['response'] = resp
        chunks.append(har_entry_to_raw_http_chunk(e))
    samples = []
    for e in entries[:5]:
        samples.append(((e.get('request') or {}).get('url') or '')[:120] or '?')
    return '\n\n'.join(chunks), len(chunks), samples


def load_combined_baseline_text(layout: ProjectLayout) -> Tuple[str, List[Path]]:
    """Read all capture files and join for multi-capture intake.

    HAR files are expanded to Raw HTTP first (joining raw HAR JSON breaks parsers).
    Duplicate same-name captures (baseline + CRBD_validation) are de-duplicated.
    """
    from minidrifter.materials.har_sequence import looks_like_har

    parts: List[str] = []
    used: List[Path] = []
    seen_names: Set[str] = set()
    for path in list_baseline_capture_files(layout):
        if path.name.lower() in SKIP_NAMES:
            continue
        if any(path.name.lower().endswith(s) for s in PLACEHOLDER_SUFFIXES):
            continue
        # Prefer first occurrence (baseline/ usually listed before RR-Drift kit)
        name_key = path.name.lower()
        if name_key in seen_names:
            continue
        text = path.read_text(encoding='utf-8', errors='replace').strip()
        if not text:
            continue
        if path.suffix.lower() == '.har' or looks_like_har(text):
            bundle, n, _samples = _har_to_raw_http_bundle(text)
            if n <= 0 or not bundle.strip():
                continue
            parts.append(bundle)
            used.append(path)
            seen_names.add(name_key)
            continue
        if not any(m in text.upper() for m in ('GET ', 'POST ', 'PUT ', 'PATCH ', 'DELETE ', 'HTTP/1.')):
            continue
        parts.append(text)
        used.append(path)
        seen_names.add(name_key)
    return '\n\n'.join(parts), used


def summarize_baseline_files(layout: ProjectLayout) -> List[Dict[str, Any]]:
    from minidrifter.materials.har_sequence import looks_like_har

    rows: List[Dict[str, Any]] = []
    for path in list_baseline_capture_files(layout):
        text = path.read_text(encoding='utf-8', errors='replace')
        if path.suffix.lower() == '.har' or looks_like_har(text):
            _bundle, n, samples = _har_to_raw_http_bundle(text)
            rows.append({
                'file': rel_display(path, base=layout.workspace),
                'name': path.name,
                'request_count': n,
                'sample_paths': samples[:3],
                'format': 'har',
            })
            continue
        chunks = split_multi_raw_http(text)
        paths: List[str] = []
        for c in chunks[:5]:
            try:
                from minidrifter.materials.baseline_importer import parse_raw_http
                req = parse_raw_http(c)
                paths.append(req.get('path') or req.get('url') or '?')
            except Exception:
                paths.append('(parse error)')
        rows.append({
            'file': rel_display(path, base=layout.workspace),
            'name': path.name,
            'request_count': len(chunks),
            'sample_paths': paths[:3],
            'format': 'raw_http',
        })
    return rows


def write_baseline_universal_guide(layout: ProjectLayout) -> Path:
    """Universal HOW_TO_ADD — same rules for every mini-program."""
    path = layout.baseline_dir / HOW_TO_ADD_FILE
    if path.exists():
        return path
    rel_base = rel_display(layout.baseline_dir, base=layout.workspace)
    text = f"""# Baseline 补充指南（通用）

> 适用于任意微信小程序 pack；文件名可自定义，工具按 **HTTP 内容** 自动分类，不按文件名。

## 三种补充方式（可混用）

1. **新文件** — 在 `{rel_base}/` 或 `{rel_base}/additions/` 新建任意 `xxx.http`
2. **追加文件** — 在 `{rel_base}/{EXTRA_CAPTURES_FILE}` 末尾粘贴新的 Raw HTTP
3. **命名槽位** — 将 `*.http.example` 改名去掉 `.example`，或新建 `{{material_id}}.http`

## 文件内容格式

- 每个文件 **一条** 或 **多条** Raw HTTP 均可（Charles/Burp/mitmproxy 导出）
- 多条时工具按 `GET`/`POST` 行自动拆分
- 尽量包含 **完整响应**（便于提取 UserId、OrderId 等字段）

## 何时需要补充

- 首次导入后查看 `{MANIFEST_FILE}` 或 `{SUPPLEMENT_NEEDED_FILE}`
- 动态测试结束后查看 `OUTPUT/user_intake_checklist.json`
- 按提示补充 **字段/材料类型**（如 OrderId、某类 list 接口），不限定具体路径

## 补充后如何生效

重新运行 `python run_minidrifter.py`，在步骤 5 **直接 Enter** — 会 **重扫全部** `.http` 并合并（不会删除你已有文件）。

或使用菜单模式 → 「导入 baseline 抓包」。
"""
    path.write_text(text, encoding='utf-8')
    return path


def write_baseline_slot_files(layout: ProjectLayout, pack_dir: Path) -> List[Path]:
    """Create profile-driven .http.example slots + universal inbox files."""
    tmpl_path = pack_dir / 'baseline_material_template.json'
    written: List[Path] = []
    layout.baseline_dir.mkdir(parents=True, exist_ok=True)
    layout.additions_dir.mkdir(parents=True, exist_ok=True)

    written.append(write_baseline_universal_guide(layout))

    add_readme = layout.additions_dir / 'README.txt'
    if not add_readme.exists():
        add_readme.write_text(
            '后续补充的抓包放此目录（任意文件名 .http）。\n'
            '向导步骤 5 Enter 会自动与 baseline/ 根目录文件一并导入。\n',
            encoding='utf-8',
        )
        written.append(add_readme)

    if not tmpl_path.exists():
        extra = layout.baseline_dir / EXTRA_CAPTURES_FILE
        if not extra.exists():
            extra.write_text(
                '# 通用扩展抓包 — 可追加任意 Raw HTTP\n\n',
                encoding='utf-8',
            )
            written.append(extra)
        return written

    template = json.loads(tmpl_path.read_text(encoding='utf-8'))
    for bucket in ('required_materials', 'recommended_materials', 'deferred_materials'):
        for mat in template.get(bucket) or []:
            mid = mat.get('material_id') or ''
            if not mid:
                continue
            target = layout.baseline_dir / f'{mid}.http'
            example = layout.baseline_dir / f'{mid}.http.example'
            if target.exists() or example.exists():
                continue
            hint = mat.get('user_instruction') or mid
            fields = ', '.join((mat.get('covers_fields') or [])[:8])
            example.write_text(
                f'# material_id: {mid}\n'
                f'# priority: {mat.get("priority", bucket)}\n'
                f'# {hint}\n'
                f'# covers_fields: {fields or "see OUTPUT/baseline_material_template.json"}\n'
                f'# 填写后: 重命名为 {mid}.http 或直接新建 additions/{mid}.http\n\n',
                encoding='utf-8',
            )
            written.append(example)

    extra = layout.baseline_dir / EXTRA_CAPTURES_FILE
    if not extra.exists():
        extra.write_text(
            '# 通用扩展抓包（追加式）\n'
            '# 测试过程中缺什么，把对应 Raw HTTP 粘贴到下方即可\n\n',
            encoding='utf-8',
        )
        written.append(extra)
    return written


def write_baseline_manifest(
    layout: ProjectLayout,
    pack_dir: Path,
    *,
    summary: Dict[str, Any],
    intake: Optional[Dict[str, Any]] = None,
) -> Path:
    """User-facing import status — regenerated each scan (universal schema)."""
    intake = intake or _load_json(pack_dir / 'baseline_intake_report.json') or {}
    tmpl = _load_json(pack_dir / 'baseline_material_template.json') or {}
    template_check = intake.get('template_coverage') or {}

    by_id: Dict[str, Dict[str, Any]] = {}
    for bucket in ('required_materials', 'recommended_materials', 'deferred_materials'):
        for mat in tmpl.get(bucket) or []:
            mid = mat.get('material_id')
            if mid:
                by_id[mid] = mat

    covered = template_check.get('covered_by_capture') or {}
    material_status: Dict[str, Any] = {}
    for mid, mat in by_id.items():
        idxs = covered.get(mid) or []
        material_status[mid] = {
            'priority': mat.get('priority'),
            'satisfied': bool(idxs),
            'from_capture_indexes': idxs,
            'instruction': mat.get('user_instruction'),
            'covers_fields': mat.get('covers_fields') or [],
            'suggested_filename': f'{mid}.http',
        }

    manifest = {
        'schema_version': '1.0.0',
        'updated_at': _utc_now(),
        'import_policy': 'merge_all_http_files_on_each_scan',
        'project_id': layout.project_id,
        'files_scanned': summary.get('files_used') or [],
        'file_summaries': summarize_baseline_files(layout),
        'capture_count': summary.get('capture_count'),
        'acceptable_captures': summary.get('acceptable'),
        'field_count': summary.get('field_count'),
        'crypto_replay_ready': summary.get('crypto_replay_ready'),
        'n1_gate': summary.get('n1_gate'),
        'missing_required_materials': summary.get('missing_required') or [],
        'material_status': material_status,
        'how_to_add_more': [
            f'新建 {rel_display(layout.additions_dir, base=layout.workspace)}/任意名.http',
            f'追加 {rel_display(layout.baseline_dir / EXTRA_CAPTURES_FILE, base=layout.workspace)}',
            f'查看 {SUPPLEMENT_NEEDED_FILE} 了解仍缺材料',
            '重新运行向导步骤 5（Enter）自动重扫全部文件',
        ],
    }
    out = layout.baseline_dir / MANIFEST_FILE
    write_json(out, manifest)
    return out


def sync_supplement_needed_doc(
    layout: ProjectLayout,
    pack_dir: Path,
    *,
    summary: Optional[Dict[str, Any]] = None,
) -> Path:
    """Write profile-driven gap list for user (static template + dynamic test)."""
    lines = [
        '# 仍需补充的运行态材料',
        '',
        f'> 生成时间 {_utc_now()} · 项目 `{layout.project_id}`',
        '',
        '## 如何补充（通用）',
        '',
        f'1. 在 `{rel_display(layout.additions_dir, base=layout.workspace)}/` 新建 `.http`',
        f'2. 或追加 `{rel_display(layout.baseline_dir / EXTRA_CAPTURES_FILE, base=layout.workspace)}`',
        '3. 重新运行向导步骤 5（Enter 自动重扫）',
        '',
    ]

    summary = summary or {}
    missing_mats = summary.get('missing_required') or []
    tmpl = _load_json(pack_dir / 'baseline_material_template.json') or {}
    by_id = {
        m['material_id']: m
        for bucket in ('required_materials', 'recommended_materials', 'deferred_materials')
        for m in (tmpl.get(bucket) or [])
        if m.get('material_id')
    }

    if missing_mats:
        lines.append('## 静态模板仍缺（首次 baseline）')
        lines.append('')
        for mid in missing_mats:
            mat = by_id.get(mid) or {}
            lines.append(f'### `{mid}`')
            lines.append(f'- 说明: {mat.get("user_instruction", "见 baseline_material_template.json")}')
            lines.append(f'- 建议文件: `{mid}.http` 或 `additions/{mid}.http`')
            fields = mat.get('covers_fields') or []
            if fields:
                lines.append(f'- 期望字段: {", ".join(fields[:12])}')
            lines.append('')

    checklist = _load_json(pack_dir / 'user_intake_checklist.json') or {}
    items = checklist.get('items') or []
    seen_fields: Set[str] = set()
    dynamic_items: List[Dict[str, Any]] = []
    for it in items:
        field = (it.get('field') or '').strip()
        if not field or field in seen_fields:
            continue
        seen_fields.add(field)
        dynamic_items.append(it)

    if dynamic_items:
        lines.append('## 动态测试发现仍缺（可补充更多信息）')
        lines.append('')
        for it in dynamic_items[:12]:
            field = it.get('field') or '?'
            lines.append(f'### 字段 `{field}`')
            if it.get('why'):
                lines.append(f'- 原因: {it["why"]}')
            if it.get('path'):
                lines.append(f'- 参考接口: `{it["path"]}`')
            lines.append(
                f'- 做法: 抓一条 **响应中含 `{field}`** 的业务请求，放入 `additions/` 或 `{EXTRA_CAPTURES_FILE}`'
            )
            lines.append('')

    if len(lines) <= 8:
        lines.append('## 当前无已知缺口')
        lines.append('')
        lines.append('如需主动提供更多业务场景，仍可在 `additions/` 追加任意 `.http`。')

    out = layout.baseline_dir / SUPPLEMENT_NEEDED_FILE
    out.write_text('\n'.join(lines), encoding='utf-8')
    return out


def import_all_baseline_captures(
    layout: ProjectLayout,
    pack_dir: Path,
    *,
    source_dir: Path,
    materialize: bool = True,
) -> Tuple[bool, Dict[str, Any]]:
    """Merge all baseline/**/*.http → intelligent intake → import."""
    from minidrifter.materials.intelligent_intake import run_intelligent_baseline_intake
    from minidrifter.orchestration.project_readiness import baseline_replay_ready
    from minidrifter.orchestration.workbench_run import _ensure_baseline_graph

    pack_dir = Path(pack_dir)
    if not (pack_dir / 'baseline_material_template.json').exists():
        if not _ensure_baseline_graph(pack_dir):
            return False, {'error': 'baseline_template_failed'}

    sync_baseline_to_pack(layout)
    combined, used_files = load_combined_baseline_text(layout)
    if not combined.strip():
        return False, {'error': 'no_capture_content', 'files': []}

    print(status(f'合并 {len(used_files)} 个抓包文件，正在解析全部 HTTP 请求…', 'RUN'))
    for row in summarize_baseline_files(layout):
        if row['name'] in {p.name for p in used_files}:
            samples = ', '.join(row['sample_paths'][:2]) or '-'
            print(f'       {row["name"]}: {row["request_count"]} 条 → {samples}')

    result = run_intelligent_baseline_intake(
        pack_dir,
        combined,
        source_dir=source_dir,
        source_label='baseline_directory_batch',
        import_after=True,
        materialize_after=materialize,
        materialize_limit=120,
    )

    intake = _load_json(pack_dir / 'baseline_intake_report.json') or {}
    n1 = intake.get('n1_gate') or {}
    cov = intake.get('template_coverage') or {}
    missing = cov.get('missing_required_materials') or []

    ctx_path = pack_dir / 'baseline_runtime_context.json'
    ctx = _load_json(ctx_path) or {}
    ok = baseline_replay_ready(ctx)

    summary = {
        'files_used': [rel_display(p, base=layout.workspace) for p in used_files],
        'capture_count': intake.get('capture_count'),
        'acceptable': (intake.get('summary') or {}).get('acceptable'),
        'n1_gate': n1.get('overall'),
        'missing_required': missing,
        'field_count': ctx.get('field_count'),
        'crypto_replay_ready': ctx.get('crypto_replay_ready'),
        'intake_result': result,
    }
    write_json(pack_dir / 'baseline_batch_import.json', summary)
    artifact(pack_dir / 'baseline_batch_import.json')
    write_baseline_manifest(layout, pack_dir, summary=summary, intake=intake)
    artifact(layout.baseline_dir / MANIFEST_FILE)
    sync_supplement_needed_doc(layout, pack_dir, summary=summary)
    artifact(layout.baseline_dir / SUPPLEMENT_NEEDED_FILE)
    return ok, summary


def print_baseline_gap_guide(
    layout: ProjectLayout,
    pack_dir: Path,
    summary: Dict[str, Any],
) -> None:
    sync_supplement_needed_doc(layout, pack_dir, summary=summary)
    missing = summary.get('missing_required') or []
    hints: List[str] = [
        '材料按 **内容** 自动匹配，文件名可任意。',
        f'补充后 Enter 重扫: {rel_display(layout.baseline_dir, base=layout.workspace)}/',
        f'详情: {rel_display(layout.baseline_dir / SUPPLEMENT_NEEDED_FILE, base=layout.workspace)}',
    ]
    if missing:
        hints.append(f'仍缺 material_id: {", ".join(missing[:6])}')
    panel('Baseline 仍不完整 — 见 supplement_needed.md', hints)
