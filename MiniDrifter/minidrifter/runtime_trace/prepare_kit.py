# -*- coding: utf-8 -*-
"""Prepare per-project CRBD_validation/trace kits for legitimate capture intake."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from minidrifter.core.utils import write_json

KIT_DIR_NAME = 'CRBD_validation'
TRACE_DIR_NAME = 'trace'
SCHEMA_VERSION = '1.0.0'


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _load(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding='utf-8'))


def _ccr_index(ccrs: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    return {c.get('operation_id'): c for c in ccrs if c.get('operation_id')}


def _op_label(RCR: Dict[str, Any]) -> str:
    ep = RCR.get('endpoint') or {}
    method = (
        (RCR.get('method') or {}).get('value')
        or ((RCR.get('request_semantics') or {}).get('operation') or {}).get('method')
        or 'UNKNOWN'
    )
    host = ep.get('host') or ''
    path = ep.get('path') or ''
    return f'{method} {host}{path}'.strip()


def build_capture_targets(
    pack_dir: Path,
    *,
    max_workflows: int = 12,
    max_ops_per_wf: int = 10,
) -> Dict[str, Any]:
    """Derive human/machine capture checklist from OUTPUT artifacts."""
    pack_dir = Path(pack_dir)
    host_doc = _load(pack_dir / 'host_resolution.json')
    from minidrifter.rcr.io import load_rcr_pack
    rcr_doc = load_rcr_pack(pack_dir)
    wf_doc = _load(pack_dir / 'workflows.json')
    from minidrifter.rpgraph.io import load_rpgraph
    graph = load_rpgraph(pack_dir)
    drift = _load(pack_dir / 'drift_plans.json')

    ccrs = list(rcr_doc.get('ccrs') or [])
    by_oid = _ccr_index(ccrs)
    default_host = host_doc.get('default_business_host') or ''
    identity_anchors = sorted({
        str((c.get('request_semantics') or {}).get('identity_anchor') or '')
        for c in ccrs
        if (c.get('request_semantics') or {}).get('identity_anchor')
    })

    workflows_out = []
    for wf in (wf_doc.get('workflows') or [])[:max_workflows]:
        target = wf.get('target') or {}
        ops = []
        for oid in (wf.get('operations') or [])[:max_ops_per_wf]:
            RCR = by_oid.get(oid) or {}
            ep = RCR.get('endpoint') or {}
            ops.append({
                'operation_id': oid,
                'method': (RCR.get('method') or {}).get('value') or 'UNKNOWN',
                'host': ep.get('host') or '',
                'path': ep.get('path') or '',
                'binding_credentials': list(RCR.get('binding_credentials') or []),
                'identity_anchor': (RCR.get('request_semantics') or {}).get('identity_anchor'),
                'label': _op_label(RCR),
            })
        workflows_out.append({
            'workflow_id': wf.get('workflow_id'),
            'scope': wf.get('scope'),
            'target_path': target.get('path'),
            'target_credential': target.get('credential'),
            'target_operation_id': target.get('operation_id'),
            'operations': ops,
            'ui_hint': _ui_hint(target.get('path') or ''),
        })

    # Unique high-value paths for filtering in Charles/mitmproxy
    path_filter = sorted({
        op.get('path') for w in workflows_out for op in w.get('operations') or [] if op.get('path')
    })
    bind_fields = sorted({
        f
        for w in workflows_out
        for op in w.get('operations') or []
        for f in (op.get('binding_credentials') or [])
    })

    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': _utc_now(),
        'project_pack': str(pack_dir),
        'default_business_host': default_host,
        'identity_anchors': identity_anchors,
        'binding_fields_of_interest': bind_fields[:40],
        'path_filter': path_filter[:80],
        'workflow_count_available': int(wf_doc.get('workflow_count') or 0),
        'drift_plan_count_available': int(drift.get('drift_plan_count') or 0),
        'graph_summary': graph.get('summary') or {},
        'priority_workflows': workflows_out,
        'accepted_formats': ['.har', '.http', '.json'],
        'layout': {
            'subject_A': 'trace/subject_A/  — 合法主体 A 的完整业务抓包 τ_A',
            'subject_B': 'trace/subject_B/  — 捐赠主体 B 的对照抓包 τ_B（仅提供漂移槽位凭证，不替换 A 身份）',
            'raw': 'trace/raw/  — 未拆分的原始 HAR/导出，可选',
        },
    }


def _ui_hint(path: str) -> str:
    p = (path or '').lower()
    if 'login' in p or 'auth' in p or 'token' in p:
        return '完成登录/授权后立刻导出该段流量'
    if 'list' in p or 'query' in p or 'search' in p:
        return '进入列表/查询页并触发刷新'
    if 'detail' in p or 'info' in p:
        return '从列表点进详情页'
    if 'pay' in p or 'order' in p:
        return '走到下单/支付相关页（可用沙箱/测试单，勿提交真实资金）'
    if 'upload' in p or 'idcard' in p or 'verify' in p:
        return '进入实名/认证/上传相关流程并触发接口'
    if 'address' in p or 'city' in p:
        return '选择城市/地址并确认'
    if 'coupon' in p:
        return '打开优惠券/权益页'
    return '按小程序正常业务路径操作直至该接口出现'


def render_guide_markdown(project_name: str, targets: Dict[str, Any]) -> str:
    host = targets.get('default_business_host') or '(见 OUTPUT/host_resolution.json)'
    anchors = targets.get('identity_anchors') or []
    bind_fields = targets.get('binding_fields_of_interest') or []
    paths = targets.get('path_filter') or []
    wfs = targets.get('priority_workflows') or []

    lines: List[str] = []
    lines.append(f'# {project_name} — RR-Drift 合法抓包指引（τ_A / τ_B）')
    lines.append('')
    lines.append('> 本文档由静态合同恢复（RCR）与绑定连续工作流（§2）自动生成，用于指导你提供**真实抓包**，供后续 Trace-Guided Materialization（§3）使用。')
    lines.append('')
    lines.append('## 1. 你要交付什么')
    lines.append('')
    lines.append('请在本目录按身份分开放置抓包文件：')
    lines.append('')
    lines.append('| 目录 | 含义 | 必须？ |')
    lines.append('|------|------|--------|')
    lines.append('| `subject_A/` | 合法主体 **A** 的完整业务轨迹 τ_A（登录态 + 走到敏感目标） | **是** |')
    lines.append('| `subject_B/` | 另一合法主体 **B** 的对照轨迹 τ_B（提供漂移用业务凭证） | 建议有（做跨主体漂移验证时需要） |')
    lines.append('| `raw/` | 未拆分的原始导出（可选备份） | 否 |')
    lines.append('')
    lines.append('支持格式：`.har`（推荐）、`.http`（原始 HTTP 报文）、`.json`（结构化导出）。')
    lines.append('')
    lines.append('## 2. 抓包过滤建议')
    lines.append('')
    lines.append(f'- **主业务 Host**：`{host}`')
    lines.append('- 代理工具：Charles / mitmproxy / Fiddler / 微信开发者工具 Network 导出均可')
    lines.append('- 尽量只保留业务 API；可丢弃静态资源、埋点、地图 SDK（除非工作流明确依赖）')
    if anchors:
        lines.append(f'- **身份锚点字段**（须保持为 A，勿在漂移时替换）：`{", ".join(anchors[:8])}`')
    if bind_fields:
        lines.append(f'- **业务绑定字段**（列表/详情间会传递，请确保响应与后续请求中可见）：`{", ".join(bind_fields[:20])}`')
    lines.append('')
    lines.append('## 3. 推荐操作顺序（按优先级工作流）')
    lines.append('')
    lines.append('对主体 A：先登录，再按下列路径操作一次成功业务；导出时尽量覆盖下列 API。')
    lines.append('对主体 B：用**另一个账号**重复相近路径，至少覆盖带绑定字段的列表/详情接口。')
    lines.append('')
    if not wfs:
        lines.append('_当前 OUTPUT 尚无 workflows.json；请先运行静态分析与工作流重建，再重新生成本指引。_')
    for i, wf in enumerate(wfs, 1):
        lines.append(f'### 3.{i} `{wf.get("workflow_id")}`')
        lines.append('')
        lines.append(f'- **目标路径**：`{wf.get("target_path")}`')
        lines.append(f'- **目标凭证槽**：`{wf.get("target_credential")}`')
        lines.append(f'- **身份 scope**：`{wf.get("scope")}`')
        lines.append(f'- **界面提示**：{wf.get("ui_hint")}')
        lines.append('- **建议覆盖的请求（顺序供参考）**：')
        for op in wf.get('operations') or []:
            creds = ', '.join(op.get('binding_credentials') or []) or '—'
            lines.append(
                f'  - `{op.get("method")} {op.get("path")}`'
                f' 绑定字段=`{creds}`'
            )
        lines.append('')

    lines.append('## 4. 路径白名单（便于代理过滤）')
    lines.append('')
    if paths:
        for p in paths[:60]:
            lines.append(f'- `{p}`')
    else:
        lines.append('- （暂无；请按主 Host 全量抓取登录后业务流量）')
    lines.append('')
    lines.append('## 5. 文件命名约定')
    lines.append('')
    lines.append('```')
    lines.append('trace/subject_A/')
    lines.append('  01_login.har')
    lines.append('  02_business_flow.har          # 或合并为一个 full_session_A.har')
    lines.append('  notes.md                      # 可选：账号角色、操作步骤备注（勿写密码）')
    lines.append('trace/subject_B/')
    lines.append('  01_login.har')
    lines.append('  02_business_flow.har')
    lines.append('```')
    lines.append('')
    lines.append('也接受单文件：`subject_A/full_session.har`。')
    lines.append('')
    lines.append('## 6. 质量检查（提交前自检）')
    lines.append('')
    lines.append('- [ ] A 的抓包包含登录/鉴权后的业务请求，且身份头/Cookie 一致')
    lines.append('- [ ] 至少一条敏感目标路径（见 §3）在 A 的轨迹中出现且应用层成功（非纯 4xx/5xx）')
    lines.append('- [ ] 绑定字段在上游响应与下游请求中可观察（或可从后续响应再生）')
    lines.append('- [ ] A/B 未混在同一文件；B 不用于替换 A 的登录态')
    lines.append('- [ ] 已脱敏：可去掉支付密码、短信验证码明文；保留 token/业务 id 供实验环境使用')
    lines.append('')
    lines.append('## 7. 放好文件之后')
    lines.append('')
    lines.append('本步骤**只要求你提供抓包**。后续工具会读取 `trace/subject_A`（与可选 `subject_B`）做：')
    lines.append('')
    lines.append('1. Trace-Guided Workflow Materialization → 合法执行 W_t^A')
    lines.append('2. 结合 `OUTPUT/drift_plans.json` 做反馈引导漂移验证')
    lines.append('')
    lines.append('重新生成本指引（不覆盖你已放入的 `.har/.http`）：')
    lines.append('')
    lines.append('```bash')
    lines.append('cd MiniDrifter')
    lines.append(f'python -m minidrifter.cli prepare-trace-kit -p "<项目目录>"')
    lines.append('# 或批量：')
    lines.append('python scripts/prepare_workspace_trace_kits.py -w "D:/Work/NKU/Fse/Workspace"')
    lines.append('```')
    lines.append('')
    lines.append(f'_generated_at: {targets.get("generated_at")}_')
    lines.append('')
    return '\n'.join(lines)


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding='utf-8')


def _ensure_placeholder(dir_path: Path, readme: str) -> None:
    dir_path.mkdir(parents=True, exist_ok=True)
    keep = dir_path / '.gitkeep'
    if not keep.exists():
        keep.write_text('', encoding='utf-8')
    readme_path = dir_path / 'README.md'
    # Always refresh short README; never delete user captures
    _write_text(readme_path, readme)


def prepare_trace_kit(
    project_dir: Path | str,
    *,
    pack_dir: Optional[Path | str] = None,
    max_workflows: int = 12,
) -> Dict[str, Any]:
    """Create CRBD_validation/trace scaffold + guide for one Workspace project."""
    project_dir = Path(project_dir).resolve()
    pack = Path(pack_dir).resolve() if pack_dir else (project_dir / 'OUTPUT')
    kit_root = project_dir / KIT_DIR_NAME
    trace_root = kit_root / TRACE_DIR_NAME

    # Ensure workflow artifacts exist when possible
    if (pack / 'rcr_pack.json').exists() and not (pack / 'workflows.json').exists():
        try:
            from minidrifter.rpgraph.export import write_rpgraph_pack
            write_rpgraph_pack(pack)
        except Exception:
            pass

    targets = build_capture_targets(pack, max_workflows=max_workflows)
    guide = render_guide_markdown(project_dir.name, targets)

    trace_root.mkdir(parents=True, exist_ok=True)
    _write_text(trace_root / '抓包指引.md', guide)
    write_json(trace_root / 'capture_targets.json', targets)

    _ensure_placeholder(
        trace_root / 'subject_A',
        '# subject_A（τ_A）\n\n将主体 **A** 的合法业务抓包放在此目录（`.har` / `.http` / `.json`）。\n\n详见上级 `抓包指引.md`。\n',
    )
    _ensure_placeholder(
        trace_root / 'subject_B',
        '# subject_B（τ_B）\n\n将主体 **B** 的对照抓包放在此目录，用于捐赠业务绑定凭证。\n\n**不要**用 B 的登录态替换 A。详见上级 `抓包指引.md`。\n',
    )
    _ensure_placeholder(
        trace_root / 'raw',
        '# raw\n\n可选：放置未拆分的原始导出文件。\n',
    )

    manifest = {
        'schema_version': SCHEMA_VERSION,
        'generated_at': _utc_now(),
        'project': project_dir.name,
        'project_dir': str(project_dir),
        'pack_dir': str(pack),
        'kit_dir': str(kit_root),
        'trace_dir': str(trace_root),
        'guide': str(trace_root / '抓包指引.md'),
        'capture_targets': str(trace_root / 'capture_targets.json'),
        'default_business_host': targets.get('default_business_host'),
        'priority_workflow_count': len(targets.get('priority_workflows') or []),
        'status': 'awaiting_captures',
        'note': 'Place real captures under trace/subject_A and optionally trace/subject_B. Guide refresh will not delete capture files.',
    }
    write_json(kit_root / 'manifest.json', manifest)
    _write_text(
        kit_root / 'README.md',
        (
            f'# {project_dir.name} — CRBD_validation\n\n'
            '本目录用于 §3 动态验证前的**合法轨迹投递**。\n\n'
            '- 请阅读并遵循：[`trace/抓包指引.md`](trace/抓包指引.md)\n'
            '- 机器可读目标清单：[`trace/capture_targets.json`](trace/capture_targets.json)\n'
            '- 把真实抓包放入 `trace/subject_A/`（必需）与 `trace/subject_B/`（建议）\n'
        ),
    )
    return manifest


def prepare_workspace_trace_kits(
    workspace: Path | str,
    *,
    only: Optional[str] = None,
    max_workflows: int = 12,
) -> Dict[str, Any]:
    from minidrifter.runtime.workspace_paths import list_workspace_projects

    workspace = Path(workspace).resolve()
    projects = [p for _, p in list_workspace_projects(workspace)]
    if only:
        projects = [p for p in projects if only.lower() in p.name.lower()]

    results = []
    for proj in projects:
        try:
            m = prepare_trace_kit(proj, max_workflows=max_workflows)
            results.append({'project': proj.name, 'ok': True, **m})
        except Exception as exc:
            results.append({
                'project': proj.name,
                'ok': False,
                'error': f'{type(exc).__name__}: {exc}',
            })

    report = {
        'schema_version': SCHEMA_VERSION,
        'generated_at': _utc_now(),
        'workspace': str(workspace),
        'ok_count': sum(1 for r in results if r.get('ok')),
        'project_count': len(results),
        'projects': results,
    }
    write_json(workspace / 'trace_kit_report.json', report)
    return report
