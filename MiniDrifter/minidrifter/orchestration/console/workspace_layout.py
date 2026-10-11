# -*- coding: utf-8 -*-
"""Workspace project layout — source / baseline / OUTPUT under each mini-program."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple

BASELINE_DIR = 'baseline'
OUTPUT_DIR = 'OUTPUT'
BASELINE_MATERIALS = 'user_materials'
BASELINE_ADDITIONS = 'additions'
EXTRA_CAPTURES_FILE = 'extra_captures.http'
MANIFEST_FILE = 'baseline_manifest.json'
SUPPLEMENT_NEEDED_FILE = 'supplement_needed.md'
HOW_TO_ADD_FILE = 'HOW_TO_ADD.md'
WORKSPACE_SKIP = frozenset({
    'captures', 'runs', 'decompiled', 'projects', '.git', '__pycache__',
})


@dataclass(frozen=True)
class ProjectLayout:
    project_id: str
    source_dir: Path
    baseline_dir: Path
    output_dir: Path
    workspace: Path

    @property
    def baseline_materials_dir(self) -> Path:
        return self.baseline_dir / BASELINE_MATERIALS

    @property
    def additions_dir(self) -> Path:
        return self.baseline_dir / BASELINE_ADDITIONS


# Tool package directory names under the repo root (new + legacy).
_TOOL_DIR_MARKERS = ('MiniDrifter', 'MiniDrifter_project')


def _is_repo_root(path: Path) -> bool:
    """Fse-style root: Workspace/ plus MiniDrifter/ (or legacy MiniDrifter_project/)."""
    if not (path / 'Workspace').is_dir():
        return False
    return any((path / name).is_dir() for name in _TOOL_DIR_MARKERS)


def find_MiniDrifter_root(start: Optional[Path] = None) -> Path:
    """Repo root containing Workspace/ and MiniDrifter/ (legacy: MiniDrifter_project/)."""
    cursor = (start or Path.cwd()).resolve()
    for _ in range(8):
        if _is_repo_root(cursor):
            return cursor
        if cursor.parent == cursor:
            break
        cursor = cursor.parent
    # fallback: MiniDrifter/MiniDrifter/orchestration/console -> repo root
    return Path(__file__).resolve().parents[3].parent


def default_workspace(*, MiniDrifter_root: Optional[Path] = None) -> Path:
    root = MiniDrifter_root or find_MiniDrifter_root()
    return root / 'Workspace'


def rel_display(path: Path | str, *, base: Path) -> str:
    """Show path relative to base when possible."""
    p = Path(path).resolve()
    base = base.resolve()
    try:
        return str(p.relative_to(base)).replace('\\', '/')
    except ValueError:
        try:
            return str(p.relative_to(find_MiniDrifter_root())).replace('\\', '/')
        except ValueError:
            return str(p)


def project_layout(workspace: Path, project_id: str) -> ProjectLayout:
    ws = Path(workspace).resolve()
    source = ws / project_id
    return ProjectLayout(
        project_id=project_id,
        source_dir=source,
        baseline_dir=source / BASELINE_DIR,
        output_dir=source / OUTPUT_DIR,
        workspace=ws,
    )


def layout_from_pack_dir(pack_dir: Path) -> ProjectLayout:
    """Resolve Workspace/<项目>/baseline + OUTPUT from an OUTPUT pack path."""
    pack_dir = Path(pack_dir).resolve()
    project_root = pack_dir.parent
    return project_layout(project_root.parent, project_root.name)


def ensure_project_layout(layout: ProjectLayout) -> None:
    layout.baseline_dir.mkdir(parents=True, exist_ok=True)
    layout.baseline_materials_dir.mkdir(parents=True, exist_ok=True)
    layout.additions_dir.mkdir(parents=True, exist_ok=True)
    layout.output_dir.mkdir(parents=True, exist_ok=True)
    readme = layout.baseline_dir / 'README.txt'
    if not readme.exists():
        readme.write_text(_baseline_readme_text(layout.project_id), encoding='utf-8')


def _baseline_readme_text(project_id: str) -> str:
    return f"""MiniDrifter Baseline — {project_id}
================================

在此目录保存「运行态抓包」（Raw HTTP），供动态验证重放签名与 Token。

需要保存哪些请求？
------------------
1. 【必填】登录后的成功业务请求
   - 必须含：Token / Authorization、AppVersion、Host
   - 示例：首页列表、设备列表、任意 200 业务接口

2. 【必填】用户信息 / 个人中心
   - 响应 JSON 中需含 UserId（或等价用户标识）

3. 【推荐】设备 / 订单 / 发票等业务对象列表
   - 便于链式验证解锁 OrderId、DeviceId 等字段

保存方式
--------
- 推荐: 导出完整 HAR 为 capture_full.har（Charles/Burp/mitmproxy）
- 或: 每个 .http 文件放一条完整「请求+响应」（如 1.http、2.http）
- 也可: 一个文件内多条 Raw HTTP（工具按 GET/POST 行自动拆分）
- 补充: 缺材料时编辑 extra_captures.http 或新增 7.http
- 模板: *.http.example 填写后改名为 .http
- 向导会扫描本目录全部 .http / .har 并合并分析

目录结构
--------
  {project_id}/baseline/*.http          ← 你粘贴/保存的抓包
  {project_id}/baseline/user_materials/   ← 向导自动归档
  {project_id}/OUTPUT/                    ← 静态分析与测试结果（勿手动改）
"""


def list_baseline_capture_files(layout: ProjectLayout) -> List[Path]:
    files: List[Path] = []
    for folder in (
        layout.baseline_dir,
        layout.baseline_materials_dir,
        layout.additions_dir,
    ):
        if folder.is_dir():
            files.extend(sorted(folder.glob('*.http')))
            files.extend(sorted(folder.glob('*.har')))
            files.extend(sorted(folder.glob('*.txt')))
    # Approach §3 capture kit (τ_A / τ_B)
    crbd_trace = layout.source_dir / 'CRBD_validation' / 'trace'
    for subject in ('subject_A', 'subject_B', 'raw'):
        folder = crbd_trace / subject
        if folder.is_dir():
            files.extend(sorted(folder.glob('*.http')))
            files.extend(sorted(folder.glob('*.har')))
            files.extend(sorted(folder.glob('*.txt')))
    seen = set()
    out: List[Path] = []
    for f in files:
        low = f.name.lower()
        if low in ('readme.txt',) or low.endswith('.http.example') or low.endswith('.placeholder'):
            continue
        if '.bak' in low or low.startswith('_'):
            continue
        key = f.resolve()
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def sync_baseline_to_pack(layout: ProjectLayout) -> List[Path]:
    """Copy baseline captures into OUTPUT/user_materials for import pipeline."""
    pack_materials = layout.output_dir / BASELINE_MATERIALS
    pack_materials.mkdir(parents=True, exist_ok=True)
    copied: List[Path] = []
    for src in list_baseline_capture_files(layout):
        dest = pack_materials / src.name
        if not dest.exists() or src.stat().st_mtime > dest.stat().st_mtime:
            dest.write_text(src.read_text(encoding='utf-8', errors='replace'), encoding='utf-8')
        copied.append(dest)
    return copied


def ensure_workspace_root(ws: Optional[Path] = None) -> Path:
    ws = Path(ws or default_workspace()).resolve()
    ws.mkdir(parents=True, exist_ok=True)
    readme = ws / 'README.txt'
    if not readme.exists():
        readme.write_text(
            'MiniDrifter Workspace\n'
            '==================\n'
            '每个小程序一个子目录（含 app.json 或 app.js）：\n'
            '  <项目名>/              反编译源码\n'
            '  <项目名>/baseline/     存放运行态抓包 (.http / .har)\n'
            '  <项目名>/OUTPUT/       静态分析与测试结果\n\n'
            '从仓库根目录运行: python MiniDrifter/run_minidrifter.py\n'
            '或从 MiniDrifter 目录: python run_minidrifter.py\n',
            encoding='utf-8',
        )
    return ws


def ensure_baseline_for_pack(pack_dir: Path, *, write_slots: bool = True) -> ProjectLayout:
    """Create <项目>/baseline/ when static analysis needs user captures."""
    layout = layout_from_pack_dir(pack_dir)
    ensure_project_layout(layout)
    if write_slots:
        from minidrifter.orchestration.console.baseline_batch import write_baseline_slot_files
        write_baseline_slot_files(layout, Path(pack_dir))
    return layout
