# -*- coding: utf-8 -*-
"""
MiniCrest 批量流水线（并行 + 已处理记忆）：
1) 扫描微信小程序 packages 缓存
2) 并行 wedecode 解包
3) 并行实名识别 + 行业粗分 + 归档
4) 按 appid 记录已处理，默认跳过重复

用法:
  python pipeline.py                 # 并行全量（跳过已处理）
  python pipeline.py --force         # 强制重跑（含已处理）
  python pipeline.py --workers 6     # 指定并行数
  python pipeline.py --classify-only # 仅对 _raw 已有产物分类
  python pipeline.py --dry-run       # 只扫描不执行
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from datetime import datetime
from pathlib import Path
from uuid import uuid4

from classify import CATEGORIES, DEFAULT_CATEGORY, classify_app
from discover import discover_packages_roots, resolve_packages_roots
from identify import identify_miniprogram, folder_name_for, sanitize_dirname

TOOLS_DIR = Path(__file__).resolve().parent
DEFAULT_CONFIG = TOOLS_DIR / "config.json"
APPID_RE = re.compile(r"^wx[0-9a-fA-F]{16}$")
PRINT_LOCK = threading.Lock()
FS_LOCK = threading.Lock()
CANCEL_EVENT = threading.Event()
ACTIVE_PROCESSES_LOCK = threading.Lock()
ACTIVE_PROCESSES: set[subprocess.Popen] = set()


def load_config(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def category_list(cfg: dict | None = None) -> list[str]:
    if cfg and isinstance(cfg.get("categories"), list) and cfg["categories"]:
        return list(cfg["categories"])
    return list(CATEGORIES)


def category_roots(data_root: Path, cfg: dict | None = None) -> list[Path]:
    roots = [data_root / name for name in category_list(cfg)]
    if data_root.exists():
        for p in data_root.iterdir():
            if not p.is_dir():
                continue
            if p.name == "未识别_低置信" or re.match(r"^C[1-5]_", p.name):
                if p not in roots:
                    roots.append(p)
    return roots


def ensure_dirs(data_root: Path, raw_name: str, report_name: str, cfg: dict | None = None) -> tuple[Path, Path]:
    raw = data_root / raw_name
    reports = data_root / report_name
    raw.mkdir(parents=True, exist_ok=True)
    reports.mkdir(parents=True, exist_ok=True)
    for name in category_list(cfg):
        (data_root / name).mkdir(parents=True, exist_ok=True)
    return raw, reports


def log(msg: str) -> None:
    with PRINT_LOCK:
        print(msg, flush=True)


class PipelineCancelled(KeyboardInterrupt):
    """用户取消流水线。"""


def stop_active_processes(grace_sec: float = 3.0) -> None:
    with ACTIVE_PROCESSES_LOCK:
        processes = list(ACTIVE_PROCESSES)
    for proc in processes:
        if proc.poll() is None:
            try:
                proc.terminate()
            except OSError:
                pass
    deadline = time.monotonic() + grace_sec
    for proc in processes:
        if proc.poll() is not None:
            continue
        try:
            proc.wait(timeout=max(0.0, deadline - time.monotonic()))
        except (OSError, subprocess.TimeoutExpired):
            try:
                proc.kill()
            except OSError:
                pass


def windows_extended_path(path: Path) -> str:
    """在 Windows 上使用长路径前缀，避免深层解包目录触发 WinError 206。"""
    value = str(path.resolve())
    if os.name != "nt" or value.startswith("\\\\?\\"):
        return value
    if value.startswith("\\\\"):
        return "\\\\?\\UNC\\" + value[2:]
    return "\\\\?\\" + value


def copytree_long_path(src: Path, dest: Path) -> None:
    shutil.copytree(windows_extended_path(src), windows_extended_path(dest))


def rmtree_long_path(path: Path, ignore_errors: bool = False) -> None:
    shutil.rmtree(windows_extended_path(path), ignore_errors=ignore_errors)


def output_snapshot(path: Path) -> tuple[int, int, bool]:
    """返回文件数、最新修改时间(ns)、是否含 app.json。"""
    file_count = 0
    latest_mtime_ns = 0
    has_app_json = False
    try:
        for root, _dirs, files in os.walk(windows_extended_path(path)):
            for name in files:
                file_count += 1
                if name.lower() == "app.json":
                    has_app_json = True
                try:
                    mtime_ns = os.stat(os.path.join(root, name)).st_mtime_ns
                    latest_mtime_ns = max(latest_mtime_ns, mtime_ns)
                except OSError:
                    continue
    except OSError:
        return 0, 0, False
    return file_count, latest_mtime_ns, has_app_json


def process_cpu_seconds(proc: subprocess.Popen) -> float | None:
    """读取子进程累计 CPU 时间；Windows 上用于区分计算中与挂起。"""
    if os.name != "nt":
        return None
    try:
        import ctypes
        from ctypes import wintypes

        creation = wintypes.FILETIME()
        exited = wintypes.FILETIME()
        kernel = wintypes.FILETIME()
        user = wintypes.FILETIME()
        get_process_times = ctypes.windll.kernel32.GetProcessTimes
        get_process_times.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.FILETIME),
            ctypes.POINTER(wintypes.FILETIME),
            ctypes.POINTER(wintypes.FILETIME),
            ctypes.POINTER(wintypes.FILETIME),
        ]
        get_process_times.restype = wintypes.BOOL
        ok = get_process_times(
            wintypes.HANDLE(int(proc._handle)),  # type: ignore[attr-defined]
            ctypes.byref(creation),
            ctypes.byref(exited),
            ctypes.byref(kernel),
            ctypes.byref(user),
        )
        if not ok:
            return None

        def ticks(value: wintypes.FILETIME) -> int:
            return (int(value.dwHighDateTime) << 32) | int(value.dwLowDateTime)

        return (ticks(kernel) + ticks(user)) / 10_000_000.0
    except (AttributeError, OSError, TypeError, ValueError):
        return None


class ProcessedRegistry:
    """按 appid 记忆已成功处理的小程序。"""

    def __init__(self, path: Path, flush_every: int = 20):
        self.path = path
        self._lock = threading.Lock()
        self.data: dict[str, dict] = {}
        self._dirty = 0
        self._flush_every = max(1, int(flush_every))
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            self.data = {}
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            self.data = raw.get("items", raw) if isinstance(raw, dict) else {}
            if not isinstance(self.data, dict):
                self.data = {}
        except (OSError, json.JSONDecodeError):
            self.data = {}

    def _save_locked(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "updated_at": datetime.now().isoformat(timespec="seconds"),
            "count": len(self.data),
            "items": self.data,
        }
        tmp = self.path.with_name(f".{self.path.name}.{os.getpid()}.tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(self.path)
        self._dirty = 0

    def save(self) -> None:
        with self._lock:
            if self._dirty:
                self._save_locked()

    def has(self, appid: str, source_mtime: float | None = None, verify_archived: bool = False) -> bool:
        with self._lock:
            item = self.data.get(appid)
            if not item or item.get("status") != "ok":
                return False
            recorded_mtime = item.get("source_mtime")
            if source_mtime is not None and recorded_mtime is not None:
                if float(source_mtime) > float(recorded_mtime) + 1e-6:
                    return False
            # 默认信任登记表，避免外置盘反复 exists 卡死
            if not verify_archived:
                return True
            archived = item.get("archived_to")
            if not archived:
                return True
            try:
                return Path(archived).exists()
            except OSError:
                return True

    def mark(self, appid: str, info: dict) -> None:
        with self._lock:
            self.data[appid] = {
                **info,
                "updated_at": datetime.now().isoformat(timespec="seconds"),
            }
            self._dirty += 1
            if self._dirty >= self._flush_every:
                self._save_locked()

    def bootstrap_from_disk(self, data_root: Path, cfg: dict | None = None) -> int:
        """把磁盘上已归档的 appid 补进记忆，避免历史结果被重复处理。

        注意：Data 若在机械/外置盘，对每个目录 stat 会非常慢。
        已有记忆时默认跳过全盘扫描；仅缺记时才轻量补齐。
        """
        cfg = cfg or {}
        # 已有足够记忆则跳过（避免外置盘上千次 exists 卡死）
        if cfg.get("skip_bootstrap"):
            return 0
        min_skip = int(cfg.get("bootstrap_skip_if_count", 1) or 1)
        if len(self.data) >= min_skip and not cfg.get("force_bootstrap"):
            return 0

        pending: dict[str, dict] = {}
        known = set(self.data.keys())
        scanned = 0
        for root in category_roots(data_root, cfg):
            if not root.is_dir():
                continue
            try:
                entries = list(root.iterdir())
            except OSError:
                continue
            for p in entries:
                if not p.is_dir() or p.name.startswith(".minicrest_"):
                    continue
                scanned += 1
                appid = None
                m = re.search(r"(wx[0-9a-fA-F]{16})$", p.name)
                if m:
                    appid = m.group(1)
                # 优先用目录名里的 appid，避免每个目录都 stat meta 文件
                if not appid:
                    meta_path = p / "_minicrest_classify.json"
                    try:
                        if meta_path.is_file():
                            meta = json.loads(meta_path.read_text(encoding="utf-8"))
                            appid = meta.get("appid")
                    except (OSError, json.JSONDecodeError):
                        appid = None
                if not appid or appid in known or appid in pending:
                    continue
                pending[appid] = {
                    "status": "ok",
                    "nickname": p.name.rsplit("_", 1)[0] if "_" in p.name else p.name,
                    "primary": root.name,
                    "archived_to": str(p),
                    "source": "bootstrap_disk",
                    "updated_at": datetime.now().isoformat(timespec="seconds"),
                }
                if scanned % 200 == 0:
                    log(f"  bootstrap 扫描中... {scanned} 目录, 新发现 {len(pending)}")
        if pending:
            with self._lock:
                self.data.update(pending)
                self._dirty += len(pending)
                self._save_locked()
        return len(pending)


def find_existing_by_appid(data_root: Path, appid: str, cfg: dict | None = None) -> list[Path]:
    if not appid:
        return []
    found: list[Path] = []
    for root in category_roots(data_root, cfg):
        if not root.exists():
            continue
        for p in root.iterdir():
            if not p.is_dir() or p.name.startswith(".minicrest_"):
                continue
            if p.name == appid or p.name.endswith(f"_{appid}"):
                found.append(p)
                continue
            meta = p / "_minicrest_classify.json"
            if meta.exists():
                try:
                    data = json.loads(meta.read_text(encoding="utf-8"))
                    if data.get("appid") == appid:
                        found.append(p)
                except (OSError, json.JSONDecodeError):
                    pass
    uniq: list[Path] = []
    seen = set()
    for p in found:
        key = str(p.resolve())
        if key not in seen:
            seen.add(key)
            uniq.append(p)
    return uniq


def purge_existing_by_appid(data_root: Path, appid: str, cfg: dict | None = None) -> int:
    removed = 0
    for p in find_existing_by_appid(data_root, appid, cfg):
        shutil.rmtree(p, ignore_errors=True)
        removed += 1
    return removed


def _shallow_wxapkg_mtime(dir_path: Path) -> tuple[bool, float]:
    """浅扫目录内 *.wxapkg（最多两层），返回 (是否有包, 最新mtime)。"""
    newest = -1.0
    found = False
    try:
        base_mtime = dir_path.stat().st_mtime
        newest = base_mtime
    except OSError:
        return False, -1.0
    try:
        for child in dir_path.iterdir():
            if child.is_file() and child.suffix.lower() == ".wxapkg":
                found = True
                try:
                    newest = max(newest, child.stat().st_mtime)
                except OSError:
                    pass
            elif child.is_dir():
                try:
                    for f in child.iterdir():
                        if f.is_file() and f.suffix.lower() == ".wxapkg":
                            found = True
                            try:
                                newest = max(newest, f.stat().st_mtime)
                            except OSError:
                                pass
                except OSError:
                    pass
    except OSError:
        pass
    return found, newest


def find_pack_dirs(packages_root: Path | list[Path]) -> list[dict]:
    """扫描一个或多个 packages 根；同一 appid 只保留最新。"""
    roots = packages_root if isinstance(packages_root, list) else [packages_root]
    latest: dict[str, dict] = {}
    for packages_root in roots:
        if not packages_root.exists():
            continue
        for app_dir in packages_root.iterdir():
            if not app_dir.is_dir() or not APPID_RE.match(app_dir.name):
                continue
            appid = app_dir.name
            version_dirs = [p for p in app_dir.iterdir() if p.is_dir()]
            candidates = version_dirs or [app_dir]
            best = None
            best_mtime = -1.0
            for c in candidates:
                has_wxapkg, mtime = _shallow_wxapkg_mtime(c)
                if not has_wxapkg:
                    continue
                if mtime >= best_mtime:
                    best_mtime = mtime
                    best = c
            if best is None:
                continue
            prev = latest.get(appid)
            if prev is None or best_mtime >= prev["mtime"]:
                latest[appid] = {
                    "appid": appid,
                    "pack_dir": best,
                    "mtime": best_mtime,
                    "packages_root": packages_root,
                }
    return sorted(latest.values(), key=lambda x: x["mtime"], reverse=True)


def resolve_wedecode_cmd(cmd: str) -> list[str]:
    configured = Path(cmd) if cmd else None
    if configured and configured.suffix.lower() in {".js", ".cmd", ".exe"} and configured.exists():
        if configured.suffix.lower() == ".js":
            return ["node", str(configured)]
        return [str(configured)]

    npm_root = Path(os.environ.get("APPDATA", "")) / "npm"
    candidates = [
        npm_root / "node_modules" / "wedecode" / "dist" / "wedecode.js",
        npm_root / "wedecode.cmd",
    ]
    if cmd:
        candidates.append(Path(cmd))
    which_cmd = shutil.which(cmd) or shutil.which("wedecode.cmd") or shutil.which("wedecode")
    if which_cmd:
        candidates.append(Path(which_cmd))

    for c in candidates:
        if not c or not c.exists():
            continue
        if c.suffix.lower() == ".js":
            return ["node", str(c)]
        if c.suffix.lower() == ".cmd":
            return ["cmd", "/c", str(c)]
        return [str(c)]
    return [cmd or "wedecode"]


def _finish_proc(proc: subprocess.Popen, timeout: float = 15.0) -> None:
    """终止 wedecode 子进程并尽量收尸；不因 wait 超时而抛异常。"""
    if proc.poll() is not None:
        return
    try:
        proc.terminate()
    except OSError:
        pass
    deadline = time.monotonic() + max(0.5, timeout)
    while proc.poll() is None and time.monotonic() < deadline:
        try:
            proc.wait(timeout=min(0.5, max(0.05, deadline - time.monotonic())))
        except subprocess.TimeoutExpired:
            continue
    if proc.poll() is None:
        try:
            proc.kill()
        except OSError:
            pass
        try:
            proc.wait(timeout=5.0)
        except subprocess.TimeoutExpired:
            pass


def run_wedecode(
    cmd: str,
    pack_dir: Path,
    out_dir: Path,
    appid: str,
    dry_run: bool = False,
    timeout_sec: float = 600.0,
    output_stable_sec: float = 12.0,
    idle_kill_sec: float = 45.0,
    proc_wait_sec: float = 15.0,
) -> tuple[bool, str]:
    out_dir.parent.mkdir(parents=True, exist_ok=True)
    base = resolve_wedecode_cmd(cmd)
    args = [*base, str(pack_dir), "--out", str(out_dir), "--clear", "--wxid", appid]
    if dry_run:
        return True, " ".join(args)
    if CANCEL_EVENT.is_set():
        return False, "任务已取消"
    proc: subprocess.Popen | None = None
    log_path = out_dir.parent / f".wedecode_{appid}.log"
    forced_complete = False
    started_at = time.monotonic()
    started_wall_ns = time.time_ns()
    last_snapshot: tuple[int, int, bool] | None = None
    snapshot_changed_at = started_at
    last_cpu_total: float | None = None
    cpu_changed_at = started_at
    next_snapshot_at = started_at + 4.0
    log_fp = None
    try:
        # 不要 PIPE：wedecode 输出多时会把管道塞满导致 8 路并行全部假死。
        log_fp = open(log_path, "w", encoding="utf-8", errors="replace")
        proc = subprocess.Popen(
            args,
            stdout=log_fp,
            stderr=subprocess.STDOUT,
        )
        with ACTIVE_PROCESSES_LOCK:
            ACTIVE_PROCESSES.add(proc)
        while proc.poll() is None:
            if CANCEL_EVENT.is_set():
                _finish_proc(proc, timeout=proc_wait_sec)
                return False, "任务已取消"
            now = time.monotonic()
            elapsed = now - started_at
            if elapsed >= float(timeout_sec):
                try:
                    proc.kill()
                except OSError:
                    pass
                _finish_proc(proc, timeout=proc_wait_sec)
                log_text = _read_tail(log_path)
                return False, "wedecode 超时\n" + log_text
            if now >= next_snapshot_at:
                snapshot = output_snapshot(out_dir)
                cpu_total = process_cpu_seconds(proc)
                if cpu_total is not None:
                    if last_cpu_total is None or cpu_total - last_cpu_total >= 0.05:
                        cpu_changed_at = now
                    last_cpu_total = cpu_total
                fresh_output = snapshot[2] and snapshot[1] >= started_wall_ns - 5_000_000_000
                if fresh_output:
                    if snapshot != last_snapshot:
                        last_snapshot = snapshot
                        snapshot_changed_at = now
                    elif (
                        now - snapshot_changed_at >= float(output_stable_sec)
                        and (
                            cpu_total is None
                            or now - cpu_changed_at >= float(output_stable_sec)
                        )
                    ):
                        forced_complete = True
                        _finish_proc(proc, timeout=proc_wait_sec)
                        break
                elif (
                    idle_kill_sec > 0
                    and cpu_total is not None
                    and now - cpu_changed_at >= float(idle_kill_sec)
                ):
                    try:
                        proc.kill()
                    except OSError:
                        pass
                    _finish_proc(proc, timeout=proc_wait_sec)
                    log_text = _read_tail(log_path)
                    return (
                        False,
                        f"wedecode {idle_kill_sec:.0f}s 无 CPU/输出进展，已终止\n" + log_text,
                    )
                else:
                    last_snapshot = snapshot
                    snapshot_changed_at = now
                next_snapshot_at = now + 4.0
            time.sleep(0.5)
        if log_fp is not None:
            log_fp.close()
            log_fp = None
        try:
            snapshot = output_snapshot(out_dir)
            has_output = snapshot[0] > 0 and snapshot[2]
        except OSError:
            has_output = False
        ok = (proc.returncode == 0 or forced_complete) and has_output
        log_text = _read_tail(log_path)
        if forced_complete:
            log_text += "\n[pipeline] 输出已稳定，已结束未自行退出的 wedecode 进程"
        if not ok and not log_text.strip():
            log_text = f"exit={proc.returncode} cmd={' '.join(args)}"
        return ok, log_text[-4000:]
    except FileNotFoundError:
        return False, f"找不到命令: {' '.join(base)}，请确认已 npm i -g wedecode"
    finally:
        if log_fp is not None:
            try:
                log_fp.close()
            except OSError:
                pass
        if proc is not None:
            with ACTIVE_PROCESSES_LOCK:
                ACTIVE_PROCESSES.discard(proc)


def _read_tail(path: Path, max_chars: int = 3500) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")[-max_chars:]
    except OSError:
        return ""


def category_dir(data_root: Path, primary: str, cfg: dict | None = None) -> Path:
    categories = category_list(cfg)
    fallback = DEFAULT_CATEGORY if DEFAULT_CATEGORY in categories else categories[-1]
    name = primary if primary in categories else fallback
    return data_root / name


def archive_output(
    src: Path,
    data_root: Path,
    result: dict,
    conf_threshold: float,
    cfg: dict | None = None,
) -> Path:
    appid = result.get("appid") or "unknown"
    dest_root = category_dir(data_root, result.get("primary") or DEFAULT_CATEGORY, cfg)
    dest_root.mkdir(parents=True, exist_ok=True)
    folder_name = result.get("folder_name") or folder_name_for(str(result.get("nickname") or ""), appid)
    dest = dest_root / folder_name

    # 大目录复制不占用全局锁；先完整写入同盘暂存区，提交阶段才短暂加锁。
    # 暂存根和随机名刻意保持很短；长路径前缀负责处理深层子目录。
    staging_root = data_root / ".mc"
    staging_root.mkdir(parents=True, exist_ok=True)
    token = uuid4().hex
    short_token = token[:12]
    stage = staging_root / f"s_{short_token}"
    backups: list[tuple[Path, Path]] = []
    purged = 0
    try:
        copytree_long_path(src, stage)
        with FS_LOCK:
            existing = find_existing_by_appid(data_root, appid, cfg)
            if dest.exists() and dest not in existing:
                existing.append(dest)
            purged = len(existing)
            meta = {
                "classified_at": datetime.now().isoformat(timespec="seconds"),
                "confidence_threshold": conf_threshold,
                "purged_duplicates": purged,
                **result,
            }
            (stage / "_minicrest_classify.json").write_text(
                json.dumps(meta, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            for index, old in enumerate(existing):
                backup = staging_root / f"b_{short_token}_{index}"
                old.replace(backup)
                backups.append((old, backup))
            stage.replace(dest)
    except Exception:
        with FS_LOCK:
            for old, backup in reversed(backups):
                if backup.exists() and not old.exists():
                    backup.replace(old)
        if stage.exists():
            rmtree_long_path(stage, ignore_errors=True)
        raise
    for _, backup in backups:
        rmtree_long_path(backup, ignore_errors=True)
    return dest


def resolve_content_dir(out_dir: Path, appid: str) -> Path:
    nested = out_dir / appid
    if nested.exists() and nested.is_dir():
        return nested
    if (out_dir / "app.json").exists():
        return out_dir
    subdirs = [p for p in out_dir.iterdir() if p.is_dir()]
    if len(subdirs) == 1:
        return subdirs[0]
    return out_dir


def process_one(
    item: dict,
    cfg: dict,
    raw: Path,
    data_root: Path,
    registry: ProcessedRegistry,
    dry_run: bool = False,
    index: int = 0,
    total: int = 0,
) -> dict:
    appid = item["appid"]
    pack_dir: Path = item["pack_dir"]
    out_dir = raw / appid
    prefix = f"[{index}/{total}] {appid}"

    if dry_run:
        ok, cmd = run_wedecode(cfg.get("wedecode_cmd", "wedecode"), pack_dir, out_dir, appid, dry_run=True)
        log(f"{prefix} DRY: {cmd}")
        return {"appid": appid, "status": "dry_run", "cmd": cmd}

    log(f"{prefix} 解包中...")
    t0 = time.time()
    try:
        has_package, _mtime = _shallow_wxapkg_mtime(pack_dir)
    except OSError:
        has_package = False
    if not has_package:
        message = f"缓存目录已失效或没有 .wxapkg: {pack_dir}"
        log(f"{prefix} {message}")
        registry.mark(
            appid,
            {
                "status": "error",
                "error": "package_missing",
                "source_mtime": item.get("mtime"),
            },
        )
        return {"appid": appid, "status": "error", "error": "package_missing", "log": message}
    ok, wedecode_log = run_wedecode(
        cfg.get("wedecode_cmd", "wedecode"),
        pack_dir,
        out_dir,
        appid,
        timeout_sec=cfg.get("wedecode_timeout_sec", 600),
        output_stable_sec=cfg.get("wedecode_output_stable_sec", 12),
        idle_kill_sec=cfg.get("wedecode_idle_kill_sec", 45),
        proc_wait_sec=cfg.get("wedecode_proc_wait_sec", 15),
    )
    if CANCEL_EVENT.is_set():
        return {"appid": appid, "status": "cancelled"}
    if not ok:
        log(f"{prefix} wedecode 失败: {wedecode_log[:300]}")
        registry.mark(appid, {"status": "error", "error": "wedecode_failed", "log": wedecode_log[-800:]})
        return {"appid": appid, "status": "error", "error": "wedecode_failed", "log": wedecode_log[-1000:]}

    content_dir = resolve_content_dir(out_dir, appid)
    identity = identify_miniprogram(
        appid,
        content_dir,
        api=cfg.get("identify_api", ""),
        remote_timeout=cfg.get("identify_timeout_sec", 5.0),
        skip_remote_when_local_named=cfg.get("skip_remote_when_local_named", True),
    )
    result = classify_app(
        content_dir,
        nickname=identity["nickname"],
        appid=appid,
        description=identity.get("description") or "",
        confidence_threshold=cfg.get("confidence_threshold", 0.22),
        ambiguity_gap=cfg.get("ambiguity_gap", 0.06),
        max_total_bytes=cfg.get("classify_max_total_bytes", 8_000_000),
    )
    result["classification_status"] = result.get("status", "unknown")
    result["nickname"] = identity["nickname"]
    result["identify_source"] = identity["source"]
    result["folder_name"] = identity.get("folder_name") or folder_name_for(identity["nickname"], appid)
    dest = archive_output(
        content_dir, data_root, result, cfg.get("confidence_threshold", 0.22), cfg
    )
    result["archived_to"] = str(dest)
    result["status"] = "ok"
    result["elapsed_sec"] = round(time.time() - t0, 2)

    registry.mark(
        appid,
        {
            "status": "ok",
            "nickname": identity["nickname"],
            "primary": result["primary"],
            "archived_to": str(dest),
            "confidence": result.get("confidence"),
            "elapsed_sec": result["elapsed_sec"],
            "source_mtime": item.get("mtime"),
            "classification_status": result["classification_status"],
        },
    )
    log(
        f"{prefix} ✓ {identity['nickname']} -> {result['primary']} "
        f"({result['elapsed_sec']}s) {dest}"
    )
    return result


def process_raw_one(
    app_dir: Path,
    cfg: dict,
    data_root: Path,
    registry: ProcessedRegistry,
    dry_run: bool = False,
    force: bool = False,
) -> dict:
    appid = app_dir.name if APPID_RE.match(app_dir.name) else ""
    if not appid:
        m = re.search(r"(wx[0-9a-fA-F]{16})", app_dir.name)
        appid = m.group(1) if m else app_dir.name

    if not force and registry.has(appid):
        log(f"[跳过] {appid} 已处理")
        return {"appid": appid, "status": "skipped"}

    if dry_run:
        log(f"[DRY] 分类 {app_dir}")
        return {"appid": appid, "status": "dry_run"}

    identity = identify_miniprogram(
        appid,
        app_dir,
        api=cfg.get("identify_api", ""),
        remote_timeout=cfg.get("identify_timeout_sec", 5.0),
        skip_remote_when_local_named=cfg.get("skip_remote_when_local_named", True),
    )
    result = classify_app(
        app_dir,
        nickname=identity["nickname"],
        appid=identity["appid"] or appid,
        description=identity.get("description") or "",
        confidence_threshold=cfg.get("confidence_threshold", 0.22),
        ambiguity_gap=cfg.get("ambiguity_gap", 0.06),
        max_total_bytes=cfg.get("classify_max_total_bytes", 8_000_000),
    )
    result["classification_status"] = result.get("status", "unknown")
    result["nickname"] = identity["nickname"]
    result["identify_source"] = identity["source"]
    result["folder_name"] = identity.get("folder_name") or folder_name_for(
        identity["nickname"], identity["appid"] or appid
    )
    dest = archive_output(app_dir, data_root, result, cfg.get("confidence_threshold", 0.22), cfg)
    result["archived_to"] = str(dest)
    result["status"] = "ok"
    registry.mark(
        appid,
        {
            "status": "ok",
            "nickname": identity["nickname"],
            "primary": result["primary"],
            "archived_to": str(dest),
            "confidence": result.get("confidence"),
            "source": "classify_only",
            "classification_status": result["classification_status"],
        },
    )
    log(f"[分类] {identity['nickname']} ({appid}) -> {result['primary']}")
    return result


def default_workers(cfg: dict) -> int:
    n = int(cfg.get("workers") or 0)
    if n > 0:
        return n
    cpu = os.cpu_count() or 4
    # wedecode 偏 I/O + 子进程，可开更高并行
    return max(2, min(16, cpu * 2))


def run_parallel(
    tasks: list,
    worker_fn,
    workers: int,
) -> list[dict]:
    rows: list[dict] = []
    if not tasks:
        return rows
    CANCEL_EVENT.clear()
    ex = ThreadPoolExecutor(max_workers=workers)
    futs = {ex.submit(worker_fn, t): t for t in tasks}
    pending = set(futs)
    total = len(tasks)
    try:
        while pending:
            done, pending = wait(pending, timeout=15.0, return_when=FIRST_COMPLETED)
            if not done:
                running = sum(1 for fut in pending if fut.running())
                running_ids: list[str] = []
                for fut in pending:
                    if not fut.running():
                        continue
                    item = futs[fut]
                    if isinstance(item, tuple) and item:
                        item = item[-1]
                    if isinstance(item, dict):
                        running_ids.append(str(item.get("appid", "?")))
                    elif isinstance(item, Path):
                        running_ids.append(item.name)
                msg = f"[进度] 已完成 {len(rows)}/{total}，运行中 {running}，等待中 {len(pending) - running}"
                if running_ids:
                    msg += f" | {', '.join(running_ids[:6])}"
                    if len(running_ids) > 6:
                        msg += f" 等{len(running_ids)}个"
                log(msg)
                continue
            for fut in done:
                try:
                    rows.append(fut.result())
                except Exception as e:  # noqa: BLE001
                    item = futs[fut]
                    if isinstance(item, tuple) and item:
                        item = item[-1]
                    if isinstance(item, dict):
                        appid = item.get("appid", "?")
                    elif isinstance(item, Path):
                        appid = item.name
                    else:
                        appid = str(item)
                    log(f"[异常] {appid}: {e}")
                    rows.append({"appid": appid, "status": "error", "error": str(e)})
    except KeyboardInterrupt as exc:
        CANCEL_EVENT.set()
        for fut in pending:
            fut.cancel()
        log("\n收到停止请求，正在终止 wedecode 子进程并保存进度...")
        stop_active_processes()
        ex.shutdown(wait=True, cancel_futures=True)
        raise PipelineCancelled() from exc
    else:
        ex.shutdown(wait=True)
    return rows


def classify_existing_raw(
    cfg: dict,
    dry_run: bool = False,
    force: bool = False,
    workers: int | None = None,
) -> list[dict]:
    data_root = Path(cfg["data_root"])
    raw, reports = ensure_dirs(data_root, cfg["raw_dir"], cfg["report_dir"], cfg)
    registry = ProcessedRegistry(
        data_root / cfg.get("processed_file", "_processed.json"),
        flush_every=cfg.get("registry_flush_every", 20),
    )
    registry.bootstrap_from_disk(data_root, cfg)

    apps = sorted(
        [
            p
            for p in raw.iterdir()
            if p.is_dir()
            and (APPID_RE.fullmatch(p.name) or re.search(r"wx[0-9a-fA-F]{16}", p.name))
        ]
    )
    w = workers or default_workers(cfg)
    log(f"classify-only: {len(apps)} 个，workers={w}, force={force}")

    def _job(app_dir: Path) -> dict:
        return process_raw_one(app_dir, cfg, data_root, registry, dry_run=dry_run, force=force)

    try:
        rows = run_parallel(apps, _job, w)
    except PipelineCancelled:
        registry.save()
        raise
    registry.save()
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    report_path = reports / f"classify_{stamp}.json"
    report_path.write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")
    log(f"报告: {report_path}")
    return rows


def run_full(
    cfg: dict,
    dry_run: bool = False,
    limit: int | None = None,
    force: bool = False,
    workers: int | None = None,
) -> list[dict]:
    log("启动 pipeline：发现微信 packages 缓存…")
    discovered = discover_packages_roots()
    packages_roots = resolve_packages_roots(cfg, discovered=discovered)
    data_root = Path(cfg["data_root"])
    raw, reports = ensure_dirs(data_root, cfg["raw_dir"], cfg["report_dir"], cfg)
    registry = ProcessedRegistry(
        data_root / cfg.get("processed_file", "_processed.json"),
        flush_every=cfg.get("registry_flush_every", 20),
    )
    log(f"已处理记忆: {len(registry.data)} 条，检查是否需要 bootstrap…")
    boot = registry.bootstrap_from_disk(data_root, cfg)
    if boot:
        log(f"从磁盘补记已归档 {boot} 个 appid")
    else:
        log("跳过磁盘 bootstrap（记忆已足够）")

    if packages_roots:
        log("缓存目录(自动发现/配置):")
        for r in discovered:
            mark = "Y" if any(
                str(Path(r["path"]).resolve()).lower() == str(p.resolve()).lower() for p in packages_roots
            ) else " "
            log(f"  [{mark}] apps={r['apps']:3d} wxapkg={r['wxapkgs']:4d}  {r['path']}")
        for p in packages_roots:
            log(f"  使用: {p}")
    else:
        log("未找到任何微信小程序 packages 目录。")

    packs = find_pack_dirs(packages_roots)
    if limit:
        packs = packs[:limit]

    skipped = []
    todo = []
    for item in packs:
        if not force and registry.has(item["appid"], item.get("mtime")):
            skipped.append(item["appid"])
        else:
            todo.append(item)

    w = workers or default_workers(cfg)
    log(f"扫描到 {len(packs)} 个 | 跳过已处理 {len(skipped)} | 待处理 {len(todo)} | workers={w}")
    if skipped and len(skipped) <= 20:
        log("已跳过: " + ", ".join(skipped))
    if not packs:
        log("packages 为空：请先在微信中打开目标小程序以生成 wxapkg 缓存。")
        log("半自动刷缓存可试: python tools/launch_miniprograms.py --from-list appids.txt")
        return []
    if not todo:
        log("没有需要处理的新小程序。可用 --force 强制重跑。")
        return [{"appid": a, "status": "skipped"} for a in skipped]

    total = len(todo)

    def _job(indexed: tuple[int, dict]) -> dict:
        i, item = indexed
        return process_one(
            item,
            cfg,
            raw,
            data_root,
            registry,
            dry_run=dry_run,
            index=i,
            total=total,
        )

    indexed_tasks = list(enumerate(todo, 1))
    t0 = time.time()
    try:
        rows = run_parallel(indexed_tasks, _job, w)
    except PipelineCancelled:
        registry.save()
        raise
    registry.save()
    # 附上 skipped 摘要
    rows.extend({"appid": a, "status": "skipped"} for a in skipped)

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    report_path = reports / f"pipeline_{stamp}.json"
    report_path.write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")
    ok_n = sum(1 for r in rows if r.get("status") == "ok")
    err_n = sum(1 for r in rows if r.get("status") == "error")
    log(
        f"\n完成: ok={ok_n} error={err_n} skipped={len(skipped)} "
        f"耗时 {time.time() - t0:.1f}s | 报告: {report_path}"
    )
    log(f"已处理记忆: {registry.path} ({len(registry.data)} 条)")
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description="MiniCrest 并行解包 + 9 类行业粗分")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG), help="配置文件路径")
    parser.add_argument("--classify-only", action="store_true", help="只分类 _raw 已有产物")
    parser.add_argument("--dry-run", action="store_true", help="只扫描/打印，不解包不拷贝")
    parser.add_argument("--limit", type=int, default=None, help="最多处理 N 个（未处理队列）")
    parser.add_argument("--workers", type=int, default=None, help="并行 worker 数")
    parser.add_argument("--force", action="store_true", help="强制重处理已记录的 appid")
    args = parser.parse_args()

    log(f"MiniCrest pipeline | config={args.config}")
    cfg = load_config(Path(args.config))
    try:
        if args.classify_only:
            classify_existing_raw(cfg, dry_run=args.dry_run, force=args.force, workers=args.workers)
        else:
            run_full(
                cfg,
                dry_run=args.dry_run,
                limit=args.limit,
                force=args.force,
                workers=args.workers,
            )
    except PipelineCancelled:
        log("已安全停止；成功结果已记录，下次运行会继续未完成项。")
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
