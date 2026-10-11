# -*- coding: utf-8 -*-
"""自动发现微信小程序本地缓存 packages 目录。"""

from __future__ import annotations

import os
import re
from pathlib import Path

APPID_RE = re.compile(r"^wx[0-9a-fA-F]{16}$")


def _count_packs(packages_dir: Path) -> tuple[int, int, float]:
    """返回 (app 数, wxapkg 数, 最新 mtime)。

    只浅扫两层，避免对每个 app 做 rglob（缓存盘上会长时间无输出）。
    """
    if not packages_dir.is_dir():
        return 0, 0, 0.0
    apps = 0
    pkgs = 0
    newest = 0.0
    try:
        for app_dir in packages_dir.iterdir():
            if not app_dir.is_dir() or not APPID_RE.match(app_dir.name):
                continue
            apps += 1
            try:
                newest = max(newest, app_dir.stat().st_mtime)
            except OSError:
                pass
            # 浅层：app_dir/*.wxapkg 与 app_dir/*/*.wxapkg
            try:
                for child in app_dir.iterdir():
                    if child.is_file() and child.suffix.lower() == ".wxapkg":
                        pkgs += 1
                        try:
                            newest = max(newest, child.stat().st_mtime)
                        except OSError:
                            pass
                    elif child.is_dir():
                        try:
                            for f in child.iterdir():
                                if f.is_file() and f.suffix.lower() == ".wxapkg":
                                    pkgs += 1
                                    try:
                                        newest = max(newest, f.stat().st_mtime)
                                    except OSError:
                                        pass
                        except OSError:
                            pass
            except OSError:
                pass
    except OSError:
        return 0, 0, 0.0
    return apps, pkgs, newest


def candidate_roots() -> list[Path]:
    """枚举本机可能的 packages 根目录。"""
    appdata = Path(os.environ.get("APPDATA", ""))
    home = Path.home()
    found: list[Path] = []

    users = appdata / "Tencent" / "xwechat" / "radium" / "users"
    if users.is_dir():
        for user in users.iterdir():
            if not user.is_dir():
                continue
            pkg = user / "applet" / "packages"
            if pkg.is_dir():
                found.append(pkg)

    # 偶见大小写路径差异
    alt = appdata / "Tencent" / "xwechat" / "radium" / "Applet" / "packages"
    if alt.is_dir():
        found.append(alt)

    # 旧版微信
    legacy = home / "Documents" / "WeChat Files" / "Applet"
    if legacy.is_dir():
        found.append(legacy)

    # 去重
    uniq: list[Path] = []
    seen = set()
    for p in found:
        try:
            key = str(p.resolve()).lower()
        except OSError:
            key = str(p).lower()
        if key not in seen:
            seen.add(key)
            uniq.append(p)
    return uniq


def discover_packages_roots(prefer_nonempty: bool = True) -> list[dict]:
    """
    发现所有 packages 根，按「有包优先、包数量、最近修改」排序。
    返回 [{path, apps, wxapkgs, mtime}, ...]
    """
    rows = []
    for root in candidate_roots():
        apps, pkgs, mtime = _count_packs(root)
        if prefer_nonempty and apps == 0 and pkgs == 0:
            # 仍保留空目录，但排后面
            pass
        rows.append(
            {
                "path": root,
                "apps": apps,
                "wxapkgs": pkgs,
                "mtime": mtime,
            }
        )
    rows.sort(key=lambda r: (r["wxapkgs"] > 0, r["apps"], r["wxapkgs"], r["mtime"]), reverse=True)
    return rows


def resolve_packages_roots(
    cfg: dict | None = None,
    discovered: list[dict] | None = None,
) -> list[Path]:
    """
    解析配置中的 packages 路径：
    - packages_root == "auto" / 空 / 缺失 → 自动发现（合并所有非空账号）
    - 指定绝对路径 → 使用该路径；若无效再回退自动发现
    - packages_roots 可显式给多个路径
    """
    cfg = cfg or {}
    explicit: list[Path] = []

    multi = cfg.get("packages_roots")
    if isinstance(multi, list):
        for item in multi:
            if not item or str(item).strip().lower() == "auto":
                continue
            explicit.append(Path(str(item)))

    single = cfg.get("packages_root")
    if single and str(single).strip().lower() not in {"", "auto"}:
        explicit.append(Path(str(single)))

    # 校验显式路径
    valid_explicit = [p for p in explicit if p.is_dir()]
    if valid_explicit:
        # 去重
        out: list[Path] = []
        seen = set()
        for p in valid_explicit:
            key = str(p.resolve()).lower()
            if key not in seen:
                seen.add(key)
                out.append(p)
        return out

    # 自动：合并所有「有小程序」的账号目录
    discovered = discovered if discovered is not None else discover_packages_roots()
    nonempty = [Path(r["path"]) for r in discovered if r["wxapkgs"] > 0]
    if nonempty:
        return nonempty
    # 都没有包时，仍返回最优候选（便于提示）
    if discovered:
        return [Path(discovered[0]["path"])]
    return []
