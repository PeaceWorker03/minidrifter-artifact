# -*- coding: utf-8 -*-
"""筛选结构稳定、信息较完整、适合 MiniCrest 测试的小程序列表。"""
from __future__ import annotations

import json
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

DATA = Path(r"E:\MiniCrest\Data")
OUT = DATA / "_reports" / "minicrest_test_candidates.json"
APPID_RE = re.compile(r"(wx[0-9a-fA-F]{16})")
ONLY_APPID_RE = re.compile(r"^wx[0-9a-fA-F]{16}$")

CATEGORIES = [
    "餐饮、生活消费",
    "房产与生活服务",
    "交通出行、租车服务",
    "景区、票务与预约",
    "企业与办公服务",
    "商城与零售",
    "校园与教育",
    "医疗与健康服务",
    "政务、缴费及其他服务",
]

GENERIC_NAMES = {
    "点餐", "首页", "未命名", "小程序", "测试", "demo", "test", "cyq-build",
}


def read_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        try:
            return json.loads(path.read_text(encoding="utf-8-sig"))
        except Exception:
            return {}


def parse_dir_name(name: str) -> tuple[str, str | None]:
    """返回 (display_name, appid)。"""
    m = APPID_RE.search(name)
    appid = m.group(1) if m else None
    if appid and name.endswith("_" + appid):
        nick = name[: -(len(appid) + 1)]
        # URL 编码目录名尝试还原
        try:
            from urllib.parse import unquote

            nick = unquote(nick)
        except Exception:
            pass
        return nick or appid, appid
    if appid and ONLY_APPID_RE.match(name):
        return appid, appid
    return name, appid


def count_pages(root: Path, app_json: dict) -> int:
    pages = app_json.get("pages") or []
    if isinstance(pages, list) and pages:
        return len(pages)
    pages_dir = root / "pages"
    if pages_dir.is_dir():
        try:
            return sum(1 for p in pages_dir.iterdir() if p.is_dir())
        except OSError:
            return 0
    return 0


def shallow_stats(root: Path) -> dict:
    """浅层统计，避免全树 walk。"""
    top_dirs: set[str] = set()
    top_files: set[str] = set()
    file_count = 0
    try:
        for child in root.iterdir():
            if child.name.startswith("."):
                continue
            if child.is_dir():
                top_dirs.add(child.name.lower())
                # 只计一层子文件数量上限
                try:
                    file_count += sum(1 for x in child.iterdir() if x.is_file())
                except OSError:
                    pass
            elif child.is_file():
                top_files.add(child.name.lower())
                file_count += 1
    except OSError:
        pass
    return {"top_dirs": top_dirs, "top_files": top_files, "file_count": file_count}


def score_one(category: str, path: Path) -> dict | None:
    nick, appid = parse_dir_name(path.name)
    if not appid:
        return None

    stats = shallow_stats(path)
    top_dirs = stats["top_dirs"]
    top_files = stats["top_files"]

    app_json_path = path / "app.json"
    app_cfg_path = path / "app-config.json"
    app_json = read_json(app_json_path) if app_json_path.is_file() else {}
    app_cfg = read_json(app_cfg_path) if app_cfg_path.is_file() else {}

    pages_n = count_pages(path, app_json)
    # app-config 有时 pages 在别处
    if pages_n == 0 and app_cfg:
        pages_n = count_pages(path, app_cfg)

    ext_name = ""
    ext = app_cfg.get("ext") if isinstance(app_cfg.get("ext"), dict) else {}
    if isinstance(ext, dict):
        ext_name = str(ext.get("appname") or ext.get("appName") or "").strip()

    window_title = ""
    win = app_json.get("window") if isinstance(app_json.get("window"), dict) else {}
    if isinstance(win, dict):
        window_title = str(win.get("navigationBarTitleText") or "").strip()

    has_app_js = (path / "app.js").is_file() or (path / "app.ts").is_file()
    has_app_json = app_json_path.is_file() or app_cfg_path.is_file()
    has_project = (path / "project.config.json").is_file()
    has_pages_dir = "pages" in top_dirs
    has_components = "components" in top_dirs or "component" in top_dirs
    has_utils = "utils" in top_dirs or "common" in top_dirs or "lib" in top_dirs
    has_classify = (path / "_minicrest_classify.json").is_file()
    named = bool(nick) and nick != appid and nick not in GENERIC_NAMES and not nick.lower().startswith("cyq")

    # 结构完整性打分
    score = 0
    reasons: list[str] = []
    checks = [
        (has_app_json, 15, "有app.json/config"),
        (has_app_js, 15, "有app入口"),
        (has_pages_dir, 10, "有pages目录"),
        (pages_n >= 3, 15, f"页面数>={pages_n}"),
        (pages_n >= 8, 5, "页面较丰富"),
        (has_project, 8, "有project.config"),
        (has_components, 8, "有components"),
        (has_utils, 5, "有utils/common"),
        (named, 12, "有可读昵称"),
        (bool(ext_name) and ext_name not in GENERIC_NAMES, 10, "ext.appname可用"),
        (has_classify, 3, "有分类元数据"),
        (stats["file_count"] >= 25, 6, "文件量充足"),
        (stats["file_count"] >= 80, 4, "体量较大"),
        ("assets" in top_dirs or "static" in top_dirs or "images" in top_dirs, 3, "有静态资源"),
    ]
    for ok, pts, why in checks:
        if ok:
            score += pts
            reasons.append(why)

    # 硬门槛：缺入口或缺页面则直接不合格
    if not has_app_json or not has_app_js or pages_n < 2:
        return None
    if score < 55:
        return None

    display = ext_name or (nick if named else "") or window_title or appid
    if display in GENERIC_NAMES:
        display = nick if named else appid

    return {
        "appid": appid,
        "name": display,
        "dir_name": path.name,
        "category": category,
        "path": str(path),
        "score": score,
        "pages": pages_n,
        "file_count_shallow": stats["file_count"],
        "has_components": has_components,
        "has_project_config": has_project,
        "ext_appname": ext_name or None,
        "reasons": reasons,
        "suitable_for_test": score >= 70,
    }


def main() -> None:
    t0 = time.time()
    jobs: list[tuple[str, Path]] = []
    for cat in CATEGORIES:
        cdir = DATA / cat
        if not cdir.is_dir():
            continue
        try:
            for child in cdir.iterdir():
                if child.is_dir() and APPID_RE.search(child.name):
                    jobs.append((cat, child))
        except OSError:
            continue

    print(f"candidates to score: {len(jobs)}", flush=True)
    rows: list[dict] = []
    workers = min(16, (os.cpu_count() or 4) * 2)
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [ex.submit(score_one, cat, p) for cat, p in jobs]
        done = 0
        for fut in as_completed(futs):
            r = fut.result()
            if r:
                rows.append(r)
            done += 1
            if done % 400 == 0:
                print(f"scored {done}/{len(jobs)} kept={len(rows)}", flush=True)

    rows.sort(key=lambda x: (-x["score"], x["category"], x["name"]))
    suitable = [r for r in rows if r["suitable_for_test"]]
    # 每类最多保留高分，避免企业类淹没；同时给出全量 stable 列表
    per_cat_cap = 40
    balanced: list[dict] = []
    cat_counts: dict[str, int] = {}
    for r in suitable:
        c = r["category"]
        if cat_counts.get(c, 0) >= per_cat_cap:
            continue
        cat_counts[c] = cat_counts.get(c, 0) + 1
        balanced.append(r)

    by_cat: dict[str, int] = {}
    for r in suitable:
        by_cat[r["category"]] = by_cat.get(r["category"], 0) + 1

    report = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "purpose": "MiniCrest 测试用：结构稳定、信息较完整的小程序候选列表",
        "criteria": {
            "hard": ["app.json或app-config.json", "app.js/ts", "pages>=2"],
            "score_pass": 55,
            "suitable_for_test": 70,
            "signals": [
                "可读昵称/ext.appname",
                "pages>=3",
                "components",
                "project.config.json",
                "utils/common",
                "浅层文件量",
            ],
        },
        "scanned_dirs": len(jobs),
        "stable_pass_count": len(rows),
        "suitable_for_test_count": len(suitable),
        "balanced_recommend_count": len(balanced),
        "by_category_suitable": by_cat,
        "elapsed_sec": round(time.time() - t0, 2),
        "recommend": balanced,
        "all_suitable": suitable,
    }

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    # 精简版仅列表，方便 MiniCrest 直接消费
    slim_path = DATA / "_reports" / "minicrest_test_list.json"
    slim = [
        {
            "appid": r["appid"],
            "name": r["name"],
            "category": r["category"],
            "path": r["path"],
            "score": r["score"],
            "pages": r["pages"],
        }
        for r in balanced
    ]
    slim_path.write_text(
        json.dumps(
            {
                "generated_at": report["generated_at"],
                "count": len(slim),
                "note": "每类最多40个高分样本；完整见 minicrest_test_candidates.json",
                "items": slim,
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    print(
        json.dumps(
            {
                "scanned": len(jobs),
                "stable": len(rows),
                "suitable": len(suitable),
                "recommend": len(balanced),
                "by_category": by_cat,
                "top10": [
                    {"name": r["name"], "cat": r["category"], "score": r["score"], "pages": r["pages"]}
                    for r in suitable[:10]
                ],
                "out": str(OUT),
                "slim": str(slim_path),
                "elapsed": report["elapsed_sec"],
            },
            ensure_ascii=False,
            indent=2,
        ),
        flush=True,
    )


if __name__ == "__main__":
    main()
