# -*- coding: utf-8 -*-
"""
Dataset 统计（论文口径，基于当前 Data）

1) 样本：_processed.json 中 status=ok 的小程序（路径优先 _raw，其次 archived_to）
2) 页面数：app.json / app-config.json 的 pages + subpackages[].pages
3) 含后端 API 的页面（口径 A）：该页面对应 .js/.ts 源文件内直接出现后端请求调用
4) 附：与已有 apis_by_app 交叉的 endpoint 规模（若可得）

输出：
  _reports/dataset_stats.json       汇总 + 方法说明
  _reports/dataset_stats_by_app.jsonl 每应用明细
"""
from __future__ import annotations

import json
import os
import re
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

DATA = Path(r"E:\MiniCrest\Data")
REG = DATA / "_processed.json"
RAW = DATA / "_raw"
APIS = DATA / "_reports" / "apis_by_app.json"
OUT_JSON = DATA / "_reports" / "dataset_stats.json"
OUT_JSONL = DATA / "_reports" / "dataset_stats_by_app.jsonl"

APPID_RE = re.compile(r"^wx[0-9a-fA-F]{16}$")
APPID_IN = re.compile(r"(wx[0-9a-fA-F]{16})")

# 口径 A：页面源码内直接后端请求迹象
API_CALL_RE = re.compile(
    r"""(?:"""
    r"""wx\s*\.\s*request\b"""
    r"""|uni\s*\.\s*request\b"""
    r"""|wx\s*\.\s*cloud\s*\.\s*callFunction\b"""
    r"""|wx\s*\.\s*uploadFile\b"""
    r"""|wx\s*\.\s*downloadFile\b"""
    r"""|Taro\s*\.\s*request\b"""
    r"""|\baxios\s*\.\s*(?:get|post|put|delete|request|patch)\b"""
    r"""|\bfly\s*\.\s*(?:get|post|put|delete|request)\b"""
    r"""|\brequest\s*\(\s*\{"""  # request({ ... url
    r"""|\.request\s*\(\s*\{"""
    r"""|\bhttp\s*\.\s*(?:get|post|put|delete|request)\b"""
    r""")""",
    re.I,
)


def read_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        try:
            return json.loads(path.read_text(encoding="utf-8-sig"))
        except Exception:
            return {}


def remap_path(p: str | Path) -> Path:
    s = str(p).replace("/", "\\")
    for old in ("F:\\MiniCrest\\Data", "f:\\MiniCrest\\Data"):
        if s.startswith(old):
            s = "E:\\MiniCrest\\Data" + s[len(old) :]
            break
    return Path(s)


def load_ok_apps() -> list[tuple[str, Path]]:
    d = read_json(REG)
    items = d.get("items", d)
    out: list[tuple[str, Path]] = []
    for appid, info in items.items():
        if not APPID_RE.match(appid):
            continue
        if not isinstance(info, dict) or info.get("status") != "ok":
            continue
        path = RAW / appid
        if not path.is_dir():
            archived = info.get("archived_to")
            if archived:
                path = remap_path(archived)
        if path.is_dir():
            out.append((appid, path))
    return out


def load_api_index() -> dict[str, dict]:
    if not APIS.is_file():
        return {}
    try:
        rows = json.loads(APIS.read_text(encoding="utf-8"))
    except Exception:
        return {}
    idx = {}
    for row in rows:
        appid = row.get("appid")
        if not appid:
            m = APPID_IN.search(row.get("name") or "") or APPID_IN.search(row.get("path") or "")
            appid = m.group(1) if m else None
        if appid:
            idx[appid] = row
    return idx


def collect_page_paths(app_dir: Path) -> list[tuple[str, str]]:
    """
    返回 [(page_route, subpackage_root_or_empty), ...]
    page_route 为 app.json 中的路径（不含后缀）。
    """
    pages: list[tuple[str, str]] = []
    seen: set[str] = set()

    def add_from(data: dict, root_prefix: str = "") -> None:
        for p in data.get("pages") or []:
            if not isinstance(p, str) or not p.strip():
                continue
            route = p.strip().lstrip("/")
            key = f"{root_prefix}|{route}" if root_prefix else route
            # subpackage: route 相对 root；主包 route 相对小程序根
            full = f"{root_prefix}/{route}".strip("/") if root_prefix else route
            if full in seen:
                continue
            seen.add(full)
            pages.append((full, root_prefix))
        for sp in data.get("subPackages") or data.get("subpackages") or []:
            if not isinstance(sp, dict):
                continue
            root = str(sp.get("root") or "").strip().strip("/")
            for p in sp.get("pages") or []:
                if not isinstance(p, str) or not p.strip():
                    continue
                route = p.strip().lstrip("/")
                full = f"{root}/{route}".strip("/") if root else route
                if full in seen:
                    continue
                seen.add(full)
                pages.append((full, root))

    for fname in ("app.json", "app-config.json"):
        fp = app_dir / fname
        if fp.is_file():
            add_from(read_json(fp))
            if pages:
                break
    return pages


def page_js_candidates(app_dir: Path, page_full: str) -> list[Path]:
    base = app_dir / page_full
    cands = [
        Path(str(base) + ".js"),
        Path(str(base) + ".ts"),
        base / "index.js",
        base / "index.ts",
    ]
    return [p for p in cands if p.is_file()]


def page_has_api_logic(app_dir: Path, page_full: str) -> bool:
    for fp in page_js_candidates(app_dir, page_full):
        try:
            size = fp.stat().st_size
        except OSError:
            continue
        if size <= 0 or size > 2 * 1024 * 1024:
            continue
        try:
            text = fp.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if API_CALL_RE.search(text):
            return True
    return False


def scan_one(appid: str, app_dir: Path, api_row: dict | None) -> dict:
    page_list = collect_page_paths(app_dir)
    n_pages = len(page_list)
    api_pages = 0
    # 限制：超大页面数的应用仍全扫，但只读候选 js
    for page_full, _root in page_list:
        if page_has_api_logic(app_dir, page_full):
            api_pages += 1

    endpoints = 0
    domains = 0
    if api_row:
        endpoints = len(api_row.get("endpoints") or [])
        domains = len(api_row.get("domains") or [])

    return {
        "appid": appid,
        "path": str(app_dir),
        "pages": n_pages,
        "pages_with_api_logic_A": api_pages,
        "api_page_ratio": round(api_pages / n_pages, 4) if n_pages else 0.0,
        "apis_report_endpoints": endpoints,
        "apis_report_domains": domains,
        "has_app_json": (app_dir / "app.json").is_file() or (app_dir / "app-config.json").is_file(),
    }


def main() -> None:
    import argparse

    ap = argparse.ArgumentParser(description="Dataset stats for paper corpus")
    ap.add_argument("--workers", type=int, default=4, help="parallel apps (USB HDD 建议 2~4)")
    ap.add_argument("--progress-every", type=int, default=50)
    ap.add_argument("--limit", type=int, default=0, help="只扫前 N 个 app（调试）")
    args = ap.parse_args()

    t0 = time.time()
    print(f"[dataset_stats] loading registry from {REG} ...", flush=True)
    apps = load_ok_apps()
    print(f"[dataset_stats] loading api index from {APIS} ...", flush=True)
    api_idx = load_api_index()
    if args.limit and args.limit > 0:
        apps = apps[: args.limit]
    print(
        f"ok apps with path: {len(apps)}; api_index: {len(api_idx)}; "
        f"workers={args.workers}",
        flush=True,
    )

    rows: list[dict] = []
    # 外置机械盘上高并发会 thrash，表现为“卡住”、CPU 几乎不涨
    workers = max(1, min(args.workers, (os.cpu_count() or 4)))
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {
            ex.submit(scan_one, appid, path, api_idx.get(appid)): appid
            for appid, path in apps
        }
        done = 0
        for fut in as_completed(futs):
            rows.append(fut.result())
            done += 1
            if done == 1 or done % max(1, args.progress_every) == 0 or done == len(apps):
                elapsed = time.time() - t0
                rate = done / elapsed if elapsed > 0 else 0
                eta = (len(apps) - done) / rate if rate > 0 else 0
                print(
                    f"scanned {done}/{len(apps)}  "
                    f"elapsed={elapsed:.0f}s  rate={rate:.2f}/s  eta={eta:.0f}s",
                    flush=True,
                )

    # 仅统计能解析出至少 1 个页面的应用（分母更干净）
    with_pages = [r for r in rows if r["pages"] > 0]
    no_pages = [r for r in rows if r["pages"] <= 0]

    total_pages = sum(r["pages"] for r in with_pages)
    total_api_pages = sum(r["pages_with_api_logic_A"] for r in with_pages)
    apps_with_any_api_page = sum(1 for r in with_pages if r["pages_with_api_logic_A"] > 0)

    # 与 apis_by_app 交叉
    with_api_report = [r for r in with_pages if r["apis_report_endpoints"] > 0]
    sum_endpoints = sum(r["apis_report_endpoints"] for r in with_pages)

    report = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "data_root": str(DATA),
        "methodology": {
            "corpus": "_processed.json status=ok，路径优先 _raw/{appid}，否则 archived_to",
            "page_definition": (
                "app.json 或 app-config.json 中 pages 与 subPackages/subpackages[].pages 条目数之和；"
                "子包页面路径 = root + '/' + page"
            ),
            "page_with_backend_api_definition_A": (
                "该页面路由对应的 .js/.ts（或目录下 index.js/ts）源文件内，"
                "直接匹配到 wx.request / uni.request / wx.cloud.callFunction / "
                "wx.uploadFile|downloadFile / Taro.request / axios|fly|http.(get|post|...) / "
                "request({ 或 .request({ 之一。不含跨文件间接调用（会低估）。"
            ),
            "api_operations_note": (
                "本脚本不重新定义 MiniCrest operation；"
                "apis_report_endpoints 来自既有 apis_by_app.json 的 endpoints 条数，供对照，"
                "不等于论文中的 API operations，除非另行统一口径。"
            ),
        },
        "summary": {
            "ok_apps_with_path": len(rows),
            "apps_with_parsed_pages": len(with_pages),
            "apps_without_parsed_pages": len(no_pages),
            "total_pages": total_pages,
            "pages_with_api_logic_A": total_api_pages,
            "pages_with_api_logic_A_pct": round(100.0 * total_api_pages / total_pages, 2)
            if total_pages
            else 0.0,
            "avg_pages_per_app": round(total_pages / len(with_pages), 2) if with_pages else 0.0,
            "avg_api_pages_per_app": round(total_api_pages / len(with_pages), 2)
            if with_pages
            else 0.0,
            "apps_with_any_api_page": apps_with_any_api_page,
            "apps_with_any_api_page_pct": round(100.0 * apps_with_any_api_page / len(with_pages), 2)
            if with_pages
            else 0.0,
            "apis_report_apps_with_endpoints": len(with_api_report),
            "apis_report_endpoints_sum": sum_endpoints,
            "apis_report_avg_endpoints_per_app_with_pages": round(
                sum_endpoints / len(with_pages), 2
            )
            if with_pages
            else 0.0,
        },
        "paper_ready_sentences_zh": [],
        "elapsed_sec": round(time.time() - t0, 2),
    }

    s = report["summary"]
    report["paper_ready_sentences_zh"] = [
        (
            f"我们成功解包并纳入统计 {s['apps_with_parsed_pages']} 个微信小程序"
            f"（另有 {s['apps_without_parsed_pages']} 个未能解析出 pages 配置）。"
        ),
        (
            f"这些样本共包含 {s['total_pages']} 个页面"
            f"（平均每个小程序约 {s['avg_pages_per_app']} 个页面，口径为 app.json 的 pages+subpackages）。"
        ),
        (
            f"其中 {s['pages_with_api_logic_A']} 个页面"
            f"（占全部页面的 {s['pages_with_api_logic_A_pct']}%）"
            f"在页面源码中直接包含后端 API 调用逻辑（口径 A：页内直接请求，不含跨文件间接调用）。"
        ),
        (
            f"对照既有 API 提取报告，上述有页面配置的应用累计检出 endpoints "
            f"{s['apis_report_endpoints_sum']} 条"
            f"（平均 {s['apis_report_avg_endpoints_per_app_with_pages']} 条/应用；"
            f"此为 endpoint 字符串统计，不等同于 MiniCrest API operation，除非另行对齐定义）。"
        ),
    ]

    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    with OUT_JSONL.open("w", encoding="utf-8") as f:
        for r in sorted(rows, key=lambda x: x["appid"]):
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    print(json.dumps(report["summary"], ensure_ascii=False, indent=2), flush=True)
    print("---", flush=True)
    for line in report["paper_ready_sentences_zh"]:
        print(line, flush=True)
    print(f"out: {OUT_JSON}", flush=True)
    print(f"elapsed: {report['elapsed_sec']}s", flush=True)


if __name__ == "__main__":
    main()
