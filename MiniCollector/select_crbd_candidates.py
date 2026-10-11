# -*- coding: utf-8 -*-
"""
从已有 apis_by_app.json + 磁盘结构校验，筛选适合 CRBD 漏洞测试的小程序：
源码 API 逻辑完整（有业务后端接口、请求封装/相对路径可还原）。
"""
from __future__ import annotations

import json
import re
import time
from collections import Counter
from pathlib import Path
from urllib.parse import unquote, urlparse

DATA = Path(r"E:\MiniCrest\Data")
APIS = DATA / "_reports" / "apis_by_app.json"
OUT = DATA / "_reports" / "crbd_testable_apps.json"
OUT_SLIM = DATA / "_reports" / "crbd_testable_list.json"

# 文档/静态/地图 CDN 等不算业务 API
SKIP_HOST_RE = re.compile(
    r"(developers\.weixin\.qq\.com|servicewechat\.com|"
    r"res\.wx\.qq\.com|mmbiz\.qpic\.cn|"
    r"googleapis\.com|gstatic\.com|"
    r"restapi\.amap\.com|apis\.map\.qq\.com|"
    r"img\.|image\.|static\.|cdn\.|oss-|"
    r"favicon)",
    re.I,
)
STATIC_PATH_RE = re.compile(
    r"\.(?:png|jpe?g|gif|svg|webp|ico|css|js|map|woff2?|ttf|mp4|mp3|pdf)(?:\?|$)",
    re.I,
)
APPID_RE = re.compile(r"(wx[0-9a-fA-F]{16})")


def remap_path(p: str) -> Path:
    """历史报告可能是 F: 路径，映射到当前 E:。"""
    s = p.replace("/", "\\")
    for old in ("F:\\MiniCrest\\Data", "f:\\MiniCrest\\Data"):
        if s.startswith(old):
            s = "E:\\MiniCrest\\Data" + s[len(old) :]
            break
    return Path(s)


def business_endpoints(endpoints: list[str]) -> list[str]:
    out = []
    for u in endpoints or []:
        try:
            pr = urlparse(u)
        except Exception:
            continue
        if pr.scheme not in {"http", "https"}:
            continue
        host = (pr.netloc or "").lower()
        if not host:
            continue
        if SKIP_HOST_RE.search(host):
            continue
        if STATIC_PATH_RE.search(pr.path or ""):
            continue
        # 纯根路径且无 query 的官网首页弱信号，降权但仍保留若有 /api
        out.append(u)
    return out


def display_name(dir_name: str, appid: str | None) -> str:
    name = unquote(dir_name)
    if appid and name.endswith("_" + appid):
        name = name[: -(len(appid) + 1)]
    return name or (appid or dir_name)


def completeness(app: dict) -> tuple[str, int, dict]:
    """
    返回 (等级, 分数, 细节)
    complete: 可测 CRBD（API 逻辑完整）
    partial: 有接口但偏少
    empty: 基本无可测业务 API
    """
    eps = business_endpoints(app.get("endpoints") or [])
    rel = [r for r in (app.get("relative_paths") or []) if isinstance(r, str) and len(r) >= 2]
    bases = app.get("config_bases") or {}
    domains = sorted(
        {
            urlparse(u).netloc.lower()
            for u in eps
            if urlparse(u).netloc
        }
    )
    # 过滤明显非业务相对路径
    rel_biz = [
        r
        for r in rel
        if not STATIC_PATH_RE.search(r)
        and not r.startswith("data: ")
        and ("/" in r or r.startswith("api"))
    ]

    score = 0
    if len(eps) >= 1:
        score += min(40, len(eps) * 4)
    if len(eps) >= 5:
        score += 10
    if len(rel_biz) >= 2:
        score += min(25, len(rel_biz) * 3)
    if bases:
        score += 15
    if len(domains) >= 1:
        score += 10
    if len(domains) >= 2:
        score += 5
    if (app.get("files_scanned") or 0) >= 5:
        score += 5

    detail = {
        "business_endpoints": len(eps),
        "relative_paths": len(rel_biz),
        "config_bases": len(bases),
        "business_domains": len(domains),
        "sample_endpoints": eps[:8],
        "sample_domains": domains[:5],
        "sample_relative_paths": rel_biz[:8],
        "files_scanned": app.get("files_scanned") or 0,
    }

    # 完整：足够业务 URL，或 base+相对路径可拼出调用链
    if len(eps) >= 3 and (len(rel_biz) >= 2 or bases or len(eps) >= 6):
        return "complete", score, detail
    if len(eps) >= 5 and len(domains) >= 1:
        return "complete", score, detail
    if bases and len(rel_biz) >= 5:
        return "complete", score, detail
    if len(eps) >= 1 or len(rel_biz) >= 3:
        return "partial", score, detail
    return "empty", score, detail


def path_still_ok(path: Path) -> bool:
    if not path.is_dir():
        return False
    # 入口文件存在即可（不解深树）
    return (path / "app.js").is_file() or (path / "app.ts").is_file() or (
        path / "app.json"
    ).is_file() or (path / "app-config.json").is_file()


def main() -> None:
    t0 = time.time()
    apps = json.loads(APIS.read_text(encoding="utf-8"))
    counts = Counter()
    complete_items = []
    partial_items = []

    for app in apps:
        if app.get("status") != "ok":
            counts["extract_error"] += 1
            continue
        level, score, detail = completeness(app)
        counts[level] += 1
        appid = app.get("appid") or (APPID_RE.search(app.get("name") or "") or type("X", (), {"group": lambda *_: None})()).group(1)
        if not appid:
            m = APPID_RE.search(app.get("path") or "")
            appid = m.group(1) if m else None
        path = remap_path(app.get("path") or "")
        exists = path_still_ok(path)
        if not exists:
            counts["missing_on_disk"] += 1
            # 仍可列入，但标记；CRBD 测试需要源码，缺盘的剔除
            if level == "complete":
                counts["complete_but_missing"] += 1
            continue

        item = {
            "appid": appid,
            "name": display_name(app.get("name") or "", appid),
            "category": app.get("category"),
            "path": str(path),
            "score": score,
            "api_level": level,
            **detail,
        }
        if level == "complete":
            complete_items.append(item)
        elif level == "partial":
            partial_items.append(item)

    complete_items.sort(key=lambda x: (-x["score"], x.get("category") or "", x.get("name") or ""))
    partial_items.sort(key=lambda x: (-x["score"], x.get("category") or "", x.get("name") or ""))

    by_cat = Counter(i["category"] for i in complete_items)

    report = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "purpose": "CRBD 漏洞测试候选：源码中业务 API 逻辑较完整的小程序",
        "source": str(APIS),
        "criteria": {
            "complete": [
                "业务 HTTP(S) 端点 >=3，且有相对路径/baseURL 封装或端点>=6",
                "或 baseURL + 相对路径>=5",
                "排除微信文档/CDN/地图静态资源域名",
                "磁盘上仍有 app 入口文件",
            ],
            "note": "基于已有 API 提取报告筛选；未重新全量解包扫描",
        },
        "summary": {
            "apis_report_total": len(apps),
            "api_complete_testable": len(complete_items),
            "api_partial": len(partial_items),
            "counts_raw": dict(counts),
            "by_category": dict(by_cat),
        },
        "elapsed_sec": round(time.time() - t0, 2),
        "items": complete_items,
    }

    OUT.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    slim = {
        "generated_at": report["generated_at"],
        "purpose": report["purpose"],
        "count": len(complete_items),
        "by_category": dict(by_cat),
        "items": [
            {
                "appid": i["appid"],
                "name": i["name"],
                "category": i["category"],
                "path": i["path"],
                "score": i["score"],
                "business_endpoints": i["business_endpoints"],
                "business_domains": i["business_domains"],
                "sample_domains": i["sample_domains"],
            }
            for i in complete_items
        ],
    }
    OUT_SLIM.write_text(json.dumps(slim, ensure_ascii=False, indent=2), encoding="utf-8")

    print(
        json.dumps(
            {
                "testable_count": len(complete_items),
                "partial_count": len(partial_items),
                "by_category": dict(by_cat),
                "top8": [
                    {
                        "name": i["name"],
                        "cat": i["category"],
                        "score": i["score"],
                        "eps": i["business_endpoints"],
                        "dom": i["sample_domains"][:2],
                    }
                    for i in complete_items[:8]
                ],
                "out": str(OUT_SLIM),
                "full": str(OUT),
            },
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
