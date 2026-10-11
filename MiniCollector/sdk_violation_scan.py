# -*- coding: utf-8 -*-
"""
第三方 SDK 合规红旗扫描（快速版）：只读固定配置/入口文件。
用于测绘摸底，不构成法律终局认定。
"""
from __future__ import annotations

import csv
import json
import os
import re
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

DATA = Path(r"E:\MiniCrest\Data")
RAW = DATA / "_raw"
REG = DATA / "_processed.json"
PER_APP = DATA / "_reports" / "sdk_per_app.jsonl"
OUT_DIR = DATA / "_reports"
APPID_RE = re.compile(r"^wx[0-9a-fA-F]{16}$")

RE_AMAP = re.compile(
    r"(?:restapi\.amap\.com[^'\"\s]*[?&]key=|amap\.com[^'\"\s]*key=)"
    r"([A-Za-z0-9]{20,40})"
    r"|(?:amapKey|gaodeKey|mapKey|amap_key|map_key)\s*[:=]\s*['\"]([A-Za-z0-9]{20,40})['\"]"
    r"|(?:key)\s*[:=]\s*['\"]([a-fA-F0-9]{32})['\"]",
    re.I,
)
RE_QQMAP = re.compile(
    r"(?:map\.qq\.com[^'\"\s]*[?&]key=)([A-Z0-9-]{20,45})"
    r"|(?:qqmapKey|tencentMapKey)\s*[:=]\s*['\"]([A-Z0-9-]{20,45})['\"]",
    re.I,
)
RE_UMENG = re.compile(
    r"(?:umeng|友盟|umtrack).{0,80}?(?:appkey|appKey)\s*[:=]\s*['\"]([0-9a-fA-F]{20,32})['\"]"
    r"|(?:appkey|appKey)\s*[:=]\s*['\"]([0-9a-fA-F]{24,32})['\"].{0,60}?(?:umeng|友盟|umtrack)",
    re.I | re.S,
)
RE_SECRET = re.compile(
    r"(?:appsecret|app_secret|client_secret|private[_-]?key|api[_-]?secret)\s*[:=]\s*['\"]([^'\"]{8,120})['\"]",
    re.I,
)
RE_HTTP = re.compile(
    r"http://(?:restapi\.amap\.com|apis\.map\.qq\.com|cloud\.umeng\.com|[a-z0-9.-]*sensorsdata[a-z0-9.-]*)",
    re.I,
)
RE_LOC = re.compile(r"wx\.getLocation|wx\.chooseLocation|getFuzzyLocation", re.I)
RE_PHONE = re.compile(r"getPhoneNumber|getUserProfile", re.I)

HIGH_RISK_SDKS = {
    "高德地图", "腾讯地图", "友盟统计", "umtrack-wx", "神策分析 Sensors",
    "美团SaaS相关", "有赞", "微盟", "GrowingIO", "微信支付插件", "广告插件",
}
PRIVACY_HINTS = {
    "高德地图": [r"高德", r"amap"],
    "腾讯地图": [r"腾讯地图", r"qqmap"],
    "友盟统计": [r"友盟", r"umeng"],
    "umtrack-wx": [r"友盟", r"umeng"],
    "神策分析 Sensors": [r"神策", r"sensors"],
    "美团SaaS相关": [r"美团", r"点评"],
    "有赞": [r"有赞", r"youzan"],
    "微盟": [r"微盟", r"weimob"],
}

PRIORITY_FILES = (
    "app.js", "app.ts", "app.json", "app-config.json", "project.config.json",
    "config.js", "config.json", "config/index.js", "config/config.js",
    "utils/config.js", "common/config.js", "constants.js", "env.js",
    "privacy.js", "privacy.json", "utils/privacy.js",
)


def load_targets():
    by_sdk = {}
    if PER_APP.is_file():
        for line in PER_APP.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            d = json.loads(line)
            if not d.get("missing"):
                by_sdk[d["appid"]] = d.get("sdks") or []
    d = json.loads(REG.read_text(encoding="utf-8"))
    items = d.get("items", d)
    out = []
    for appid, info in items.items():
        if not isinstance(info, dict) or info.get("status") != "ok":
            continue
        if not APPID_RE.match(appid):
            continue
        path = RAW / appid
        if not path.is_dir():
            archived = info.get("archived_to")
            if archived and Path(str(archived)).is_dir():
                path = Path(str(archived))
            else:
                continue
        out.append((appid, path, by_sdk.get(appid, [])))
    return out


def read_text(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def collect_files(root: Path, deep: bool) -> list[Path]:
    files = []
    for rel in PRIORITY_FILES:
        p = root / rel
        if p.is_file():
            files.append(p)
    if not deep:
        return files
    # 再扫一层子目录里的 *config* / *key*
    try:
        for child in root.iterdir():
            if not child.is_dir() or child.name.startswith(".") or child.name in {
                "miniprogram_npm", "node_modules", "pages", "components"
            }:
                continue
            try:
                for sub in list(child.iterdir())[:20]:
                    if not sub.is_file():
                        continue
                    n = sub.name.lower()
                    if sub.suffix.lower() in {".js", ".json", ".ts"} and (
                        "config" in n or "key" in n or "secret" in n or "env" in n or "privacy" in n
                    ):
                        files.append(sub)
            except OSError:
                pass
    except OSError:
        pass
    return files


def extract(text: str, has_amap_ctx: bool) -> dict[str, set[str]]:
    found: dict[str, set[str]] = defaultdict(set)
    for m in RE_AMAP.finditer(text):
        for g in m.groups():
            if not g:
                continue
            # 32位 hex 仅在高德上下文中算 amap key，避免误报
            if len(g) == 32 and re.fullmatch(r"[a-fA-F0-9]{32}", g):
                if has_amap_ctx or "amap" in text.lower() or "高德" in text:
                    found["amap_key"].add(g)
            else:
                found["amap_key"].add(g)
    for m in RE_QQMAP.finditer(text):
        for g in m.groups():
            if g:
                found["qqmap_key"].add(g)
    for m in RE_UMENG.finditer(text):
        for g in m.groups():
            if g:
                found["umeng_appkey"].add(g)
    for m in RE_SECRET.finditer(text):
        val = m.group(1)
        if val.lower() in {"your_secret", "xxx", "test", "null", "undefined", "placeholder", "secret"}:
            continue
        found["plaintext_secret"].add(val[:80])
    for m in RE_HTTP.finditer(text):
        found["http_third_party"].add(m.group(0)[:120])
    return found


def scan_one(appid: str, root: Path, sdks: list[str]) -> dict:
    risky = bool(set(sdks) & HIGH_RISK_SDKS)
    texts = []
    has_loc = has_phone = False
    keys_all: dict[str, set[str]] = defaultdict(set)
    for fp in collect_files(root, deep=risky):
        t = read_text(fp)
        if not t:
            continue
        texts.append(t)
        if RE_LOC.search(t):
            has_loc = True
        if RE_PHONE.search(t):
            has_phone = True
        for k, vs in extract(t, "高德地图" in sdks).items():
            keys_all[k].update(vs)

    flags = []
    for ktype, sev, title in (
        ("amap_key", "高", "硬编码高德Key"),
        ("qqmap_key", "高", "硬编码腾讯地图Key"),
        ("umeng_appkey", "中", "硬编码友盟AppKey"),
        ("plaintext_secret", "高", "明文Secret/Token"),
        ("http_third_party", "高", "HTTP明文调用第三方域名"),
    ):
        vals = keys_all.get(ktype) or set()
        if vals:
            flags.append({"type": ktype, "severity": sev, "title": title, "count": len(vals), "samples": sorted(vals)[:2]})

    missing = []
    if risky:
        priv = "\n".join(texts)  # 入口/配置即隐私线索来源；另读 privacy 文件已在 collect
        for sdk in sdks:
            hints = PRIVACY_HINTS.get(sdk)
            if not hints:
                continue
            if not any(re.search(h, priv, re.I) for h in hints):
                missing.append(sdk)
        if missing:
            flags.append({
                "type": "privacy_vendor_undisclosed",
                "severity": "中",
                "title": "高敏SDK疑似未在隐私文案披露",
                "count": len(set(missing)),
                "samples": sorted(set(missing))[:5],
            })
        high = set(sdks) & HIGH_RISK_SDKS
        if has_loc and high and missing:
            flags.append({
                "type": "location_with_undisclosed_sdk",
                "severity": "高",
                "title": "采集位置且第三方SDK疑似未披露",
                "count": 1,
                "samples": sorted(high)[:5],
            })

    sev_rank = {"高": 3, "中": 2, "低": 1}
    max_sev = "无"
    if flags:
        max_sev = max(flags, key=lambda f: sev_rank.get(f["severity"], 0))["severity"]
    return {
        "appid": appid,
        "sdks": sdks,
        "flag_count": len(flags),
        "max_severity": max_sev,
        "flags": flags,
        "keys": {k: sorted(v) for k, v in keys_all.items()},
        "has_location_api": has_loc,
        "has_phone_api": has_phone,
        "risky": risky,
    }


def main():
    t0 = time.time()
    targets = load_targets()
    print(f"targets: {len(targets)}", flush=True)
    workers = min(24, (os.cpu_count() or 4) * 3)
    rows = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [ex.submit(scan_one, a, p, s) for a, p, s in targets]
        done = 0
        for fut in as_completed(futs):
            rows.append(fut.result())
            done += 1
            if done % 500 == 0:
                print(f"scanned {done}/{len(targets)}", flush=True)

    n = len(rows)
    key_owners: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    for r in rows:
        for ktype, vals in (r.get("keys") or {}).items():
            if ktype in {"amap_key", "qqmap_key", "umeng_appkey"}:
                for v in vals:
                    key_owners[ktype][v].add(r["appid"])

    reused = []
    apps_reused: set[str] = set()
    for ktype, mapping in key_owners.items():
        for key, apps in mapping.items():
            if len(apps) >= 3:
                reused.append({
                    "type": ktype,
                    "key_fingerprint": key[:6] + "…" + key[-4:],
                    "app_count": len(apps),
                    "sample_appids": sorted(apps)[:5],
                })
                apps_reused.update(apps)

    TYPE_CN = {
        "amap_key": "硬编码高德Key",
        "qqmap_key": "硬编码腾讯地图Key",
        "umeng_appkey": "硬编码友盟AppKey",
        "plaintext_secret": "明文Secret/Token",
        "http_third_party": "HTTP明文调用第三方",
        "privacy_vendor_undisclosed": "高敏SDK疑似未披露",
        "location_with_undisclosed_sdk": "定位+未披露第三方SDK",
        "shared_api_key": "API Key跨多个小程序复用",
    }
    DESC = {
        "amap_key": "客户端嵌入高德Key，易被盗用，常违反密钥保密要求",
        "qqmap_key": "客户端嵌入腾讯地图Key",
        "umeng_appkey": "友盟AppKey硬编码（常见，重点看是否串用）",
        "plaintext_secret": "appsecret 等绝不应出现在小程序包内",
        "http_third_party": "第三方接口走 HTTP，传输明文",
        "privacy_vendor_undisclosed": "使用高敏SDK但入口/隐私文案未提服务商（启发式）",
        "location_with_undisclosed_sdk": "有定位采集且第三方未披露",
        "shared_api_key": "同一Key被≥3个小程序共用，疑似违规共享/白牌滥用",
    }

    type_counter = Counter()
    sev_high: set[str] = set(apps_reused)
    sev_mid: set[str] = set()
    any_flag: set[str] = set(apps_reused)
    for r in rows:
        for f in r.get("flags") or []:
            type_counter[f["type"]] += 1
            any_flag.add(r["appid"])
            if f["severity"] == "高":
                sev_high.add(r["appid"])
            elif f["severity"] == "中":
                sev_mid.add(r["appid"])
    if apps_reused:
        type_counter["shared_api_key"] = len(apps_reused)

    flag_table = []
    for t, _ in type_counter.most_common():
        if t == "shared_api_key":
            apps = len(apps_reused)
            sev = "高"
        else:
            apps = len({r["appid"] for r in rows if any(f["type"] == t for f in r.get("flags") or [])})
            sev = "高" if t in {
                "amap_key", "qqmap_key", "plaintext_secret", "http_third_party",
                "location_with_undisclosed_sdk", "shared_api_key",
            } else "中"
        flag_table.append({
            "红旗类型": TYPE_CN.get(t, t),
            "type": t,
            "命中app数": apps,
            "占样本%": round(100.0 * apps / n, 2),
            "风险等级": sev,
            "说明": DESC.get(t, ""),
        })

    high_apps = []
    for r in rows:
        if r["appid"] not in sev_high:
            continue
        titles = [f["title"] for f in r.get("flags") or []]
        if r["appid"] in apps_reused:
            titles.append("API Key跨小程序复用")
        high_apps.append({
            "appid": r["appid"],
            "flags": "；".join(dict.fromkeys(titles)),
            "sdks": "、".join((r.get("sdks") or [])[:6]),
        })

    report = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "disclaimer": "自动化红旗检测，用于测绘摸底；隐私披露为启发式，不构成法律认定。扫描范围为入口/配置类文件。",
        "sample_size": n,
        "apps_with_any_flag": len(any_flag),
        "apps_with_any_flag_pct": round(100.0 * len(any_flag) / n, 2),
        "apps_severity_high": len(sev_high),
        "apps_severity_high_pct": round(100.0 * len(sev_high) / n, 2),
        "apps_severity_medium_only": len(sev_mid - sev_high),
        "reused_key_count": len(reused),
        "apps_with_reused_key": len(apps_reused),
        "reused_keys_top": sorted(reused, key=lambda x: -x["app_count"])[:30],
        "flag_table": flag_table,
        "high_risk_app_count": len(high_apps),
        "elapsed_sec": round(time.time() - t0, 2),
    }

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / "sdk_violation_flags.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    with (OUT_DIR / "sdk_violation_flags.csv").open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["红旗类型", "type", "命中app数", "占样本%", "风险等级", "说明"])
        w.writeheader()
        w.writerows(flag_table)
    with (OUT_DIR / "sdk_violation_high_apps.csv").open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["appid", "flags", "sdks"])
        w.writeheader()
        w.writerows(high_apps)

    with (OUT_DIR / "sdk_violation_per_app.jsonl").open("w", encoding="utf-8") as f:
        for r in rows:
            if r["flag_count"] or r["appid"] in apps_reused:
                safe = dict(r)
                safe["keys"] = {
                    k: [v[:6] + "…" + v[-4:] if len(v) > 12 else "***" for v in vals]
                    for k, vals in (r.get("keys") or {}).items()
                }
                if r["appid"] in apps_reused:
                    safe.setdefault("flags", []).append({
                        "type": "shared_api_key", "severity": "高",
                        "title": "API Key跨小程序复用", "count": 1, "samples": [],
                    })
                f.write(json.dumps(safe, ensure_ascii=False) + "\n")

    print(json.dumps({
        "sample": n,
        "any_flag": report["apps_with_any_flag"],
        "high": report["apps_severity_high"],
        "reused_keys": report["reused_key_count"],
        "apps_reused_key": report["apps_with_reused_key"],
        "flag_table": flag_table,
        "reused_top10": report["reused_keys_top"][:10],
        "elapsed": report["elapsed_sec"],
    }, ensure_ascii=False, indent=2), flush=True)


if __name__ == "__main__":
    main()
