# -*- coding: utf-8 -*-
"""用 ripgrep 快速扫 _raw 中的 SDK 合规红旗。"""
from __future__ import annotations

import csv
import json
import re
import subprocess
import time
from collections import Counter, defaultdict
from pathlib import Path

DATA = Path(r"E:\MiniCrest\Data")
RAW = DATA / "_raw"
PER_APP = DATA / "_reports" / "sdk_per_app.jsonl"
OUT = DATA / "_reports"
RG = Path(r"d:\Program Files\cursor\cursor\resources\app\node_modules\@vscode\ripgrep\bin\rg.exe")
APPID_RE = re.compile(r"^(wx[0-9a-fA-F]{16})")

# pattern, type, severity, title
PATTERNS = [
    (
        r"restapi\.amap\.com[^'\"\s]*[?&]key=([A-Za-z0-9]{20,40})",
        "amap_key",
        "高",
        "硬编码高德Key(URL)",
    ),
    (
        r"(?:amapKey|gaodeKey|amap_key)\s*[:=]\s*['\"]([A-Za-z0-9]{20,40})['\"]",
        "amap_key",
        "高",
        "硬编码高德Key(配置)",
    ),
    (
        r"map\.qq\.com[^'\"\s]*[?&]key=([A-Z0-9-]{20,45})",
        "qqmap_key",
        "高",
        "硬编码腾讯地图Key",
    ),
    (
        r"(?:appsecret|app_secret|client_secret)\s*[:=]\s*['\"]([^'\"]{8,80})['\"]",
        "plaintext_secret",
        "高",
        "明文AppSecret",
    ),
    (
        r"http://restapi\.amap\.com",
        "http_third_party",
        "高",
        "HTTP明文调用高德",
    ),
    (
        r"http://apis\.map\.qq\.com",
        "http_third_party",
        "高",
        "HTTP明文调用腾讯地图",
    ),
    (
        r"(?:umeng|umtrack).{0,40}(?:appkey|appKey)\s*[:=]\s*['\"]([0-9a-fA-F]{20,32})['\"]",
        "umeng_appkey",
        "中",
        "硬编码友盟AppKey",
    ),
]


def rg(pattern: str) -> list[tuple[str, str]]:
    """返回 (appid, matched_line_or_capture)。"""
    cmd = [
        str(RG),
        "--no-messages",
        "-a",
        "-o",
        "--no-heading",
        "-g",
        "!miniprogram_npm/**",
        "-g",
        "*.js",
        "-g",
        "*.json",
        "-g",
        "*.ts",
        pattern,
        str(RAW),
    ]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="ignore", timeout=600)
    except subprocess.TimeoutExpired:
        return []
    out = []
    for line in (p.stdout or "").splitlines():
        # path:match
        if ":" not in line:
            continue
        # Windows path E:\...\wx...\file:match
        m = re.search(r"\\(wx[0-9a-fA-F]{16})\\", line)
        if not m:
            continue
        appid = m.group(1)
        # capture after last colon following extension roughly
        parts = line.split(":", 2)
        payload = parts[-1] if len(parts) >= 2 else line
        # extract key-like token
        key_m = re.search(r"([A-Za-z0-9_-]{16,80})", payload)
        val = key_m.group(1) if key_m else payload[:80]
        out.append((appid, val))
    return out


def load_sdks() -> dict[str, list[str]]:
    d = {}
    if not PER_APP.is_file():
        return d
    for line in PER_APP.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        d[row["appid"]] = row.get("sdks") or []
    return d


def main():
    t0 = time.time()
    sdks_map = load_sdks()
    sample = len(sdks_map) or 4197
    print(f"per_app apps: {len(sdks_map)}", flush=True)

    # type -> appid -> set(values)
    hits: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    type_meta = {}

    for pattern, typ, sev, title in PATTERNS:
        print(f"rg: {title} ...", flush=True)
        rows = rg(pattern)
        type_meta[typ] = (sev, title)
        for appid, val in rows:
            # filter placeholders
            if typ == "plaintext_secret" and val.lower() in {
                "your_secret", "xxx", "test", "null", "undefined", "placeholder", "secret", "appsecret"
            }:
                continue
            hits[typ][appid].add(val)
        print(f"  apps={len(hits[typ])} raw_hits={len(rows)}", flush=True)

    # key reuse
    reused = []
    apps_reused = set()
    for typ in ("amap_key", "qqmap_key", "umeng_appkey"):
        owners = defaultdict(set)
        for appid, vals in hits.get(typ, {}).items():
            for v in vals:
                owners[v].add(appid)
        for key, apps in owners.items():
            if len(apps) >= 3:
                reused.append({
                    "type": typ,
                    "key_fingerprint": key[:6] + "…" + key[-4:] if len(key) > 12 else key,
                    "app_count": len(apps),
                    "sample_appids": sorted(apps)[:5],
                })
                apps_reused.update(apps)

    # privacy heuristic: high-risk sdk but no vendor name in app.js/app.json via rg
    print("rg: privacy disclosure heuristic ...", flush=True)
    undisclosed = set()
    loc_undisclosed = set()
    # apps with 高德
    amap_apps = {a for a, s in sdks_map.items() if "高德地图" in s}
    youzan_apps = {a for a, s in sdks_map.items() if "有赞" in s}
    meituan_apps = {a for a, s in sdks_map.items() if "美团SaaS相关" in s}
    umeng_apps = {a for a, s in sdks_map.items() if "umtrack-wx" in s or "友盟统计" in s}

    def apps_mention(pattern: str) -> set[str]:
        rows = rg(pattern)
        return {a for a, _ in rows}

    mention_gaode = apps_mention(r"高德|amap")
    mention_youzan = apps_mention(r"有赞|youzan")
    mention_meituan = apps_mention(r"美团|meituan")
    mention_umeng = apps_mention(r"友盟|umeng|umtrack")

    for a in amap_apps:
        if a not in mention_gaode:
            undisclosed.add(a)
    for a in youzan_apps:
        if a not in mention_youzan:
            undisclosed.add(a)
    for a in meituan_apps:
        if a not in mention_meituan:
            undisclosed.add(a)
    for a in umeng_apps:
        if a not in mention_umeng:
            undisclosed.add(a)

    loc_apps = apps_mention(r"wx\.getLocation|wx\.chooseLocation|getFuzzyLocation")
    loc_undisclosed = (loc_apps & (amap_apps | youzan_apps | meituan_apps | umeng_apps) & undisclosed)

    hits["privacy_vendor_undisclosed"] = {a: {"1"} for a in undisclosed}
    hits["location_with_undisclosed_sdk"] = {a: {"1"} for a in loc_undisclosed}
    type_meta["privacy_vendor_undisclosed"] = ("中", "高敏SDK疑似未披露")
    type_meta["location_with_undisclosed_sdk"] = ("高", "定位+未披露第三方SDK")
    type_meta["shared_api_key"] = ("高", "API Key跨多个小程序复用")

    DESC = {
        "amap_key": "客户端嵌入高德Key，易被盗用，常违反密钥保密要求",
        "qqmap_key": "客户端嵌入腾讯地图Key",
        "umeng_appkey": "友盟AppKey硬编码（常见，重点看是否串用）",
        "plaintext_secret": "appsecret 等绝不应出现在小程序包内",
        "http_third_party": "第三方接口走 HTTP，传输明文",
        "privacy_vendor_undisclosed": "使用高敏SDK但代码/配置中几乎未出现服务商名称（启发式，偏宽）",
        "location_with_undisclosed_sdk": "有定位采集且第三方服务商名疑似未披露",
        "shared_api_key": "同一Key被≥3个小程序共用，疑似违规共享/白牌滥用",
    }

    flag_table = []
    any_flag = set(apps_reused)
    high = set(apps_reused)
    mid = set()

    order = [
        "amap_key", "qqmap_key", "plaintext_secret", "http_third_party",
        "shared_api_key", "location_with_undisclosed_sdk",
        "umeng_appkey", "privacy_vendor_undisclosed",
    ]
    for typ in order:
        if typ == "shared_api_key":
            apps = len(apps_reused)
            sev, title = "高", "API Key跨多个小程序复用"
        else:
            apps = len(hits.get(typ, {}))
            sev, title = type_meta.get(typ, ("中", typ))
            any_flag.update(hits.get(typ, {}).keys())
            if sev == "高":
                high.update(hits.get(typ, {}).keys())
            else:
                mid.update(hits.get(typ, {}).keys())
        if apps == 0 and typ != "shared_api_key":
            continue
        flag_table.append({
            "红旗类型": title,
            "type": typ,
            "命中app数": apps if typ != "shared_api_key" else len(apps_reused),
            "占样本%": round(100.0 * (apps if typ != "shared_api_key" else len(apps_reused)) / sample, 2),
            "风险等级": sev,
            "说明": DESC.get(typ, ""),
        })

    high_apps = []
    for a in sorted(high):
        titles = []
        for typ in order:
            if typ == "shared_api_key":
                if a in apps_reused:
                    titles.append("API Key跨小程序复用")
            elif a in hits.get(typ, {}):
                titles.append(type_meta[typ][1])
        high_apps.append({
            "appid": a,
            "flags": "；".join(dict.fromkeys(titles)),
            "sdks": "、".join((sdks_map.get(a) or [])[:6]),
        })

    report = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "disclaimer": "基于解包代码的自动化红旗检测，用于测绘摸底；不构成法律认定。隐私披露为启发式。",
        "method": "ripgrep over _raw (exclude miniprogram_npm)",
        "sample_size": sample,
        "apps_with_any_flag": len(any_flag),
        "apps_with_any_flag_pct": round(100.0 * len(any_flag) / sample, 2),
        "apps_severity_high": len(high),
        "apps_severity_high_pct": round(100.0 * len(high) / sample, 2),
        "apps_severity_medium_only": len(mid - high),
        "reused_key_count": len(reused),
        "apps_with_reused_key": len(apps_reused),
        "reused_keys_top": sorted(reused, key=lambda x: -x["app_count"])[:30],
        "flag_table": flag_table,
        "high_risk_app_count": len(high_apps),
        "elapsed_sec": round(time.time() - t0, 2),
    }

    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "sdk_violation_flags.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    with (OUT / "sdk_violation_flags.csv").open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["红旗类型", "type", "命中app数", "占样本%", "风险等级", "说明"])
        w.writeheader()
        w.writerows(flag_table)
    with (OUT / "sdk_violation_high_apps.csv").open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["appid", "flags", "sdks"])
        w.writeheader()
        w.writerows(high_apps)

    print(json.dumps({
        "sample": sample,
        "any_flag": report["apps_with_any_flag"],
        "high": report["apps_severity_high"],
        "reused_keys": report["reused_key_count"],
        "apps_reused": report["apps_with_reused_key"],
        "flag_table": flag_table,
        "reused_top8": report["reused_keys_top"][:8],
        "elapsed": report["elapsed_sec"],
    }, ensure_ascii=False, indent=2), flush=True)


if __name__ == "__main__":
    main()
