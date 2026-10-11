# -*- coding: utf-8 -*-
"""统计已成功处理小程序中的第三方 SDK / 插件分布。"""
from __future__ import annotations

import json
import os
import re
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

DATA = Path(r"E:\MiniCrest\Data")
RAW = DATA / "_raw"
REG = DATA / "_processed.json"
OUT = DATA / "_reports" / "sdk_distribution.json"
APPID_RE = re.compile(r"^wx[0-9a-fA-F]{16}$")

NPM_MAP = {
    "@vant/weapp": "Vant Weapp",
    "vant-weapp": "Vant Weapp",
    "@tdesign/miniprogram": "TDesign",
    "tdesign-miniprogram": "TDesign",
    "weui-miniprogram": "WeUI",
    "weui-wxss": "WeUI",
    "@miniprogram-i18n/core": "miniprogram-i18n",
    "miniprogram-computed": "miniprogram-computed",
    "miniprogram-sm-crypto": "sm-crypto",
    "mobx-miniprogram": "MobX",
    "mobx-miniprogram-bindings": "MobX",
    "echarts": "ECharts",
    "echarts-for-weixin": "ECharts",
    "ec-canvas": "ECharts",
    "lin-ui": "Lin UI",
    "wux-weapp": "Wux Weapp",
    "iview-weapp": "iView Weapp",
    "@dcloudio/vant-weapp": "Vant Weapp",
    "mescroll-uni": "MeScroll",
    "mescroll": "MeScroll",
    "dayjs": "dayjs",
    "lodash": "lodash",
    "lodash-es": "lodash",
    "crypto-js": "crypto-js",
    "js-md5": "js-md5",
    "qrcode": "qrcode",
    "weapp-qrcode": "qrcode",
    "@tencent/weui": "WeUI",
    "mp-colorui": "ColorUI",
    "colorui": "ColorUI",
    "@babel/runtime": "@babel/runtime",
    "tslib": "tslib",
    "regenerator-runtime": "regenerator-runtime",
    "miniprogram-recycle-view": "recycle-view",
    "wxml-to-canvas": "wxml-to-canvas",
    "painter": "Painter",
    "@antv/f2": "AntV F2",
    "wxcharts": "wxcharts",
    "towxml": "towxml",
    "mp-html": "mp-html",
}

PLUGIN_MAP = {
    "sendCoupon": "微信卡券插件",
    "live-player-plugin": "直播插件",
    "WechatSI": "同声传译插件",
    "studentVerify": "学生验证插件",
    "wxPaymentPlugin": "微信支付插件",
    "cityservice": "城市服务插件",
    "materialPlugin": "素材插件",
    "captcha": "验证码插件",
    "ocr-plugin": "OCR插件",
    "advert-plugin": "广告插件",
}

PROVIDER_MAP = {
    "wxf3f436ba9bd4be7b": "微信卡券插件",
    "wx2b03c6e691cd7370": "直播插件",
    "wx069ba97219f66d99": "同声传译插件",
    "wxa16657d57059e0f0": "学生验证插件",
    "wx1fde2c33280d64b6": "微信支付相关插件",
    "wxafb4fcc54c70a08a": "广告插件",
}

CODE_MARKERS = [
    (re.compile(r"sensorsdata|神策", re.I), "神策分析 Sensors"),
    (re.compile(r"growingio|gio\(", re.I), "GrowingIO"),
    (re.compile(r"umeng|友盟", re.I), "友盟统计"),
    (re.compile(r"tdanalytics|thinkingdata|数数科技", re.I), "ThinkingData数数"),
    (re.compile(r"meituan\.net|rmsminamaterial|mtstat", re.I), "美团SaaS相关"),
    (re.compile(r"youzan|有赞", re.I), "有赞"),
    (re.compile(r"weimob|微盟", re.I), "微盟"),
    (re.compile(r"welife|微生活", re.I), "腾讯微生活"),
    (re.compile(r"qqmap|腾讯地图|TMapWx", re.I), "腾讯地图"),
    (re.compile(r"amap|高德", re.I), "高德地图"),
    (re.compile(r"qiyukf|七鱼", re.I), "网易七鱼客服"),
    (re.compile(r"zhichi|智齿", re.I), "智齿客服"),
]


def load_ok_targets() -> list[tuple[str, Path | None]]:
    d = json.loads(REG.read_text(encoding="utf-8"))
    items = d.get("items", d)
    out: list[tuple[str, Path | None]] = []
    for appid, info in items.items():
        if not isinstance(info, dict) or info.get("status") != "ok":
            continue
        if not APPID_RE.match(appid):
            continue
        paths: list[Path] = []
        raw = RAW / appid
        if raw.is_dir():
            paths.append(raw)
        archived = info.get("archived_to")
        if archived:
            p = Path(str(archived))
            if p.is_dir():
                paths.append(p)
        out.append((appid, paths[0] if paths else None))
    return out


def read_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        try:
            return json.loads(path.read_text(encoding="utf-8-sig"))
        except Exception:
            return {}


def add_plugin(found: set[str], pname: str, pinfo) -> None:
    label = PLUGIN_MAP.get(pname)
    if not label and isinstance(pinfo, dict):
        label = PROVIDER_MAP.get(str(pinfo.get("provider") or ""), "")
    if not label:
        label = f"plugin:{pname}"
    found.add(label)


def scan_one(appid: str, root: Path | None) -> dict:
    found: set[str] = set()
    if root is None or not root.is_dir():
        return {"appid": appid, "sdks": [], "missing": True}

    npm = root / "miniprogram_npm"
    if npm.is_dir():
        try:
            for child in npm.iterdir():
                if not child.is_dir():
                    continue
                name = child.name
                if name in {"__extended__", "pages", "components"}:
                    continue
                if name.startswith("@"):
                    try:
                        for sub in child.iterdir():
                            if sub.is_dir():
                                full = f"{name}/{sub.name}"
                                found.add(NPM_MAP.get(full, full))
                    except OSError:
                        pass
                else:
                    found.add(NPM_MAP.get(name, name))
        except OSError:
            pass

    for fname in ("app.json", "app-config.json"):
        fp = root / fname
        if not fp.is_file():
            continue
        data = read_json(fp)
        plugins = data.get("plugins") or {}
        if isinstance(plugins, dict):
            for pname, pinfo in plugins.items():
                add_plugin(found, pname, pinfo)
        for sp in data.get("subPackages") or data.get("subpackages") or []:
            if isinstance(sp, dict) and isinstance(sp.get("plugins"), dict):
                for pname, pinfo in sp["plugins"].items():
                    add_plugin(found, pname, pinfo)
        try:
            text = fp.read_text(encoding="utf-8", errors="ignore")[:200_000]
            for cre, label in CODE_MARKERS:
                if cre.search(text):
                    found.add(label)
        except OSError:
            pass

    return {"appid": appid, "sdks": sorted(found), "missing": False}


def main() -> None:
    t0 = time.time()
    targets = load_ok_targets()
    print(f"ok targets: {len(targets)}", flush=True)
    workers = min(16, (os.cpu_count() or 4) * 2)
    rows: list[dict] = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [ex.submit(scan_one, a, p) for a, p in targets]
        done = 0
        for fut in as_completed(futs):
            rows.append(fut.result())
            done += 1
            if done % 300 == 0:
                print(f"scanned {done}/{len(targets)}", flush=True)

    sdk_counter: Counter[str] = Counter()
    apps_with_sdk = 0
    missing = 0
    for r in rows:
        if r.get("missing"):
            missing += 1
            continue
        sdks = r.get("sdks") or []
        if sdks:
            apps_with_sdk += 1
        for s in sdks:
            sdk_counter[s] += 1

    scanned = len(rows) - missing
    ranking = [
        {
            "sdk": k,
            "count": v,
            "pct_of_scanned": round(100.0 * v / scanned, 2) if scanned else 0.0,
        }
        for k, v in sdk_counter.most_common(100)
    ]

    ui = {"Vant Weapp", "TDesign", "WeUI", "Lin UI", "Wux Weapp", "iView Weapp", "ColorUI"}
    growth = {"神策分析 Sensors", "GrowingIO", "友盟统计", "ThinkingData数数"}
    saas = {"美团SaaS相关", "有赞", "微盟", "腾讯微生活"}
    maps = {"腾讯地图", "高德地图"}

    def hit(members: set[str]) -> int:
        return sum(
            1
            for r in rows
            if (not r.get("missing")) and any(s in members for s in (r.get("sdks") or []))
        )

    plugin_hit = sum(
        1
        for r in rows
        if (not r.get("missing"))
        and any(("插件" in s or s.startswith("plugin:")) for s in (r.get("sdks") or []))
    )

    categories = [
        {"category": "UI组件库", "apps": hit(ui), "pct": round(100 * hit(ui) / scanned, 2) if scanned else 0},
        {"category": "微信官方/第三方插件", "apps": plugin_hit, "pct": round(100 * plugin_hit / scanned, 2) if scanned else 0},
        {"category": "数据增长SDK", "apps": hit(growth), "pct": round(100 * hit(growth) / scanned, 2) if scanned else 0},
        {"category": "SaaS平台痕迹", "apps": hit(saas), "pct": round(100 * hit(saas) / scanned, 2) if scanned else 0},
        {"category": "地图SDK", "apps": hit(maps), "pct": round(100 * hit(maps) / scanned, 2) if scanned else 0},
    ]

    report = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "ok_registry": len(targets),
        "scanned_with_path": scanned,
        "missing_path": missing,
        "apps_with_any_sdk": apps_with_sdk,
        "apps_with_any_sdk_pct": round(100.0 * apps_with_sdk / scanned, 2) if scanned else 0,
        "unique_sdk_labels": len(sdk_counter),
        "ranking": ranking,
        "categories": categories,
        "elapsed_sec": round(time.time() - t0, 2),
        "method": "miniprogram_npm + app.json/app-config plugins + config keyword markers",
        "note": "分母 scanned_with_path=能找到解包目录的成功样本；missing_path 表示登记成功但本地路径缺失",
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(
        json.dumps(
            {
                "ok": len(targets),
                "scanned": scanned,
                "missing": missing,
                "with_sdk": apps_with_sdk,
                "top20": ranking[:20],
                "categories": categories,
                "elapsed": report["elapsed_sec"],
                "out": str(OUT),
            },
            ensure_ascii=False,
            indent=2,
        ),
        flush=True,
    )


if __name__ == "__main__":
    main()
