# -*- coding: utf-8 -*-
"""
测绘用：第三方 SDK → 功能类别 × 服务商 归类统计。
基于 registry status=ok 样本，输出 JSON/CSV 便于后续对照安全条款。
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
OUT_DIR = DATA / "_reports"
APPID_RE = re.compile(r"^wx[0-9a-fA-F]{16}$")

# ---------------------------------------------------------------------------
# 归类规则：功能类别（测绘维度）+ 服务商
# 安全条款调研优先关注：地图、分析、SaaS、广告、验证码/风控、支付、客服
# ---------------------------------------------------------------------------

# (match_fn(label) -> bool) or exact / prefix rules applied in order
# category, vendor, compliance_focus (高/中/低)


def classify(label: str) -> tuple[str, str, str, str]:
    """返回 (功能类别, 服务商, 合规关注度, 归类依据简述)。"""
    s = label.strip()
    sl = s.lower()

    # ---- 地图定位 ----
    if s in {"高德地图"} or "amap" in sl or "高德" in s:
        return "地图定位", "高德（阿里巴巴）", "高", "地图SDK，常涉位置与轨迹数据"
    if s in {"腾讯地图"} or "qqmap" in sl or "腾讯地图" in s:
        return "地图定位", "腾讯位置服务", "高", "地图SDK"
    if "百度地图" in s or "bmap" in sl:
        return "地图定位", "百度地图", "高", "地图SDK"

    # ---- 数据分析 / 增长 ----
    if "神策" in s or "sensors" in sl:
        return "数据分析与增长", "神策数据", "高", "行为分析SDK，用户事件上报"
    if "growingio" in sl or s == "GrowingIO":
        return "数据分析与增长", "GrowingIO", "高", "行为分析SDK"
    if "友盟" in s or "umtrack" in sl or "umeng" in sl:
        return "数据分析与增长", "友盟（阿里巴巴）", "高", "统计/归因SDK"
    if "thinkingdata" in sl or "数数" in s or "tdanalytics" in sl:
        return "数据分析与增长", "数数科技 ThinkingData", "高", "游戏/应用分析"
    if sl in {"@analytics/wechat-sdk"} or "analytics" in sl and "wechat" in sl:
        return "数据分析与增长", "美团", "高", "美团体系分析包"
    if "@aliyun-sls" in sl or "web-track-mini" in sl:
        return "数据分析与增长", "阿里云", "高", "日志/埋点上报"
    if "@dp/owl" in sl:
        return "数据分析与增长", "美团", "中", "前端监控（美团点评）"

    # ---- 电商 / 餐饮 SaaS 白牌 ----
    if s in {"美团SaaS相关"} or sl.startswith("@mtfe/") or sl.startswith("@limo/") or sl.startswith(
        "@components/limo"
    ):
        return "电商/餐饮SaaS", "美团", "高", "白牌点餐/SaaS模板依赖"
    if sl.startswith("@dp/") and sl not in {"@dp/owl-wxapp"}:
        return "电商/餐饮SaaS", "美团", "高", "美团点评体系包"
    if s in {"有赞"} or "youzan" in sl or sl.startswith("plugin:yz") or "yzvideo" in sl:
        return "电商/餐饮SaaS", "有赞", "高", "有赞电商能力/插件"
    if s in {"微盟"} or "weimob" in sl:
        return "电商/餐饮SaaS", "微盟", "高", "微盟电商能力"
    if s in {"腾讯微生活"} or "welife" in sl:
        return "电商/餐饮SaaS", "腾讯微生活", "高", "会员/门店SaaS"

    # ---- 支付 ----
    if "支付" in s or "payment" in sl or "wxpayment" in sl:
        return "支付与金融", "微信支付（腾讯）", "高", "支付插件/能力"

    # ---- 广告营销 ----
    if "广告" in s or "advert" in sl or "adplus" in sl:
        return "广告与营销", "微信广告/流量主生态", "高", "广告插件，涉设备与转化数据"
    if "lucky-canvas" in sl or "@lucky-canvas" in sl:
        return "广告与营销", "开源抽奖组件", "低", "营销互动UI，非云服务商"

    # ---- 安全 / 验证码 / 风控 ----
    if "jsguard" in sl or "safety-request" in sl:
        return "安全风控与验证", "美团", "高", "请求防护/加固"
    if "aliyuncaptcha" in sl or "captcha4" in sl or "awscwx" in sl:
        return "安全风控与验证", "阿里云", "高", "人机验证/风控"
    if s in {"验证码插件"} or sl == "plugin:captcha":
        return "安全风控与验证", "腾讯云/微信生态", "高", "验证码插件"
    if "tdfp" in sl:
        return "安全风控与验证", "同盾（疑似）", "高", "设备指纹类插件名"
    if "turing" in sl:
        return "安全风控与验证", "腾讯天御（疑似）", "高", "图灵/天御类插件名"
    if "sm-crypto" in sl or s == "sm-crypto":
        return "安全风控与验证", "开源国密实现", "中", "国密算法库，关注密钥与实现正确性"
    if "crypto-js" in sl or sl in {"jsbn", "wxmp-rsa", "js-md5", "md5", "charenc", "crypt"}:
        return "安全风控与验证", "开源密码学工具", "中", "加解密/哈希工具库"

    # ---- 微信官方能力插件 ----
    WECHAT_OFFICIAL = {
        "微信卡券插件",
        "同声传译插件",
        "学生验证插件",
        "直播插件",
        "素材插件",
        "OCR插件",
        "城市服务插件",
    }
    if s in WECHAT_OFFICIAL:
        return "微信官方能力插件", "腾讯微信", "中", "微信官方插件，仍需遵守插件服务条款"
    if sl.startswith("plugin:healthcard") or "healthcard" in sl:
        return "微信官方能力插件", "腾讯微信/医保健康卡", "中", "健康卡相关插件"
    if sl in {
        "plugin:chooselocation",
        "plugin:routeplan",
        "plugin:cityselector",
        "plugin:logisticsplugin",
        "plugin:wxacommentplugin",
        "plugin:wx-invoice",
        "plugin:wxparserplugin",
        "plugin:contactplugin",
        "plugin:tencentvideo",
        "plugin:qcloudaivoice",
        "plugin:chatbot",
    }:
        return "微信官方能力插件", "腾讯微信/腾讯云", "中", "微信/腾讯云官方或近官方插件"

    # ---- UI 组件 ----
    if s in {"Vant Weapp"} or "@vant/" in sl or "vant" in sl:
        return "UI组件库", "有赞开源（Vant）", "低", "开源UI，主要关注开源许可而非数据条款"
    if s in {"WeUI", "TDesign"} or "weui" in sl or "tdesign" in sl:
        return "UI组件库", "腾讯开源", "低", "开源UI组件"
    if s in {"Lin UI", "Wux Weapp", "iView Weapp", "ColorUI", "widget-ui"}:
        return "UI组件库", "开源UI社区", "低", "第三方开源UI"
    if "mp-html" in sl or "towxml" in sl:
        return "UI组件库", "开源富文本", "低", "富文本渲染"

    # ---- 客服 ----
    if "七鱼" in s or "qiyukf" in sl:
        return "在线客服", "网易七鱼", "高", "客服SDK，会话与用户标识"
    if "智齿" in s or "zhichi" in sl:
        return "在线客服", "智齿科技", "高", "客服SDK"

    # ---- 通用开源工程库（非云服务商）----
    OPEN_SOURCE = {
        "redux",
        "redux-thunk",
        "reselect",
        "seamless-immutable",
        "wechat-weapp-redux-extend",
        "dayjs",
        "moment",
        "MobX",
        "miniprogram-computed",
        "rfdc",
        "fast-deep-equal",
        "colord",
        "tslib",
        "qs",
        "base64-js",
        "js-base64",
        "is-buffer",
        "lottie-miniprogram",
        "wxml-to-canvas",
        "recycle-view",
        "miniprogram-element",
        "miniprogram-render",
        "qrcode",
        "weapp-qrcode-canvas-2d",
        "@babel/runtime",
        "regenerator-runtime",
        "lodash",
        "ECharts",
    }
    if s in OPEN_SOURCE or sl.startswith("@henrydf/") or sl.startswith("@acewill/"):
        return "开源工程依赖", "开源社区/独立作者", "低", "无云端服务商数据条款，关注许可证"

    # ---- 未识别插件 / 包 ----
    if sl.startswith("plugin:"):
        return "未归类插件", "待识别第三方", "中", "插件名未能映射到已知服务商，需二次人工核对"
    if sl.startswith("@") or "/" in sl:
        return "未归类npm包", "待识别第三方", "中", "作用域包未能映射，需二次核对"

    return "其他/未归类", "待识别", "低", "未命中规则"


# ---- 扫描（与 sdk_stats 对齐，轻量）----
NPM_MAP = {
    "@vant/weapp": "Vant Weapp",
    "vant-weapp": "Vant Weapp",
    "@tdesign/miniprogram": "TDesign",
    "tdesign-miniprogram": "TDesign",
    "weui-miniprogram": "WeUI",
    "weui-wxss": "WeUI",
    "mobx-miniprogram": "MobX",
    "mobx-miniprogram-bindings": "MobX",
    "miniprogram-sm-crypto": "sm-crypto",
    "miniprogram-computed": "miniprogram-computed",
    "miniprogram-recycle-view": "recycle-view",
    "crypto-js": "crypto-js",
    "dayjs": "dayjs",
    "moment": "moment",
    "echarts": "ECharts",
    "echarts-for-weixin": "ECharts",
    "mp-html": "mp-html",
    "wxml-to-canvas": "wxml-to-canvas",
}

PLUGIN_MAP = {
    "sendCoupon": "微信卡券插件",
    "live-player-plugin": "直播插件",
    "WechatSI": "同声传译插件",
    "studentVerify": "学生验证插件",
    "wxPaymentPlugin": "微信支付插件",
    "materialPlugin": "素材插件",
    "captcha": "验证码插件",
    "ocr-plugin": "OCR插件",
    "advert-plugin": "广告插件",
}

CODE_MARKERS = [
    (re.compile(r"sensorsdata|神策", re.I), "神策分析 Sensors"),
    (re.compile(r"growingio|gio\(", re.I), "GrowingIO"),
    (re.compile(r"umeng|友盟|umtrack", re.I), "友盟统计"),
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
        raw = RAW / appid
        archived = info.get("archived_to")
        path = None
        if raw.is_dir():
            path = raw
        elif archived and Path(str(archived)).is_dir():
            path = Path(str(archived))
        out.append((appid, path))
    return out


def read_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        try:
            return json.loads(path.read_text(encoding="utf-8-sig"))
        except Exception:
            return {}


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
                label = PLUGIN_MAP.get(pname)
                if not label and isinstance(pinfo, dict):
                    # keep raw plugin name for later classify
                    label = f"plugin:{pname}"
                found.add(label or f"plugin:{pname}")
        for sp in data.get("subPackages") or data.get("subpackages") or []:
            if isinstance(sp, dict) and isinstance(sp.get("plugins"), dict):
                for pname in sp["plugins"]:
                    found.add(PLUGIN_MAP.get(pname, f"plugin:{pname}"))
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
    workers = min(20, (os.cpu_count() or 4) * 2)

    rows: list[dict] = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [ex.submit(scan_one, a, p) for a, p in targets]
        done = 0
        for fut in as_completed(futs):
            rows.append(fut.result())
            done += 1
            if done % 400 == 0:
                print(f"scanned {done}/{len(targets)}", flush=True)

    # 持久化 per-app，便于后续条款对照不重扫
    per_app_path = OUT_DIR / "sdk_per_app.jsonl"
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    with per_app_path.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    scanned = [r for r in rows if not r.get("missing")]
    n = len(scanned)

    # 每个 app 的 (category, vendor) 集合
    cat_apps: dict[str, set[str]] = defaultdict(set)
    vendor_apps: dict[str, set[str]] = defaultdict(set)
    vendor_cats: dict[str, set[str]] = defaultdict(set)
    vendor_sdk_counter: dict[str, Counter] = defaultdict(Counter)
    focus_apps: dict[str, set[str]] = defaultdict(set)
    label_meta: dict[str, tuple[str, str, str, str]] = {}

    for r in scanned:
        appid = r["appid"]
        seen_cv: set[tuple[str, str]] = set()
        for sdk in r.get("sdks") or []:
            cat, vendor, focus, why = classify(sdk)
            label_meta[sdk] = (cat, vendor, focus, why)
            vendor_sdk_counter[vendor][sdk] += 1
            key = (cat, vendor)
            if key not in seen_cv:
                seen_cv.add(key)
                cat_apps[cat].add(appid)
                vendor_apps[vendor].add(appid)
                vendor_cats[vendor].add(cat)
                focus_apps[focus].add(appid)

    # 任一「高合规关注」类别命中
    HIGH_CATS = {
        "地图定位",
        "数据分析与增长",
        "电商/餐饮SaaS",
        "支付与金融",
        "广告与营销",
        "安全风控与验证",
        "在线客服",
    }
    high_compliance_apps = set()
    for cat in HIGH_CATS:
        high_compliance_apps |= cat_apps.get(cat, set())

    category_table = []
    for cat, apps in sorted(cat_apps.items(), key=lambda x: -len(x[1])):
        # 该类别下主导服务商
        vend_in_cat: Counter = Counter()
        for r in scanned:
            if r["appid"] not in apps:
                continue
            for sdk in r.get("sdks") or []:
                c, v, _, _ = classify(sdk)
                if c == cat:
                    vend_in_cat[v] += 1  # sdk出现次数，下面改为 unique
        # unique apps per vendor in category
        v_unique: dict[str, set[str]] = defaultdict(set)
        for r in scanned:
            for sdk in r.get("sdks") or []:
                c, v, _, _ = classify(sdk)
                if c == cat:
                    v_unique[v].add(r["appid"])
        top_vendors = sorted(
            ((v, len(s)) for v, s in v_unique.items()), key=lambda x: -x[1]
        )[:5]
        sample_focus = "高" if cat in HIGH_CATS else ("中" if "插件" in cat or "未归类" in cat else "低")
        category_table.append(
            {
                "功能类别": cat,
                "覆盖app数": len(apps),
                "占全部样本%": round(100.0 * len(apps) / n, 2),
                "合规关注度": sample_focus,
                "主要服务商(app数)": "；".join(f"{v}:{c}" for v, c in top_vendors),
            }
        )

    vendor_table = []
    for vendor, apps in sorted(vendor_apps.items(), key=lambda x: -len(x[1])):
        top_sdks = vendor_sdk_counter[vendor].most_common(5)
        # 该 vendor 的最高合规关注
        focuses = set()
        for sdk, _ in vendor_sdk_counter[vendor].items():
            focuses.add(label_meta[sdk][2])
        focus = "高" if "高" in focuses else ("中" if "中" in focuses else "低")
        vendor_table.append(
            {
                "第三方服务商": vendor,
                "覆盖app数": len(apps),
                "占全部样本%": round(100.0 * len(apps) / n, 2),
                "占检出SDK样本%": round(
                    100.0 * len(apps) / max(1, sum(1 for r in scanned if r.get("sdks"))), 2
                ),
                "功能类别": "、".join(sorted(vendor_cats[vendor])),
                "合规关注度": focus,
                "代表SDK": "；".join(f"{k}({v})" for k, v in top_sdks),
            }
        )

    # 测绘优先：仅高关注服务商子表
    priority_vendors = [row for row in vendor_table if row["合规关注度"] == "高"]

    report = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "purpose": "小程序第三方SDK摸底：功能分类 × 服务商占比，供安全条款合规测绘",
        "sample_size": n,
        "apps_with_any_sdk": sum(1 for r in scanned if r.get("sdks")),
        "apps_with_high_compliance_sdk": len(high_compliance_apps),
        "apps_with_high_compliance_sdk_pct": round(100.0 * len(high_compliance_apps) / n, 2),
        "category_table": category_table,
        "vendor_table": vendor_table,
        "priority_vendor_table": priority_vendors,
        "method": "miniprogram_npm + plugins + config keywords；按app去重统计服务商",
        "elapsed_sec": round(time.time() - t0, 2),
        "artifacts": {
            "per_app": str(per_app_path),
            "json": str(OUT_DIR / "sdk_vendor_survey.json"),
            "csv_category": str(OUT_DIR / "sdk_category_table.csv"),
            "csv_vendor": str(OUT_DIR / "sdk_vendor_table.csv"),
            "csv_priority": str(OUT_DIR / "sdk_priority_vendors.csv"),
        },
    }

    (OUT_DIR / "sdk_vendor_survey.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    def write_csv(path: Path, rows: list[dict]) -> None:
        if not rows:
            return
        with path.open("w", encoding="utf-8-sig", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)

    write_csv(OUT_DIR / "sdk_category_table.csv", category_table)
    write_csv(OUT_DIR / "sdk_vendor_table.csv", vendor_table)
    write_csv(OUT_DIR / "sdk_priority_vendors.csv", priority_vendors)

    # 控制台摘要
    print(
        json.dumps(
            {
                "sample": n,
                "high_compliance_apps": len(high_compliance_apps),
                "categories": category_table,
                "priority_vendors_top20": priority_vendors[:20],
                "elapsed": report["elapsed_sec"],
            },
            ensure_ascii=False,
            indent=2,
        ),
        flush=True,
    )


if __name__ == "__main__":
    main()
