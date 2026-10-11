# -*- coding: utf-8 -*-
"""行业粗分分类器：按 9 类行业加权打分（昵称权重更高）。"""

from __future__ import annotations

import json
import math
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

# 与 E:\MiniCrest 既有目录名保持一致
CATEGORIES: list[str] = [
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

DEFAULT_CATEGORY = "政务、缴费及其他服务"

# (pattern, weight, tag) — 昵称命中会再乘 NAME_BOOST
NAME_BOOST = 3.0

SIGNAL_RULES: dict[str, list[tuple[str, float, str]]] = {
    "餐饮、生活消费": [
        (r"餐饮|外卖|点餐|美食|奶茶|咖啡|火锅|烧烤|小吃|食堂|餐厅|饭店|饮品|甜品|烘焙|生鲜到家", 5.0, "food"),
        (r"美团|饿了么|肯德基|麦当劳|星巴克|喜茶|瑞幸|海底捞", 6.0, "food_brand"),
        (r"menu|外卖单|堂食|取餐|菜品|套餐", 3.0, "food_biz"),
    ],
    "房产与生活服务": [
        (r"房产|楼盘|二手房|租房|装修|物业|家政|保洁|搬家|家政服务|生活服务|房产中介", 5.0, "life"),
        (r"贝壳|链家|安居客|58同城|闲鱼|到家", 5.5, "life_brand"),
        (r"房源|带看|物业费|报修|家政预约", 3.5, "life_biz"),
    ],
    "交通出行、租车服务": [
        (r"打车|出行|租车|网约车|公交|地铁|高铁|火车|机票|航旅|停车|加油|充电桩|骑行|单车", 5.5, "travel"),
        (r"滴滴|一嗨|T3|曹操|高德打车|哈啰|青桔|飞猪|携程机票", 6.0, "travel_brand"),
        (r"行程|司机|车牌|还车|取车|运力|导航", 3.5, "travel_biz"),
    ],
    "景区、票务与预约": [
        (r"景区|门票|票务|预约参观|文旅|博物馆|动物园|游乐园|演出票|电影票|场馆预约", 5.5, "ticket"),
        (r"购票|入园|预约入场|展览|演唱会|剧院", 4.0, "ticket_biz"),
        (r"美团票务|大麦|猫眼", 5.0, "ticket_brand"),
    ],
    "企业与办公服务": [
        (r"企业|办公|OA|审批|报销|考勤|人事|CRM|进销存|合同|发票|税务|企业微信|钉钉", 5.0, "office"),
        (r"商户管理|员工端|工作台|协同办公|企微", 4.0, "office_biz"),
        (r"用友|金蝶|纷享销客|北森", 5.0, "office_brand"),
    ],
    "商城与零售": [
        (r"商城|零售|购物|电商|超市|便利店|旗舰店|拼团|秒杀|购物车|商品详情|店铺", 5.0, "retail"),
        (r"京东|天猫|淘宝|拼多多|唯品会|苏宁|盒马|永辉|Apple.*店", 6.0, "retail_brand"),
        (r"sku|加购|确认订单|物流|售后|优惠券商城", 3.5, "retail_biz"),
    ],
    "校园与教育": [
        (r"校园|学校|教育|培训|课程|题库|考试|教务|选课|成绩|家校|留学|网课|学堂|校园生活", 5.5, "edu"),
        (r"大学|中学|小学|幼儿园|驾校|考研|软考|四六级|智慧校园", 4.5, "edu_biz"),
        (r"学习通|超星|猿辅导|作业帮", 5.5, "edu_brand"),
    ],
    "医疗与健康服务": [
        (r"医院|医疗|健康|挂号|问诊|药房|药品|体检|核酸|疫苗|口腔|眼科|医美|养生", 5.5, "med"),
        (r"丁香|好大夫|微医|平安好医生|药店|处方", 6.0, "med_brand"),
        (r"患者|医生|科室|病历|预约挂号|互联网医院", 4.0, "med_biz"),
    ],
    "政务、缴费及其他服务": [
        (r"政务|社保|公积金|户籍|公安|税务局|不动产登记|公积金|市民|一网通办", 5.5, "gov"),
        (r"缴费|话费|电费|水费|燃气|宽带|中国电信|移动|联通|营业厅", 5.0, "utility"),
        (r"银行|保险|证券|征信|政务服务", 3.5, "finance_gov"),
    ],
}

SKIP_DIR_RE = re.compile(
    r"(?:^|[\\/])(miniprogram_npm|node_modules|@vant|@babel|__MACOSX|OUTPUT)(?:[\\/])",
    re.I,
)
CODE_EXTS = {".js", ".json", ".wxml", ".wxss", ".wxs", ".ts"}
COMPILED_SIGNAL_RULES = {
    cat: [(re.compile(pattern, re.I), weight, tag) for pattern, weight, tag in rules]
    for cat, rules in SIGNAL_RULES.items()
}


def _safe_read(path: Path, max_bytes: int = 300_000) -> str:
    try:
        with path.open("rb") as fh:
            data = fh.read(max_bytes)
        for enc in ("utf-8", "utf-8-sig", "gbk"):
            try:
                return data.decode(enc)
            except UnicodeDecodeError as exc:
                # 限长读取可能恰好截断 UTF-8 多字节字符；只忽略末尾残片。
                if enc in {"utf-8", "utf-8-sig"} and exc.start >= len(data) - 4:
                    return data.decode(enc, errors="ignore")
                continue
        return data.decode("utf-8", errors="ignore")
    except OSError:
        return ""


def collect_corpus(
    app_dir: Path,
    max_files: int = 250,
    max_total_bytes: int = 8_000_000,
) -> tuple[str, dict[str, Any]]:
    meta: dict[str, Any] = {}
    chunks: list[str] = []
    seen: set[str] = set()
    remaining = max(1, int(max_total_bytes))
    app_json = app_dir / "app.json"
    if app_json.exists():
        read_limit = min(300_000, remaining)
        raw = _safe_read(app_json, read_limit)
        chunks.append(raw)
        try:
            remaining -= min(read_limit, app_json.stat().st_size)
        except OSError:
            remaining -= read_limit
        try:
            seen.add(str(app_json.resolve()).lower())
        except OSError:
            seen.add(str(app_json).lower())
        try:
            meta = json.loads(raw)
        except json.JSONDecodeError:
            meta = {}

    count = 0
    for p in app_dir.rglob("*"):
        if remaining <= 0:
            break
        if not p.is_file() or p.suffix.lower() not in CODE_EXTS:
            continue
        if SKIP_DIR_RE.search(str(p)):
            continue
        try:
            key = str(p.resolve()).lower()
        except OSError:
            key = str(p).lower()
        if key in seen:
            continue
        seen.add(key)
        read_limit = min(300_000, remaining)
        raw = _safe_read(p, read_limit)
        chunks.append(raw)
        try:
            remaining -= min(read_limit, p.stat().st_size)
        except OSError:
            remaining -= read_limit
        count += 1
        if count >= max_files:
            break
    return "\n".join(chunks), meta


def _count_hits(text: str, pattern: re.Pattern[str], limit: int = 1000) -> int:
    count = 0
    for _ in pattern.finditer(text):
        count += 1
        if count >= limit:
            break
    return count


def score_categories(
    text: str,
    nickname: str = "",
    description: str = "",
) -> tuple[dict[str, float], dict[str, list[str]]]:
    scores: dict[str, float] = {k: 0.0 for k in CATEGORIES}
    evidence: dict[str, list[str]] = defaultdict(list)
    name_blob = f"{nickname} {description}"

    for cat, rules in COMPILED_SIGNAL_RULES.items():
        for pattern, weight, tag in rules:
            name_hits = _count_hits(name_blob, pattern)
            if name_hits:
                contrib = weight * NAME_BOOST * (1.0 + math.log1p(name_hits))
                scores[cat] += contrib
                evidence[cat].append(f"name:{tag}×{name_hits}")

            body_hits = _count_hits(text, pattern)
            if body_hits:
                contrib = weight * (1.0 + math.log1p(body_hits))
                scores[cat] += contrib
                if len(evidence[cat]) < 8:
                    evidence[cat].append(f"code:{tag}×{body_hits}")

    return scores, evidence


def normalize_scores(scores: dict[str, float]) -> dict[str, float]:
    total = sum(max(0.0, v) for v in scores.values())
    if total <= 1e-9:
        return {k: 0.0 for k in scores}
    return {k: max(0.0, v) / total for k, v in scores.items()}


def classify_app(
    app_dir: str | Path,
    nickname: str = "",
    appid: str = "",
    description: str = "",
    confidence_threshold: float = 0.22,
    ambiguity_gap: float = 0.06,
    max_total_bytes: int = 8_000_000,
) -> dict[str, Any]:
    """粗分到 9 个行业类；信号极弱时归入「政务、缴费及其他服务」。"""
    root = Path(app_dir)
    text, _meta = collect_corpus(root, max_total_bytes=max_total_bytes)
    # 导航标题也并入昵称侧信号
    title = ""
    if isinstance(_meta, dict):
        title = str((_meta.get("window") or {}).get("navigationBarTitleText") or "")
    scores, evidence = score_categories(
        text,
        nickname=f"{nickname} {title}",
        description=description,
    )
    probs = normalize_scores(scores)
    ranked = sorted(probs.items(), key=lambda x: x[1], reverse=True)
    primary, conf = ranked[0]
    second, second_conf = ranked[1] if len(ranked) > 1 else ("", 0.0)

    if sum(scores.values()) < 2.0:
        primary, conf = DEFAULT_CATEGORY, 0.15
        reason = "weak_fallback_other"
    elif conf < confidence_threshold:
        reason = "low_confidence"
    elif conf - second_conf < ambiguity_gap:
        reason = "ambiguous_top2"
    else:
        reason = "ok"

    return {
        "primary": primary,
        "primary_name": primary,
        "confidence": round(conf, 4),
        "secondary": second,
        "secondary_confidence": round(second_conf, 4),
        "scores": {k: round(v, 3) for k, v in scores.items()},
        "probs": {k: round(v, 4) for k, v in probs.items()},
        "evidence": dict(evidence),
        "status": reason,
        "nickname": nickname,
        "appid": appid,
        "app_dir": str(root),
    }
