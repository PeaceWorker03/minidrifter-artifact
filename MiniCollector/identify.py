# -*- coding: utf-8 -*-
"""小程序实名识别：权威字段优先，拒绝泛化页标题。"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib import error, request

# 导航栏常见泛词：不能当官方名
GENERIC_TITLES = {
    "点餐",
    "首页",
    "我的",
    "订单",
    "设置",
    "登录",
    "取消",
    "确定",
    "返回",
    "加载中",
    "提交",
    "搜索",
    "详情",
    "分享",
    "客服",
    "会员",
    "购物车",
    "支付",
    "优惠券",
    "地址",
    "消息",
    "发现",
    "附近",
    "扫码",
    "扫一扫",
    "微餐饮",
    "加载中...",
    "请稍后",
}

APPID_RE = re.compile(r"^wx[0-9a-fA-F]{16}$")


def _http_post_json(url: str, payload: dict[str, Any], timeout: float = 10.0) -> dict[str, Any]:
    data = json.dumps(payload).encode("utf-8")
    req = request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) MiniCrest/1.0",
            "Accept": "application/json",
        },
        method="POST",
    )
    with request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", errors="ignore"))


def fetch_remote_info(appid: str, api: str, timeout: float = 10.0) -> dict[str, Any]:
    if not appid or not APPID_RE.fullmatch(appid) or not api:
        return {}
    try:
        resp = _http_post_json(api, {"appid": appid}, timeout=timeout)
        if isinstance(resp, dict) and resp.get("code") == 0 and isinstance(resp.get("data"), dict):
            return resp["data"]
    except (error.URLError, error.HTTPError, TimeoutError, json.JSONDecodeError, OSError):
        return {}
    return {}


def _read_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        try:
            return json.loads(path.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError):
            return {}


def _is_codeish_name(name: str) -> bool:
    """工程/构建名，如 cyq-build、vipskcxyxf，不能当展示名。"""
    s = name.strip()
    if re.fullmatch(r"[A-Za-z0-9._\-]+", s) and not re.search(r"[\u4e00-\u9fff]", s):
        return True
    return False


def _is_good_name(name: Any, appid: str = "") -> bool:
    if not isinstance(name, str):
        return False
    name = name.strip()
    if not name or len(name) > 40:
        return False
    if APPID_RE.fullmatch(name) or name == appid:
        return False
    if name in GENERIC_TITLES:
        return False
    if len(name) <= 1:
        return False
    if _is_codeish_name(name):
        return False
    return True


def _name_score_bonus(name: str) -> int:
    """含中文的品牌名加分。"""
    return 20 if re.search(r"[\u4e00-\u9fff]", name) else 0


def _pick_ext_name(ext: dict[str, Any], appid: str) -> str | None:
    """第三方/门店小程序常把官方名写在 ext.appname。"""
    if not isinstance(ext, dict):
        return None
    for key in (
        "appname",
        "appName",
        "brandName",
        "brand_name",
        "shopName",
        "shop_name",
        "merchantName",
        "merchant_name",
        "nickName",
        "nickname",
        "name",
        "title",
    ):
        val = ext.get(key)
        if _is_good_name(val, appid):
            return str(val).strip()
    return None


def infer_from_output(output_dir: Path, appid: str = "") -> dict[str, Any]:
    """
    本地权威度大致为:
    1) app-config.json / app.json 的 ext.appname（第三方平台注入的品牌名）
    2) accountInfo.nickname
    3) projectname（非泛词）
    4) navigationBarTitleText（仅非泛词时采用）
    """
    info: dict[str, Any] = {"candidates": []}

    def add(source: str, name: str, score: int) -> None:
        if _is_good_name(name, appid):
            info["candidates"].append(
                {
                    "source": source,
                    "name": name.strip(),
                    "score": score + _name_score_bonus(name.strip()),
                }
            )

    target_names = (
        "app-config.json",
        "app.json",
        "project.config.json",
        "project.private.config.json",
    )
    first_by_name: dict[str, Path] = {}
    all_app_configs: list[Path] = []
    seen_paths: set[str] = set()

    for name in target_names:
        p = output_dir / name
        if p.is_file():
            first_by_name[name] = p

    # 单次遍历同时建立常见配置索引，避免按文件名重复 rglob 整棵目录树。
    for p in output_dir.rglob("*"):
        if not p.is_file() or p.name not in target_names:
            continue
        try:
            key = str(p.resolve()).lower()
        except OSError:
            key = str(p).lower()
        if key in seen_paths:
            continue
        seen_paths.add(key)
        first_by_name.setdefault(p.name, p)
        if p.name == "app-config.json":
            all_app_configs.append(p)

    files = [first_by_name[name] for name in target_names if name in first_by_name]

    for p in files:
        data = _read_json(p)
        if not data:
            continue

        ext = data.get("ext")
        if isinstance(ext, dict):
            n = _pick_ext_name(ext, appid)
            if n:
                add(f"{p.name}:ext.appname", n, 100)
            if ext.get("appid") and not appid:
                info.setdefault("appid", ext.get("appid"))

        acc = data.get("accountInfo")
        if isinstance(acc, dict):
            if _is_good_name(acc.get("nickname"), appid):
                add(f"{p.name}:accountInfo.nickname", str(acc["nickname"]).strip(), 90)
            info.setdefault("appid", acc.get("appId") or acc.get("appid"))

        if _is_good_name(data.get("projectname"), appid):
            # 工程名可信度低于 ext.appname；纯英文构建名已被 _is_good_name 过滤
            add(f"{p.name}:projectname", str(data["projectname"]).strip(), 55)

        title = (data.get("window") or {}).get("navigationBarTitleText")
        if _is_good_name(title, appid):
            add(f"{p.name}:navigationBarTitleText", str(title).strip(), 40)

        for key in ("appid", "extAppid"):
            if data.get(key):
                info.setdefault("appid", data.get(key))

    # 再扫一遍常见配置里的 ext（有的在子包）
    primary_keys = {str(p.resolve()).lower() for p in files}
    for p in all_app_configs:
        if str(p.resolve()).lower() in primary_keys:
            continue
        data = _read_json(p)
        n = _pick_ext_name(data.get("ext") or {}, appid)
        if n:
            add(f"{p.relative_to(output_dir)}:ext", n, 95)

    cands = sorted(info.get("candidates") or [], key=lambda x: (-x["score"], -len(x["name"])))
    if cands:
        info["nickname"] = cands[0]["name"]
        info["nickname_source"] = cands[0]["source"]
    info["candidates"] = cands[:8]
    return {k: v for k, v in info.items() if v}


def sanitize_dirname(name: str, fallback: str) -> str:
    name = (name or "").strip() or fallback
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", name)
    name = re.sub(r"\s+", " ", name).strip(" .")
    return (name[:80] or fallback)


def folder_name_for(nickname: str, appid: str) -> str:
    """官方名_appid；若无可靠名则只用 appid，避免 appid_appid。"""
    appid = appid or "unknown"
    if _is_good_name(nickname, appid) and nickname != appid:
        return sanitize_dirname(f"{nickname}_{appid}", appid)
    return sanitize_dirname(appid, "unknown")


def identify_miniprogram(
    appid: str,
    output_dir: str | Path | None = None,
    api: str = "https://kainy.cn/api/weapp/info/",
    remote_timeout: float = 10.0,
    skip_remote_when_local_named: bool = False,
) -> dict[str, Any]:
    local = infer_from_output(Path(output_dir), appid=appid) if output_dir else {}
    local_named = _is_good_name(local.get("nickname"), appid)
    remote = (
        {}
        if skip_remote_when_local_named and local_named
        else fetch_remote_info(appid, api, timeout=remote_timeout)
    )

    nickname = None
    source = "appid"
    if _is_good_name(remote.get("nickname"), appid):
        nickname = str(remote["nickname"]).strip()
        source = "remote"
    elif _is_good_name(local.get("nickname"), appid):
        nickname = str(local["nickname"]).strip()
        source = local.get("nickname_source") or "local"
    else:
        nickname = appid

    description = remote.get("description") or remote.get("signature") or ""
    return {
        "appid": appid or local.get("appid") or "",
        "nickname": nickname,
        "description": description,
        "source": source,
        "raw_remote": remote,
        "raw_local": local,
        "safe_name": sanitize_dirname(str(nickname), appid or "unknown"),
        "folder_name": folder_name_for(str(nickname), appid or "unknown"),
    }
