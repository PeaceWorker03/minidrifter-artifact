# -*- coding: utf-8 -*-
"""
尝试用微信 URL Scheme 批量拉起小程序，以生成本地缓存。

限制（请知悉）：
1. 需要本机已登录 PC 微信
2. 明文 Scheme 可能弹系统/微信确认框，无法完全无人值守
3. 官方更稳的方式是开放平台 OpenSDK（需网站应用 + ticket + 原始ID），门槛高
4. 本脚本适合「半自动刷缓存」：自动依次拉起，你偶尔点确认即可
5. 若要按名称搜索并点击打开，改用 open_miniprograms_ui.py（UI 控件）

用法:
  python launch_miniprograms.py --from-list appids.txt
  python launch_miniprograms.py --appid wx123... --appid wx456...
  python launch_miniprograms.py --scan-packages   # 对当前缓存里已有的再打开一遍（刷新）
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
import urllib.parse
import webbrowser
from pathlib import Path

from discover import resolve_packages_roots
from pipeline import APPID_RE, find_pack_dirs, load_config

TOOLS_DIR = Path(__file__).resolve().parent


def build_scheme(appid: str, path: str = "", env: str = "release") -> str:
    # 明文 URL Scheme（微信文档公开格式）
    q = {
        "appid": appid,
        "path": path or "",
        "env_version": env,
    }
    return "weixin://dl/business/?" + urllib.parse.urlencode(q)


def launch_scheme(scheme: str) -> None:
    # Windows: os.startfile / explorer 都可触发协议
    if sys.platform.startswith("win"):
        try:
            os_start = getattr(__import__("os"), "startfile", None)
            if os_start:
                os_start(scheme)
                return
        except OSError:
            pass
        subprocess.run(["cmd", "/c", "start", "", scheme], check=False)
        return
    webbrowser.open(scheme)


def main() -> int:
    parser = argparse.ArgumentParser(description="半自动拉起微信小程序以生成缓存")
    parser.add_argument("--config", default=str(TOOLS_DIR / "config.json"))
    parser.add_argument("--appid", action="append", default=[], help="可重复传入")
    parser.add_argument("--from-list", help="每行一个 appid 的文本文件")
    parser.add_argument("--scan-packages", action="store_true", help="打开当前缓存中已有的小程序")
    parser.add_argument("--interval", type=float, default=8.0, help="两次拉起间隔秒")
    parser.add_argument("--path", default="", help="小程序启动 path")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    cfg = load_config(Path(args.config))
    appids: list[str] = []
    for a in args.appid:
        if APPID_RE.match(a):
            appids.append(a)
    if args.from_list:
        for line in Path(args.from_list).read_text(encoding="utf-8").splitlines():
            s = line.strip().split("#")[0].strip()
            if APPID_RE.match(s):
                appids.append(s)
    if args.scan_packages:
        for root in resolve_packages_roots(cfg):
            for item in find_pack_dirs(root):
                appids.append(item["appid"])

    # 去重保序
    seen = set()
    uniq = []
    for a in appids:
        if a not in seen:
            seen.add(a)
            uniq.append(a)

    if not uniq:
        print("没有可拉起的 appid。请用 --appid / --from-list / --scan-packages")
        return 1

    print(f"准备拉起 {len(uniq)} 个小程序，间隔 {args.interval}s")
    print("请保持 PC 微信已登录；若弹出确认框请点击允许。")
    for i, appid in enumerate(uniq, 1):
        scheme = build_scheme(appid, path=args.path)
        print(f"[{i}/{len(uniq)}] {appid}")
        print(f"  {scheme}")
        if not args.dry_run:
            launch_scheme(scheme)
            time.sleep(args.interval)
    print("完成。可再运行: python pipeline.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
