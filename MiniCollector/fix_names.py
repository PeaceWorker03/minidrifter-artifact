# -*- coding: utf-8 -*-
"""根据 _raw 重新实名，并重命名已归档目录（修正 点餐_xxx / appid_appid）。"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from classify import CATEGORIES
from identify import folder_name_for, identify_miniprogram

DATA = Path(__file__).resolve().parents[1]
RAW = DATA / "_raw"
APPID_RE = re.compile(r"(wx[0-9a-fA-F]{16})")


def main() -> int:
    cfg_api = ""
    cfg_path = Path(__file__).with_name("config.json")
    if cfg_path.exists():
        cfg_api = json.loads(cfg_path.read_text(encoding="utf-8")).get("identify_api") or ""

    renamed = 0
    for cat in CATEGORIES:
        root = DATA / cat
        if not root.exists():
            continue
        for p in list(root.iterdir()):
            if not p.is_dir():
                continue
            m = APPID_RE.search(p.name)
            if not m:
                continue
            appid = m.group(1)
            raw = RAW / appid
            if not raw.exists():
                continue
            identity = identify_miniprogram(appid, raw, api=cfg_api)
            new_name = identity.get("folder_name") or folder_name_for(identity["nickname"], appid)
            dest = root / new_name
            if dest.resolve() == p.resolve():
                continue
            if dest.exists():
                print(f"[跳过] 目标已存在: {dest.name}")
                continue
            print(f"[重命名] {p.name} -> {new_name}  ({identity['source']})")
            p.rename(dest)
            meta = dest / "_minicrest_classify.json"
            if meta.exists():
                try:
                    data = json.loads(meta.read_text(encoding="utf-8"))
                    data["nickname"] = identity["nickname"]
                    data["identify_source"] = identity["source"]
                    data["folder_name"] = new_name
                    meta.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
                except (OSError, json.JSONDecodeError):
                    pass
            renamed += 1
    print(f"完成，重命名 {renamed} 个")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
