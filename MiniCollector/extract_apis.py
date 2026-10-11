# -*- coding: utf-8 -*-
"""
扫描 Data 目录下所有小程序源码，提取其调用的网络 API（HTTP/HTTPS 域名与路径）。

用法:
  python extract_apis.py
  python extract_apis.py --data-root F:/MiniCrest/Data
  python extract_apis.py --category 餐饮、生活消费
  python extract_apis.py --workers 12
  python extract_apis.py --limit 50          # 仅扫前 N 个小程序（调试）
  python extract_apis.py --include-static    # 不过滤图片/字体等静态资源域名

输出（默认写入 Data/_reports）:
  apis_by_app.json       每个小程序的 API 明细
  apis_summary.json      全局域名/路径汇总
  apis_by_app.csv        扁平表（便于 Excel）
  apis_domains.csv       域名出现频次
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse, urlunparse

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------

SKIP_DIRS = {
    ".mc",
    ".minicrest_staging",
    "tools",
    "tools_backup",
    "_raw",
    "_reports",
    "__pycache__",
    "node_modules",
    "miniprogram_npm",
    "__MACOSX",
    ".git",
}

# 优先扫描这些相对路径（覆盖绝大多数 API 定义位置）
# 注意：避免使用 **/ 全树递归，在大包上会极慢
PRIORITY_GLOBS = (
    "app.js",
    "app.ts",
    "app.json",
    "project.config.json",
    "project.private.config.json",
    "common/*.js",
    "common/*.ts",
    "common/vendor.js",
    "utils/*.js",
    "utils/*.ts",
    "util/*.js",
    "api/*.js",
    "api/*/*.js",
    "apis/*.js",
    "service/*.js",
    "services/*.js",
    "request/*.js",
    "config/*.js",
    "configs/*.js",
    "store/*.js",
    "lib/*.js",
    "libs/*.js",
    "helpers/*.js",
    "network/*.js",
    "http/*.js",
    "vendor.js",
    "request.js",
    "http.js",
    "api.js",
    "config.js",
    "env.js",
    "constant.js",
    "constants.js",
)

# 单应用最多检查的候选文件数
MAX_FILES_PER_APP = 400

SCAN_EXTS = {".js", ".ts", ".jsx", ".tsx", ".wxs", ".json"}

# 单文件过大则跳过（避免拖垮扫描；多数 API 会在其它文件重复出现）
MAX_FILE_BYTES = 3 * 1024 * 1024

STATIC_EXT_RE = re.compile(
    r"\.(?:png|jpe?g|gif|svg|webp|ico|bmp|css|less|scss|"
    r"ttf|otf|woff2?|eot|mp3|mp4|m4a|wav|aac|ogg|webm|"
    r"pdf|zip|rar|7z|map|wasm)(?:\?|#|$)",
    re.I,
)

# 常见非业务噪声域名（开源许可、文档站、前端框架主页等）
NOISE_DOMAINS = {
    "github.com",
    "raw.github.com",
    "raw.githubusercontent.com",
    "gitlab.com",
    "bitbucket.org",
    "npmjs.com",
    "www.npmjs.com",
    "npms.io",
    "unpkg.com",
    "jsdelivr.net",
    "cdn.jsdelivr.net",
    "lodash.com",
    "underscorejs.org",
    "vuejs.org",
    "reactjs.org",
    "angular.io",
    "jquery.com",
    "www.w3.org",
    "w3.org",
    "developer.mozilla.org",
    "mozilla.org",
    "opensource.org",
    "apache.org",
    "www.apache.org",
    "gnu.org",
    "www.gnu.org",
    "feross.org",
    "stuartk.com",
    "stuk.github.io",
    "openjsf.org",
    "creativecommons.org",
    "schemas.microsoft.com",
    "json-schema.org",
    "example.com",
    "example.org",
    "localhost",
}

NOISE_PATH_RE = re.compile(
    r"(?:/LICENSE(?:\.txt|\.md)?$|/license$|/blob/|/tree/|/commits?/|"
    r"readme\.md$|\.md$|/docs?/|/changelog)",
    re.I,
)

URL_RE = re.compile(
    r"""(?P<url>https?://[^\s"'`<>\\\)\]\},;]+)""",
    re.I,
)

# 配置项：key: "https://..."（再用 CFG_KEY_HINT 过滤）
SIMPLE_CFG_RE = re.compile(
    r"""\b(?P<key>[A-Za-z_][\w]*)\s*[:=]\s*(['"`])(?P<val>https?://[^'"`]+)\2"""
)

CFG_KEY_HINT = re.compile(
    r"(?:server|url|host|domain|api|base|endpoint|gateway|origin)",
    re.I,
)

# baseServer + "/path" / apiServer+"/xxx" / o.default.baseServer+"/auth/login"
CONCAT_PATH_RE = re.compile(
    r"""(?P<base>[A-Za-z_][\w.]*(?:Server|Url|URL|Host|baseURL|baseUrl|apiUrl|apiURL))"""
    r"""\s*\+\s*(['"`])(?P<path>/[^'"`]+)\2"""
)

# ".default.baseServer + \"/auth/login\"" 之类已由上面覆盖

APPID_IN_NAME = re.compile(r"(wx[0-9a-fA-F]{16})")


def load_config_data_root(tools_dir: Path) -> Path | None:
    cfg = tools_dir / "config.json"
    if not cfg.is_file():
        return None
    try:
        data = json.loads(cfg.read_text(encoding="utf-8"))
        root = data.get("data_root")
        if root:
            return Path(root)
    except Exception:
        pass
    return None


def find_categories(data_root: Path) -> list[Path]:
    cats = []
    for p in sorted(data_root.iterdir()):
        if not p.is_dir():
            continue
        if p.name in SKIP_DIRS or p.name.startswith("."):
            continue
        cats.append(p)
    return cats


def iter_apps(data_root: Path, category: str | None = None) -> list[tuple[str, Path]]:
    """返回 [(category_name, app_dir), ...]"""
    result: list[tuple[str, Path]] = []
    cats = find_categories(data_root)
    if category:
        cats = [c for c in cats if c.name == category]
        if not cats:
            raise SystemExit(f"未找到分类目录: {category}")
    for cat in cats:
        try:
            children = list(cat.iterdir())
        except OSError:
            continue
        for app in children:
            if app.is_dir():
                result.append((cat.name, app))
    return result


def parse_appid(app_dir: Path) -> str:
    m = APPID_IN_NAME.search(app_dir.name)
    if m:
        return m.group(1)
    # project.config.json / app.json
    for name in ("project.config.json", "project.private.config.json"):
        f = app_dir / name
        if f.is_file():
            try:
                data = json.loads(f.read_text(encoding="utf-8", errors="ignore"))
                appid = data.get("appid") or data.get("accountInfo", {}).get("appId")
                if isinstance(appid, str) and appid.startswith("wx"):
                    return appid
            except Exception:
                pass
    return ""


def clean_url(raw: str) -> str | None:
    if not raw:
        return None
    u = raw.strip().rstrip("\\")
    # 截断常见噪声尾巴
    for stop in ("\\n", "\\t", "${", "`", " "):
        if stop in u:
            u = u.split(stop, 1)[0]
    u = u.rstrip(".,;)]}'\"\\")
    if not u.lower().startswith(("http://", "https://")):
        return None
    # 过滤明显不完整
    if "://" not in u[4:]:
        # http://x 至少要有 host
        try:
            p = urlparse(u)
        except Exception:
            return None
        if not p.netloc or "." not in p.netloc and p.netloc not in ("localhost",):
            # 允许 IP
            if not re.match(r"^\d{1,3}(\.\d{1,3}){3}(:\d+)?$", p.netloc):
                if p.netloc not in ("localhost",) and not p.netloc.startswith("localhost:"):
                    return None
    return u


def is_static_asset(url: str) -> bool:
    path = urlparse(url).path or ""
    return bool(STATIC_EXT_RE.search(path))


def is_noise_url(url: str) -> bool:
    try:
        p = urlparse(url)
        host = (p.netloc or "").lower()
        if "@" in host:
            host = host.rsplit("@", 1)[-1]
        if host.startswith("www."):
            host_noscheme = host[4:]
        else:
            host_noscheme = host
        if host in NOISE_DOMAINS or host_noscheme in NOISE_DOMAINS:
            return True
        # 子域命中（如 raw.githubusercontent.com 已在集合；再兜底 *.github.io 文档站）
        if host.endswith(".github.io") or host.endswith(".github.com"):
            return True
        path = p.path or ""
        if NOISE_PATH_RE.search(path):
            return True
    except Exception:
        return False
    return False


def normalize_endpoint(url: str) -> str:
    """去掉 query/fragment，统一为 scheme://netloc/path"""
    try:
        p = urlparse(url)
        path = p.path or ""
        # 去掉尾部多余斜杠（根路径除外）
        if path.endswith("/") and len(path) > 1:
            path = path.rstrip("/")
        return urlunparse((p.scheme.lower(), p.netloc.lower(), path, "", "", ""))
    except Exception:
        return url


def extract_from_text(text: str, include_static: bool) -> tuple[set[str], list[tuple[str, str]], dict[str, str]]:
    """
    返回:
      urls: 绝对 URL 集合
      concat_pairs: [(base_var_name, /relative/path), ...]
      cfg: 配置键 -> 基址 URL
    """
    urls: set[str] = set()
    concat_pairs: list[tuple[str, str]] = []
    cfg: dict[str, str] = {}

    for m in URL_RE.finditer(text):
        u = clean_url(m.group("url"))
        if not u:
            continue
        if not include_static and is_static_asset(u):
            continue
        if is_noise_url(u):
            continue
        urls.add(normalize_endpoint(u))

    for m in SIMPLE_CFG_RE.finditer(text):
        key = m.group("key")
        if not CFG_KEY_HINT.search(key):
            continue
        u = clean_url(m.group("val"))
        if not u:
            continue
        if not include_static and is_static_asset(u):
            continue
        if is_noise_url(u):
            continue
        nu = normalize_endpoint(u)
        cfg[key] = nu
        urls.add(nu)

    for m in CONCAT_PATH_RE.finditer(text):
        path = m.group("path")
        base_var = m.group("base")
        if not path or not path.startswith("/") or len(path) >= 300:
            continue
        if not include_static and STATIC_EXT_RE.search(path):
            continue
        path = path.split("?", 1)[0].split("#", 1)[0]
        if path.endswith("/") and len(path) > 1:
            path = path.rstrip("/")
        # 取属性末段，便于匹配 config_bases 的 key（如 o.default.baseServer -> baseServer）
        leaf = base_var.rsplit(".", 1)[-1]
        concat_pairs.append((leaf, path))

    return urls, concat_pairs, cfg


def should_skip_dir(name: str) -> bool:
    if name in SKIP_DIRS or name.startswith("."):
        return True
    if name.startswith("plugin") or name.endswith("_npm"):
        return True
    return False


def iter_candidate_files(app_dir: Path) -> list[Path]:
    """收集候选源文件，避免对 pages 下每个组件做全量 walk。"""
    seen: set[str] = set()
    out: list[Path] = []

    def add(p: Path) -> None:
        try:
            key = str(p.resolve()).lower()
        except OSError:
            key = str(p).lower()
        if key in seen:
            return
        if not p.is_file():
            return
        # 跳过插件 / npm 内文件
        parts = {x.lower() for x in p.parts}
        if parts & {x.lower() for x in SKIP_DIRS}:
            return
        if any(part.startswith("plugin") or part.endswith("_npm") for part in p.parts):
            return
        seen.add(key)
        out.append(p)

    for pattern in PRIORITY_GLOBS:
        try:
            for p in app_dir.glob(pattern):
                add(p)
                if len(out) >= MAX_FILES_PER_APP:
                    return out
        except OSError:
            continue

    # 回退：若几乎没命中，再浅扫根目录与一级子目录的 js/json
    if len(out) < 3:
        try:
            for p in app_dir.iterdir():
                if p.is_file() and p.suffix.lower() in SCAN_EXTS:
                    add(p)
                elif p.is_dir() and not should_skip_dir(p.name):
                    for q in p.glob("*.js"):
                        add(q)
                        if len(out) >= 200:
                            return out
        except OSError:
            pass
    return out


def scan_app(app_dir: Path, include_static: bool = False) -> dict:
    urls: set[str] = set()
    concat_pairs: list[tuple[str, str]] = []
    cfg: dict[str, str] = {}
    files_scanned = 0
    files_skipped = 0
    errors = 0

    candidates = iter_candidate_files(app_dir)
    # 让 app.js / vendor / *api* 更靠前
    candidates.sort(
        key=lambda p: (
            0 if p.name.lower() in {"app.js", "app.ts", "app.json", "config.js", "env.js"} else 1,
            0 if any(k in p.name.lower() for k in ("vendor", "request", "api", "http", "config")) else 1,
            len(p.parts),
            p.name.lower(),
        )
    )

    for fp in candidates:
        try:
            size = fp.stat().st_size
        except OSError:
            errors += 1
            continue
        if size <= 0 or size > MAX_FILE_BYTES:
            files_skipped += 1
            continue
        try:
            raw = fp.read_bytes()
        except OSError:
            errors += 1
            continue
        if b"http" not in raw and b"Server" not in raw and b"baseURL" not in raw:
            files_scanned += 1
            continue
        try:
            text = raw.decode("utf-8", errors="ignore")
        except Exception:
            errors += 1
            continue
        files_scanned += 1
        u, pairs, c = extract_from_text(text, include_static)
        urls.update(u)
        concat_pairs.extend(pairs)
        cfg.update(c)

    composed: set[str] = set()
    rels: set[str] = set()
    for leaf, path in concat_pairs:
        rels.add(path)
        base = cfg.get(leaf)
        if base:
            composed.add(normalize_endpoint(base.rstrip("/") + path))

    domains: set[str] = set()
    for u in urls | composed:
        try:
            host = urlparse(u).netloc.lower()
            if host:
                domains.add(host)
        except Exception:
            pass

    return {
        "urls": sorted(urls),
        "composed_urls": sorted(composed),
        "relative_paths": sorted(rels),
        "config_bases": dict(sorted(cfg.items())),
        "domains": sorted(domains),
        "files_scanned": files_scanned,
        "files_skipped": files_skipped,
        "errors": errors,
    }


def _worker(payload: tuple) -> dict:
    """进程池 worker：接收可 pickle 的简单参数。"""
    cat, app_path, include_static = payload
    app_dir = Path(app_path)
    try:
        detail = scan_app(app_dir, include_static=include_static)
        status = "ok"
        err = ""
    except Exception as e:
        detail = {
            "urls": [],
            "composed_urls": [],
            "relative_paths": [],
            "config_bases": {},
            "domains": [],
            "files_scanned": 0,
            "files_skipped": 0,
            "errors": 1,
        }
        status = "error"
        err = str(e)
    return {
        "category": cat,
        "name": app_dir.name,
        "path": str(app_dir),
        "appid": parse_appid(app_dir),
        "status": status,
        "error": err,
        **detail,
    }


def write_csv(path: Path, rows: list[dict], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        for row in rows:
            w.writerow(row)


def main() -> int:
    tools_dir = Path(__file__).resolve().parent
    default_root = tools_dir.parent
    cfg_root = load_config_data_root(tools_dir)
    # 优先使用当前 Data（脚本所在上级）；config 仅在当前目录不像 Data 时兜底
    if not any((default_root / c).is_dir() for c in ("餐饮、生活消费", "交通出行、租车服务", "_reports")):
        if cfg_root and cfg_root.is_dir():
            default_root = cfg_root

    ap = argparse.ArgumentParser(description="提取 Data 下所有小程序调用的网络 API")
    ap.add_argument("--data-root", type=Path, default=default_root, help="Data 根目录")
    ap.add_argument("--out-dir", type=Path, default=None, help="报告输出目录，默认 <data-root>/_reports")
    ap.add_argument("--category", type=str, default=None, help="只扫描某个分类目录名")
    ap.add_argument("--workers", type=int, default=max(8, min(16, (os.cpu_count() or 4) * 2)))
    ap.add_argument("--limit", type=int, default=0, help="限制扫描小程序数量（0=不限制）")
    ap.add_argument("--include-static", action="store_true", help="保留图片/字体等静态资源 URL")
    ap.add_argument("--prefix", type=str, default="apis", help="输出文件名前缀")
    ap.add_argument("--serial", action="store_true", help="串行扫描（调试用）")
    args = ap.parse_args()

    data_root: Path = args.data_root
    out_dir: Path = args.out_dir or (data_root / "_reports")
    out_dir.mkdir(parents=True, exist_ok=True)

    apps = iter_apps(data_root, args.category)
    if args.limit and args.limit > 0:
        apps = apps[: args.limit]

    total = len(apps)
    workers = 1 if args.serial else max(1, args.workers)
    print(f"Data 根目录: {data_root}", flush=True)
    print(f"输出目录:   {out_dir}", flush=True)
    print(f"小程序数:   {total}", flush=True)
    print(f"并行度:     {workers}", flush=True)
    print(f"开始扫描…  {datetime.now().isoformat(timespec='seconds')}", flush=True)

    payloads = [(cat, str(app), args.include_static) for cat, app in apps]
    results: list[dict] = []
    t0 = time.time()
    done = 0

    def _on_done(row: dict) -> None:
        nonlocal done
        results.append(row)
        done += 1
        if done % 10 == 0 or done == total:
            elapsed = time.time() - t0
            rate = done / elapsed if elapsed > 0 else 0
            print(f"  进度 {done}/{total}  ({rate:.2f} app/s)", flush=True)

    if args.serial or workers == 1:
        for p in payloads:
            _on_done(_worker(p))
    else:
        # I/O 密集：线程池在 Windows 上比进程池更稳、启动更快
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futs = [ex.submit(_worker, p) for p in payloads]
            for fut in as_completed(futs):
                _on_done(fut.result())

    results.sort(key=lambda r: (r["category"], r["name"]))

    # ---- 汇总 ----
    domain_counter: Counter[str] = Counter()
    endpoint_counter: Counter[str] = Counter()
    domain_apps: dict[str, set[str]] = defaultdict(set)

    flat_rows: list[dict] = []
    for r in results:
        app_key = r.get("appid") or r["name"]
        all_eps = sorted(set(r["urls"]) | set(r["composed_urls"]))
        for d in r["domains"]:
            domain_counter[d] += 1
            domain_apps[d].add(app_key)
        for ep in all_eps:
            endpoint_counter[ep] += 1
            try:
                host = urlparse(ep).netloc.lower()
            except Exception:
                host = ""
            flat_rows.append(
                {
                    "category": r["category"],
                    "name": r["name"],
                    "appid": r["appid"],
                    "domain": host,
                    "endpoint": ep,
                    "kind": "composed" if ep in r["composed_urls"] and ep not in r["urls"] else "literal",
                }
            )

    summary = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "data_root": str(data_root),
        "app_count": total,
        "ok_count": sum(1 for r in results if r["status"] == "ok"),
        "error_count": sum(1 for r in results if r["status"] != "ok"),
        "unique_domains": len(domain_counter),
        "unique_endpoints": len(endpoint_counter),
        "top_domains": [
            {
                "domain": d,
                "app_hit_count": domain_counter[d],
                "app_count": len(domain_apps[d]),
            }
            for d, _ in domain_counter.most_common(200)
        ],
        "top_endpoints": [
            {"endpoint": e, "app_hit_count": c}
            for e, c in endpoint_counter.most_common(500)
        ],
    }

    # per-app 精简字段写 JSON
    by_app = []
    for r in results:
        by_app.append(
            {
                "category": r["category"],
                "name": r["name"],
                "appid": r["appid"],
                "path": r["path"],
                "status": r["status"],
                "error": r["error"],
                "domains": r["domains"],
                "config_bases": r["config_bases"],
                "relative_paths": r["relative_paths"],
                "endpoints": sorted(set(r["urls"]) | set(r["composed_urls"])),
                "files_scanned": r["files_scanned"],
            }
        )

    prefix = args.prefix
    by_app_path = out_dir / f"{prefix}_by_app.json"
    summary_path = out_dir / f"{prefix}_summary.json"
    csv_app_path = out_dir / f"{prefix}_by_app.csv"
    csv_domain_path = out_dir / f"{prefix}_domains.csv"

    by_app_path.write_text(json.dumps(by_app, ensure_ascii=False, indent=2), encoding="utf-8")
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    write_csv(
        csv_app_path,
        flat_rows,
        ["category", "name", "appid", "domain", "endpoint", "kind"],
    )
    domain_rows = [
        {
            "domain": d,
            "app_hit_count": domain_counter[d],
            "app_count": len(domain_apps[d]),
        }
        for d, _ in domain_counter.most_common()
    ]
    write_csv(csv_domain_path, domain_rows, ["domain", "app_hit_count", "app_count"])

    elapsed = time.time() - t0
    print()
    print("完成")
    print(f"  耗时:           {elapsed:.1f}s")
    print(f"  唯一域名:       {summary['unique_domains']}")
    print(f"  唯一 endpoint:  {summary['unique_endpoints']}")
    print(f"  明细 JSON:      {by_app_path}")
    print(f"  汇总 JSON:      {summary_path}")
    print(f"  明细 CSV:       {csv_app_path}")
    print(f"  域名 CSV:       {csv_domain_path}")
    if summary["top_domains"]:
        print("  Top 域名:")
        for item in summary["top_domains"][:15]:
            print(f"    {item['domain']}\tapps={item['app_count']}")
    return 0


if __name__ == "__main__":
    # Windows 控制台尽量用 UTF-8
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass
    raise SystemExit(main())
