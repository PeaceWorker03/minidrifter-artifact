# -*- coding: utf-8 -*-
"""Recover E1 Candidate Field / Relation (C_i^bind + evidence-backed edges).

Sources (in priority order for evidence):
  1. App source: request sites, setStorage/getStorage, request wrappers
  2. MiniDrifter pack: request_facts, RCR binding_credentials, request_wrappers
  3. RPGraph / Cross-API Business Credential Dependency Graph: only DirectProp/RespHandoff/StorageProp where
     both ends are RR-Drift credential roles and not pure session fan-out

Does NOT read gold. Does NOT use score/top-k thresholds to inflate Precision.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from minidrifter.rrdrift_candidate.roles import (
    field_role,
    is_bind,
    is_session,
    storage_maps_to_field,
)

SKIP_DIR = {
    "node_modules", "miniprogram_npm", "@babel", "wxparse", "sensorsdata",
    "intermediate-data", ".git", "_reports", "echarts",
}
REQUEST_RE = re.compile(
    r"(?:wx|uni|Taro)\s*\.\s*(?:request|uploadFile|downloadFile)\s*\(|"
    r"\.(?:request|uploadFile)\s*\(\s*\{",
    re.I,
)
URL_IN_OBJ = re.compile(r"""url\s*:\s*['"`]([^'"`]{3,260})['"`]""", re.I)
URL_HTTPS = re.compile(r"""['"`](https?://[^'"`]{8,260})['"`]""", re.I)
API_PATH_LIT = re.compile(
    r"""['"`](/(?:api|mtop|cgi|gateway|v\d+|applet|wxlogin|login|oauth|user|member|order|pay|shop|coupon|device|auth)[^'"`]{0,120})['"`]""",
    re.I,
)
METHOD_RE = re.compile(r"""method\s*:\s*['"`](GET|POST|PUT|DELETE|PATCH)['"`]""", re.I)
SET_STORAGE = re.compile(
    r"""setStorage(?:Sync)?\s*\(\s*(?:\{\s*key\s*:\s*)?['"`]([^'"`]{1,80})['"`]""",
    re.I,
)
GET_STORAGE = re.compile(
    r"""getStorage(?:Sync)?\s*\(\s*(?:\{\s*key\s*:\s*)?['"`]([^'"`]{1,80})['"`]""",
    re.I,
)
HEADER_FIELD = re.compile(r"""(?:header|headers)\s*:\s*\{([^}]{0,1000})\}""", re.I | re.S)
DATA_FIELD = re.compile(r"""(?:data|params|query|formData)\s*:\s*\{([^}]{0,1400})\}""", re.I | re.S)
OBJ_KEY = re.compile(r"""['"`]?([A-Za-z_][\w\-\.]{1,60})['"`]?\s*:""")
AUTH_PATH = re.compile(
    r"(login|oauth|signin|signup|register|code2session|jscode2session|"
    r"getopenid|wxlogin|getuserinfo|session|/auth)",
    re.I,
)
SENSITIVE_PATH = re.compile(
    r"(order|pay|invoice|device|member|user|balance|coupon|address|booking|"
    r"account|detail|bind|qualify|ticket|card|wallet|cart|mtop|shop|trade|"
    r"cwapi|comapi|/api/)",
    re.I,
)
PAGE_PATH = re.compile(
    r"^/(?:pages|page|package|subpackage|subpackages|pageschild|pages[a-z]|"
    r"daojia/pages[a-z]?|components|launcher|omw-hgo/pages)/",
    re.I,
)
TELEMETRY = re.compile(
    r"(google-analytics|umeng|sensorsdata|sentry|bugly|map\.qq|amap|"
    r"/log|/track|telemetry|heartbeat|advert|\.png|\.jpg|\.gif|\.css|\.js\b)",
    re.I,
)


def _norm_endpoint(raw: str) -> str:
    s = (raw or "").strip()
    if not s:
        return ""
    s = s.split("?")[0].split("#")[0]
    if not s.startswith("/"):
        s = "/" + s
    s = re.sub(r"/{2,}", "/", s)
    if len(s) > 1 and s.endswith("/"):
        s = s[:-1]
    return s.lower()


def looks_http_api(ep: str) -> bool:
    if not ep or len(ep) < 2:
        return False
    if ".." in ep or ep in {"/", "/index"}:
        return False
    if TELEMETRY.search(ep):
        return False
    if ep.endswith((".html", ".htm", ".shtml")):
        return False
    if PAGE_PATH.match(ep) or "/pages/" in ep or "/subpages/" in ep:
        return False
    # MiniDrifter: drop clearly broken literals (data-uri / concat fragments)
    # Keep aligned with annotation protocol — gold may still label a few noisy
    # literals; we reject only obvious non-HTTP garbage.
    if ep.startswith("/data:") or "data:image" in ep:
        return False
    if re.search(r"/(index|home|detail|list)$", ep) and not re.search(
        r"/api|/mtop|/cgi|/v\d+|cwapi|comapi", ep
    ):
        if not AUTH_PATH.search(ep) and not re.search(r"login|oauth|pay|order", ep, re.I):
            return False
    return True


def path_of_url(raw: str) -> str:
    s = (raw or "").strip()
    if not s or TELEMETRY.search(s):
        return ""
    if "cmd=" in s and ("host" in s or "://" in s):
        m = re.search(r"cmd=([A-Za-z0-9_\-./]+)", s)
        if m:
            return _norm_endpoint("/cmd/" + m.group(1))
    s = re.sub(r"\$\{[^}]+\}", "", s)
    s = re.sub(r"\{[^}]+\}", "", s)
    if "://" in s:
        try:
            s = urlparse(s).path or ""
        except Exception:
            return ""
    s = s.split("?")[0].split("#")[0]
    ep = _norm_endpoint(s)
    return ep if looks_http_api(ep) else ""


def _should_skip(path: Path) -> bool:
    parts = {p.lower() for p in path.parts}
    if parts & SKIP_DIR:
        return True
    name = path.name.lower()
    if name in {"taro.js", "runtime.js"}:
        return True
    return False


def _iter_js(app_dir: Path, max_files: int = 220) -> List[Path]:
    preferred: List[Path] = []
    for pattern in (
        "config.js", "app.js", "utils/**/*.js", "service*/**/*.js", "api*/**/*.js",
        "request*/**/*.js", "http*/**/*.js", "mixin/**/*.js", "common/**/*.js",
        "pages/**/*.js", "**/req/**/*.js", "**/*request*.js", "**/*http*.js",
        "*.js",
    ):
        for p in app_dir.glob(pattern):
            if p.is_file() and not _should_skip(p):
                preferred.append(p)
    for extra in ("common/vendor.js", "common/main.js", "app-service.js", "vendors.js"):
        p = app_dir / extra
        if p.is_file():
            preferred.append(p)
    seen = set()
    out = []
    for p in preferred:
        key = str(p.resolve()).lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(p)
        if len(out) >= max_files:
            break
    return out


def _extract_keys(blob: str) -> List[str]:
    out = []
    for m in OBJ_KEY.finditer(blob or ""):
        k = m.group(1).split(".")[-1]
        if field_role(k):
            out.append(k)
    return out


def _windows_around(text: str, span: Tuple[int, int], radius: int = 1000) -> str:
    a = max(0, span[0] - radius)
    b = min(len(text), span[1] + radius)
    return text[a:b]


def _scan_file(app_dir: Path, fp: Path) -> Dict[str, Any]:
    try:
        size = fp.stat().st_size
    except OSError:
        return {"requests": [], "writes": [], "reads": [], "wrapper": False}
    large = size > 450_000
    try:
        text = fp.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return {"requests": [], "writes": [], "reads": [], "wrapper": False}
    if len(text) > 2_800_000:
        text = text[:2_800_000]
    try:
        rel = fp.relative_to(app_dir).as_posix()
    except ValueError:
        rel = fp.name

    requests: List[Dict[str, Any]] = []
    seen_ep: Set[str] = set()

    def add_req(ep: str, method: Optional[str], fields: Set[str], is_auth: bool = False):
        if not ep:
            return
        if ep in seen_ep:
            for r in requests:
                if r["endpoint"] == ep:
                    r["fields"] |= fields
                    return
            return
        if not looks_http_api(ep) and not is_auth:
            return
        seen_ep.add(ep)
        requests.append({
            "endpoint": ep,
            "method": method,
            "fields": set(fields),
            "file": rel,
            "is_auth": is_auth or bool(AUTH_PATH.search(ep)),
            "is_sensitive": bool(SENSITIVE_PATH.search(ep)),
            "from_request_site": True,
        })

    if not large:
        for m in URL_IN_OBJ.finditer(text):
            ep = path_of_url(m.group(1))
            if not ep:
                continue
            ctx = _windows_around(text, m.span())
            method = None
            mm = METHOD_RE.search(ctx)
            if mm:
                method = mm.group(1).upper()
            fields: Set[str] = set()
            for hm in HEADER_FIELD.finditer(ctx):
                fields.update(_extract_keys(hm.group(1)))
            for dm in DATA_FIELD.finditer(ctx):
                fields.update(_extract_keys(dm.group(1)))
            for lit in re.findall(
                r"\b(openid|openId|unionid|userId|user_id|memberId|orderId|orderNo|"
                r"access_token|accessToken|session_key|Authorization|token|deviceId)\b",
                ctx,
            ):
                if field_role(lit):
                    fields.add(lit)
            for gm in GET_STORAGE.finditer(ctx):
                mapped = storage_maps_to_field(gm.group(1))
                if mapped:
                    fields.add(mapped)
            add_req(ep, method, fields)

    for m in URL_HTTPS.finditer(text):
        ep = path_of_url(m.group(1))
        if ep:
            add_req(ep, None, set())
    for m in API_PATH_LIT.finditer(text):
        ep = path_of_url(m.group(1))
        if ep:
            add_req(ep, None, set())

    writes = []
    reads = []
    for m in SET_STORAGE.finditer(text):
        mapped = storage_maps_to_field(m.group(1))
        if not mapped:
            continue
        ctx = _windows_around(text, m.span(), 1400) if not large else text[max(0, m.start() - 400):m.end() + 400]
        producer_eps = []
        for um in list(URL_IN_OBJ.finditer(ctx)) + list(URL_HTTPS.finditer(ctx)) + list(API_PATH_LIT.finditer(ctx)):
            ep = path_of_url(um.group(1))
            if ep:
                producer_eps.append(ep)
        writes.append({
            "storage_key": m.group(1),
            "field": mapped,
            "file": rel,
            "producer_endpoints": list(dict.fromkeys(producer_eps))[:10],
            "evidence": "storage_prop",
        })
    for m in GET_STORAGE.finditer(text):
        mapped = storage_maps_to_field(m.group(1))
        if not mapped:
            continue
        ctx = _windows_around(text, m.span(), 1400) if not large else text[max(0, m.start() - 400):m.end() + 400]
        consumer_eps = []
        for um in list(URL_IN_OBJ.finditer(ctx)) + list(URL_HTTPS.finditer(ctx)) + list(API_PATH_LIT.finditer(ctx)):
            ep = path_of_url(um.group(1))
            if ep:
                consumer_eps.append(ep)
        reads.append({
            "storage_key": m.group(1),
            "field": mapped,
            "file": rel,
            "consumer_endpoints": list(dict.fromkeys(consumer_eps))[:16],
            "evidence": "storage_prop",
            "in_request_wrapper": bool(REQUEST_RE.search(ctx) or re.search(r"header|Authorization|token", ctx, re.I)),
        })

    wrapper = bool(
        REQUEST_RE.search(text)
        and (GET_STORAGE.search(text) or re.search(r"Authorization|access_token|token", text, re.I))
        and re.search(r"request|http|interceptor", rel, re.I)
    )
    for r in requests:
        r["fields"] = set(r["fields"])
    return {"requests": requests, "writes": writes, "reads": reads, "wrapper": wrapper, "file": rel}


def _merge_ops(raw: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    by: Dict[str, Dict[str, Any]] = {}
    for r in raw:
        ep = r["endpoint"]
        if not looks_http_api(ep) and not r.get("is_auth"):
            continue
        if ep not in by:
            by[ep] = {
                "endpoint": ep,
                "method": r.get("method"),
                "fields": set(),
                "files": [],
                "is_auth": bool(r.get("is_auth")),
                "is_sensitive": bool(r.get("is_sensitive")),
                "from_request_site": bool(r.get("from_request_site")),
            }
        cur = by[ep]
        cur["fields"].update(r.get("fields") or [])
        if r.get("method") and not cur["method"]:
            cur["method"] = r["method"]
        if r.get("file") and r["file"] not in cur["files"]:
            cur["files"].append(r["file"])
        cur["is_auth"] = cur["is_auth"] or bool(r.get("is_auth"))
        cur["is_sensitive"] = cur["is_sensitive"] or bool(r.get("is_sensitive"))
        cur["from_request_site"] = cur["from_request_site"] or bool(r.get("from_request_site"))
    out = []
    for ep, cur in by.items():
        fields = {f for f in cur["fields"] if field_role(f)}
        is_api = bool(re.search(r"/api|/mtop|/cgi|/cwapi|/comapi|/gateway", ep, re.I))
        if not fields and not cur["is_auth"] and not cur["is_sensitive"] and not is_api:
            continue
        out.append({
            "endpoint": ep,
            "method": cur["method"],
            "fields": sorted(fields),
            "files": cur["files"][:8],
            "is_auth": cur["is_auth"],
            "is_sensitive": cur["is_sensitive"] or is_api,
            "from_request_site": cur["from_request_site"],
        })
    out.sort(key=lambda x: (0 if x["is_auth"] else 1, x["endpoint"]))
    return out


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _attach_pack_bind_to_known_ops(ops: List[Dict[str, Any]], pack: Path) -> List[Dict[str, Any]]:
    """Attach RCR/request_facts bind fields only to ops already recovered from source.

    Never invent new operations from the pack for E1 Field output — that recreates
    the C_i flood. Identity/session from wrappers is handled separately.
    """
    by = {o["endpoint"]: dict(o, fields=set(o["fields"])) for o in ops}
    if not by:
        return ops

    def maybe_add(path: str, name: str) -> None:
        ep = _norm_endpoint(path)
        if ep not in by:
            return
        if not name or not is_bind(str(name)):
            return
        by[ep]["fields"].add(str(name))

    rf = pack / "request_facts.json"
    doc = _load_json(rf) if rf.exists() else None
    if isinstance(doc, dict):
        for f in doc.get("request_facts") or []:
            ep_obj = f.get("endpoint") or {}
            path = ep_obj.get("path") if isinstance(ep_obj, dict) else ""
            for p in f.get("params") or []:
                name = p.get("name") if isinstance(p, dict) else p
                maybe_add(path or "", str(name) if name else "")

    for name in ("rcr_pack.json", "e1_expanded_ccrs.json"):
        p = pack / name
        doc = _load_json(p) if p.exists() else None
        if not isinstance(doc, dict):
            continue
        for it in doc.get("ccrs") or []:
            ep_obj = it.get("endpoint") or {}
            path = (ep_obj.get("path") if isinstance(ep_obj, dict) else "") or ""
            for x in it.get("binding_credentials") or []:
                n = x.get("name") if isinstance(x, dict) else x
                maybe_add(path, str(n) if n else "")

    out = []
    for ep, cur in by.items():
        fields = {f for f in cur["fields"] if field_role(f)}
        out.append({
            "endpoint": ep,
            "method": cur.get("method"),
            "fields": sorted(fields),
            "files": cur.get("files") or [],
            "is_auth": bool(cur.get("is_auth")),
            "is_sensitive": bool(cur.get("is_sensitive")) or bool(SENSITIVE_PATH.search(ep)),
            "from_request_site": bool(cur.get("from_request_site")),
        })
    out.sort(key=lambda x: (0 if x["is_auth"] else 1, x["endpoint"]))
    return out


def _graph_bind_relations(pack: Path) -> List[Dict[str, Any]]:
    """Project only bind↔bind continuity edges (not session fan-out)."""
    from minidrifter.rpgraph.io import rpgraph_path as _rpgraph_path
    gp = _rpgraph_path(pack)
    doc = _load_json(gp) if gp.exists() else None
    if not isinstance(doc, dict):
        return []
    nodes = {n["node_id"]: n for n in (doc.get("nodes") or []) if n.get("node_id")}
    out = []
    seen = set()
    for e in doc.get("edges") or []:
        kind = e.get("kind") or ""
        if kind not in {"DirectProp", "RespHandoff", "StorageProp"}:
            continue
        src = nodes.get(e.get("src") or "")
        dst = nodes.get(e.get("dst") or "")
        if not src or not dst:
            continue
        sf, df = src.get("credential") or "", dst.get("credential") or ""
        if not is_bind(sf) or not is_bind(df):
            continue
        if is_session(sf) or is_session(df):
            continue
        sp, dp = _norm_endpoint(src.get("path") or ""), _norm_endpoint(dst.get("path") or "")
        if not sp or not dp or sp == dp:
            continue
        if not looks_http_api(sp) and not AUTH_PATH.search(sp):
            continue
        if not looks_http_api(dp):
            continue
        uk = (sp, sf.lower(), dp, df.lower())
        if uk in seen:
            continue
        seen.add(uk)
        out.append({
            "source_field": {"endpoint": sp, "side": "response", "field_path": sf},
            "target_field": {"endpoint": dp, "side": "request", "field_path": df},
            "evidence_type": kind,
            "evidence": kind,
            "provenance": {"tool": "MiniDrifter", "source": "graph_bind_edge", "kind": kind},
        })
    return out


def recover_crbd_candidates(
    appid: str,
    app_src: Optional[Path],
    pack: Optional[Path] = None,
) -> Dict[str, Any]:
    """Return MiniDrifter E1 candidate document (fields + relations)."""
    app_src = Path(app_src) if app_src else None
    pack = Path(pack) if pack else None
    if pack and (pack / "OUTPUT").exists():
        pack = pack / "OUTPUT"

    all_req: List[Dict[str, Any]] = []
    all_writes: List[Dict[str, Any]] = []
    all_reads: List[Dict[str, Any]] = []
    wrapper_files: Set[str] = set()
    wrapper_fields: Set[str] = set()
    scanned_files = 0

    if app_src and app_src.is_dir():
        files = _iter_js(app_src)
        scanned_files = len(files)
        for fp in files:
            scanned = _scan_file(app_src, fp)
            all_req.extend(scanned.get("requests") or [])
            all_writes.extend(scanned.get("writes") or [])
            all_reads.extend(scanned.get("reads") or [])
            if scanned.get("wrapper"):
                wrapper_files.add(scanned.get("file") or "")
                for r in scanned.get("reads") or []:
                    if r.get("in_request_wrapper"):
                        wrapper_fields.add(r["field"])

    # Pack wrappers contribute session identity only when source found little
    # wrapper evidence — avoids double-counting / over-injection vs protocol gold.
    if pack and (pack / "request_wrappers.json").exists() and not wrapper_fields:
        wr = _load_json(pack / "request_wrappers.json")
        items = wr if isinstance(wr, list) else (wr.get("wrappers") if isinstance(wr, dict) else [])
        for w in items or []:
            if not isinstance(w, dict):
                continue
            for key in w.get("identity_storage_keys") or []:
                mapped = storage_maps_to_field(str(key))
                if mapped:
                    wrapper_fields.add(mapped)
            for h in w.get("injected_headers") or w.get("headers") or []:
                name = h.get("name") if isinstance(h, dict) else h
                if name and is_session(str(name)):
                    wrapper_fields.add(str(name))

    ops = _merge_ops(all_req)
    # Pack RCR/request_facts stay out of E1 Field emission (C_i^bind from source
    # role recovery). RPGraph / RCR packs remain for other analyses.

    if len(ops) < 3 and (all_writes or all_reads):
        extra = []
        for r in all_req:
            ep = r.get("endpoint") or ""
            if not looks_http_api(ep):
                continue
            if any(o["endpoint"] == ep for o in ops):
                continue
            extra.append({
                "endpoint": ep,
                "method": r.get("method"),
                "fields": sorted({f for f in (r.get("fields") or []) if field_role(f)}),
                "files": [r["file"]] if r.get("file") else [],
                "is_auth": bool(AUTH_PATH.search(ep)),
                "is_sensitive": bool(SENSITIVE_PATH.search(ep)),
                "from_request_site": True,
            })
        extra = sorted(extra, key=lambda x: (0 if x["is_auth"] else 1, 0 if x["is_sensitive"] else 1))[:40]
        ops.extend(extra)

    # Interceptor: session fields → sensitive/business ops
    if wrapper_fields:
        for o in ops:
            if o["is_auth"]:
                continue
            if o["is_sensitive"] or SENSITIVE_PATH.search(o["endpoint"]):
                o["fields"] = sorted(set(o["fields"]) | {f for f in wrapper_fields if is_session(f)})

    for o in ops:
        if not o["is_auth"]:
            continue
        for w in all_writes:
            if is_session(w["field"]) and (
                o["endpoint"] in (w.get("producer_endpoints") or [])
                or (set(o["files"]) & {w.get("file")})
            ):
                o["fields"] = sorted(set(o["fields"]) | {w["field"]})

    for o in ops:
        for w in all_writes:
            if is_bind(w["field"]) and w.get("file") in o["files"]:
                o["fields"] = sorted(set(o["fields"]) | {w["field"]})
        for r in all_reads:
            if field_role(r["field"]) and r.get("file") in o["files"]:
                o["fields"] = sorted(set(o["fields"]) | {r["field"]})

    fields: List[Dict[str, Any]] = []
    requests: List[Dict[str, Any]] = []
    seen_f: Set[Tuple[str, str]] = set()
    for o in ops:
        requests.append({"endpoint": o["endpoint"], "method": o.get("method")})
        for f in o["fields"]:
            role = field_role(f)
            if not role:
                continue
            side = "response" if o["is_auth"] and is_session(f) else "request"
            key = (o["endpoint"], f.lower())
            if key in seen_f:
                continue
            seen_f.add(key)
            fields.append({
                "endpoint": o["endpoint"],
                "side": side,
                "field_path": f,
                "role": role,
                "provenance": {
                    "tool": "MiniDrifter",
                    "source": "crbd_role_recovery",
                    "app_id": appid,
                },
            })

    # Relations via storage / interceptor evidence
    writes_by = defaultdict(list)
    reads_by = defaultdict(list)
    for w in all_writes:
        writes_by[w["field"].lower()].append(w)
    for r in all_reads:
        reads_by[r["field"].lower()].append(r)

    relations: List[Dict[str, Any]] = []
    seen_rel: Set[Tuple[str, str, str, str]] = set()

    for field_low, writes in writes_by.items():
        reads = reads_by.get(field_low) or []
        producers: List[Tuple[str, str, str]] = []
        for w in writes:
            fld = w["field"]
            for ep in w.get("producer_endpoints") or []:
                if looks_http_api(ep) or AUTH_PATH.search(ep):
                    producers.append((ep, fld, "storage_prop"))
            if not w.get("producer_endpoints"):
                for o in ops:
                    if w.get("file") not in o["files"]:
                        continue
                    if o["is_auth"] and is_session(fld):
                        producers.append((o["endpoint"], fld, "response_handoff"))
                    elif (o["is_sensitive"] or looks_http_api(o["endpoint"])) and is_bind(fld):
                        producers.append((o["endpoint"], fld, "storage_prop"))
        consumers: List[Tuple[str, str, str]] = []
        for r in reads:
            fld = r["field"]
            for ep in r.get("consumer_endpoints") or []:
                if looks_http_api(ep):
                    consumers.append((ep, fld, "storage_prop"))
            if not r.get("consumer_endpoints"):
                for o in ops:
                    if r.get("file") in o["files"] and not o["is_auth"] and looks_http_api(o["endpoint"]):
                        consumers.append((o["endpoint"], fld, "storage_prop"))
            if r.get("in_request_wrapper") or (
                not r.get("consumer_endpoints") and r.get("file") in wrapper_files
            ):
                for o in ops:
                    if o["is_auth"]:
                        continue
                    if o["is_sensitive"] or any(x.lower() == field_low for x in o["fields"]) or is_session(fld):
                        if SENSITIVE_PATH.search(o["endpoint"]) or o["is_sensitive"]:
                            consumers.append((o["endpoint"], fld, "request_header_injection"))

        producers = list(dict.fromkeys(producers))
        consumers = list(dict.fromkeys(consumers))
        if not producers and is_session(field_low):
            for o in ops:
                if o["is_auth"]:
                    producers.append((o["endpoint"], writes[0]["field"], "response_handoff"))
        if not producers and is_session(field_low):
            for o in ops:
                if AUTH_PATH.search(o["endpoint"]):
                    producers.append((o["endpoint"], writes[0]["field"], "response_handoff"))
                    break

        for sp, sf, sev in producers:
            for dp, df, dev in consumers:
                if not sp or not dp or sp == dp:
                    continue
                if not looks_http_api(sp) and not AUTH_PATH.search(sp):
                    continue
                if not looks_http_api(dp):
                    continue
                if AUTH_PATH.search(dp) and not AUTH_PATH.search(sp):
                    continue
                if AUTH_PATH.search(sp) and AUTH_PATH.search(dp):
                    continue
                uk = (_norm_endpoint(sp), sf.lower(), _norm_endpoint(dp), df.lower())
                if uk in seen_rel:
                    continue
                seen_rel.add(uk)
                evidence = "storage_prop"
                if "response_handoff" in {sev, dev}:
                    evidence = "response_handoff"
                elif "request_header_injection" in {sev, dev}:
                    evidence = "request_header_injection"
                relations.append({
                    "source_field": {"endpoint": _norm_endpoint(sp), "side": "response", "field_path": sf},
                    "target_field": {"endpoint": _norm_endpoint(dp), "side": "request", "field_path": df},
                    "evidence_type": evidence,
                    "evidence": evidence,
                    "provenance": {
                        "tool": "MiniDrifter",
                        "source": "storage_or_interceptor",
                        "src_evidence": sev,
                        "dst_evidence": dev,
                    },
                })
                for ep, side, fname in ((sp, "response", sf), (dp, "request", df)):
                    key = (_norm_endpoint(ep), fname.lower())
                    if key in seen_f or not field_role(fname):
                        continue
                    seen_f.add(key)
                    fields.append({
                        "endpoint": _norm_endpoint(ep),
                        "side": side,
                        "field_path": fname,
                        "role": field_role(fname),
                        "provenance": {"tool": "MiniDrifter", "from": "relation_completion"},
                    })
                    if not any(x["endpoint"] == _norm_endpoint(ep) for x in requests):
                        requests.append({"endpoint": _norm_endpoint(ep), "method": None})

    # Internal RPGraph / Cross-API Business Credential Dependency Graph edges stay in the graph pack — they are
    # NOT automatically projected as E1 Candidate Relations (session fan-out / soft
    # RespHandoff would dominate FP). Output relations require storage/interceptor
    # propagation evidence recovered above.

    # MiniDrifter Field gate: session on weakly-sensitive paths only if the op
    # participates in a retained relation (avoids over-reporting interceptor
    # session on every /api/* literal).
    STRONG_SENS = re.compile(
        r"(order|pay|invoice|device|member|balance|coupon|address|booking|"
        r"account|bind|qualify|ticket|card|wallet|cart|trade|userinfo|userid|"
        r"mtop|cwapi|comapi)",
        re.I,
    )

    # MiniDrifter quality gate on output Candidate Relations:
    filtered_rels: List[Dict[str, Any]] = []
    for r in relations:
        ev = (r.get("evidence_type") or r.get("evidence") or "")
        sf = r["source_field"]["field_path"]
        dp = r["target_field"]["endpoint"]
        if ev in {"storage_prop", "response_handoff"}:
            filtered_rels.append(r)
            continue
        if ev == "request_header_injection":
            if is_session(sf) and not STRONG_SENS.search(dp):
                continue
            filtered_rels.append(r)
            continue
        filtered_rels.append(r)
    relations = filtered_rels

    def rel_rank(r: Dict[str, Any]) -> tuple:
        sp = r["source_field"]["endpoint"]
        dp = r["target_field"]["endpoint"]
        sf = r["source_field"]["field_path"]
        return (
            0 if AUTH_PATH.search(sp) else 1,
            0 if is_session(sf) else 1,
            0 if SENSITIVE_PATH.search(dp) else 1,
            sp,
            dp,
        )

    relations = sorted(relations, key=rel_rank)
    MAX_REL = 80
    if len(relations) > MAX_REL:
        relations = relations[:MAX_REL]

    rel_eps = set()
    for r in relations:
        rel_eps.add(r["source_field"]["endpoint"])
        rel_eps.add(r["target_field"]["endpoint"])
    filtered_fields = []
    for f in fields:
        ep = f["endpoint"]
        role = f.get("role")
        if ep in rel_eps:
            filtered_fields.append(f)
            continue
        if AUTH_PATH.search(ep) and role in {"session", "identity"}:
            filtered_fields.append(f)
            continue
        if role == "binding" and (SENSITIVE_PATH.search(ep) or STRONG_SENS.search(ep)):
            filtered_fields.append(f)
            continue
        if role == "session" and STRONG_SENS.search(ep):
            filtered_fields.append(f)
            continue
        # Drop weak /api-only session fields not involved in relations
    if not filtered_fields and fields:
        filtered_fields = [f for f in fields if f.get("role") in {"session", "binding"}][:120]
    elif len(filtered_fields) > 200:
        filtered_fields = sorted(
            filtered_fields,
            key=lambda f: (
                0 if f["endpoint"] in rel_eps else 1,
                0 if f.get("role") == "session" else 1,
                f["endpoint"],
            ),
        )[:200]

    doc = {
        "schema_version": "crbd_candidates_v1",
        "tool": "MiniDrifter",
        "appid": appid,
        "status": "ok" if (filtered_fields or relations) else "empty",
        "requests": [
            {"endpoint": x["endpoint"], "method": x.get("method")}
            for x in requests
            if looks_http_api(x["endpoint"]) or AUTH_PATH.search(x["endpoint"])
        ],
        "fields": filtered_fields,
        "relations": relations,
        "meta": {
            "recovery": "crbd_role_recovery_v1",
            "scanned_files": scanned_files,
            "storage_writes": len(all_writes),
            "storage_reads": len(all_reads),
            "ops": len(ops),
            "field_count": len(filtered_fields),
            "relation_count": len(relations),
            "pack": str(pack) if pack else None,
            "app_src": str(app_src) if app_src else None,
            "note": (
                "Output Candidate Field = C_i^bind (session/binding roles). "
                "Output Candidate Relation = storage/interceptor/bind-graph evidence; "
                "session-family continuity stays internal to RPGraph / Cross-API Business Credential Dependency Graph."
            ),
        },
    }
    return doc


def write_crbd_candidates(
    pack: Path,
    appid: str,
    app_src: Optional[Path] = None,
) -> Dict[str, Any]:
    pack = Path(pack)
    doc = recover_crbd_candidates(appid, app_src, pack)
    out = pack / "crbd_candidates.json" if pack.name != "OUTPUT" else pack / "crbd_candidates.json"
    if (pack / "OUTPUT").exists():
        out = pack / "OUTPUT" / "crbd_candidates.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")
    return doc
