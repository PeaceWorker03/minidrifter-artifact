# -*- coding: utf-8 -*-
"""Sensitive workflow recovery and drift planning (target-directed binding slices)."""
from __future__ import annotations

import re
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple

from minidrifter.rpgraph.schema import (
    AUTH_BOOTSTRAP_RE,
    PATH_CONTEXT_CRED,
    SENSITIVE_PATH_RE,
    credential_set,
    field_aliases,
    is_business_bind_field,
    is_sensitive_ccr,
)


def canonicalize_credential(name: str) -> str:
    """Early canonical key for (op, bind_cred) targets."""
    n = str(name or "").strip()
    if not n or n.startswith("__"):
        return ""
    # drop common wrappers
    n = re.sub(r"^(data|payload|body|params|result)\.", "", n, flags=re.I)
    n = n.split(".")[-1]
    snake = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", n).lower()
    snake = snake.replace("-", "_")
    # member_info_id → member_id soft normalize
    snake = re.sub(r"_info_", "_", snake)
    snake = re.sub(r"_+", "_", snake).strip("_")
    # accidentid / orderid → accident_id / order_id (unify with AccidentId)
    if "_" not in snake:
        snake = re.sub(r"([a-z0-9])(id|no|code)$", r"\1_\2", snake)
    return snake


def _is_identity_or_session(name: str) -> bool:
    cl = (name or "").lower()
    if cl in {
        "token", "accesstoken", "access_token", "openid", "unionid",
        "sessionkey", "session_key", "authorization", "auth", "session",
    }:
        return True
    if re.fullmatch(r"(user_?id|userid|uid)", cl):
        return True
    return False


def _has_binding_use(RCR: Dict[str, Any], cred: str) -> bool:
    bind = [str(x) for x in (RCR.get("binding_credentials") or [])]
    if any(canonicalize_credential(x) == canonicalize_credential(cred) for x in bind):
        return True
    # request_semantics credentials with business-bind name count as use
    rs = RCR.get("request_semantics") or {}
    for c in rs.get("credentials") or []:
        n = c if isinstance(c, str) else (c.get("name") if isinstance(c, dict) else "")
        if canonicalize_credential(str(n)) == canonicalize_credential(cred):
            return True
    return False


def _has_continuity_support(cred: str, nodes: List[Dict[str, Any]], edges: List[Dict[str, Any]]) -> bool:
    """Fallback: credential appears on ≥1 continuity edge (named, not resource_ctx)."""
    canon = canonicalize_credential(cred)
    if not canon:
        return False
    named = {
        n["node_id"]
        for n in nodes
        if canonicalize_credential(n.get("credential") or "") == canon
    }
    for e in edges:
        if e.get("src") in named or e.get("dst") in named:
            kind = e.get("kind") or ""
            if kind in {"DirectProp", "RespHandoff"}:
                # reject pure path_context handoff noise when both ends are resource_ctx
                ev = e.get("evidence") or {}
                fields = ev.get("fields") or ev.get("credential_match") or []
                if fields and all(str(x).startswith("__") for x in fields):
                    continue
                return True
    return False


def _adj(edges: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    g: Dict[str, List[str]] = defaultdict(list)
    for e in edges:
        g[e["src"]].append(e["dst"])
    return g


def _rev_adj(edges: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    g: Dict[str, List[str]] = defaultdict(list)
    for e in edges:
        g[e["dst"]].append(e["src"])
    return g


def _ancestors(rev: Dict[str, List[str]], target: str) -> Set[str]:
    seen: Set[str] = set()
    stack = [target]
    while stack:
        cur = stack.pop()
        if cur in seen:
            continue
        seen.add(cur)
        for p in rev.get(cur) or []:
            if p not in seen:
                stack.append(p)
    return seen


def _descendants(fwd: Dict[str, List[str]], start: str) -> Set[str]:
    seen: Set[str] = set()
    stack = [start]
    while stack:
        cur = stack.pop()
        if cur in seen:
            continue
        seen.add(cur)
        for n in fwd.get(cur) or []:
            if n not in seen:
                stack.append(n)
    return seen


def _reachable(fwd: Dict[str, List[str]], start: str, goal: str) -> bool:
    if start == goal:
        return True
    seen: Set[str] = set()
    stack = [start]
    while stack:
        cur = stack.pop()
        if cur == goal:
            return True
        if cur in seen:
            continue
        seen.add(cur)
        stack.extend(fwd.get(cur) or [])
    return False


def _is_business_operation(RCR: Dict[str, Any], path: str) -> bool:
    try:
        from minidrifter.optimizers.url_utils import is_engine_noise_path, is_frontend_route_path
        if is_frontend_route_path(path) or is_engine_noise_path(path):
            return False
    except Exception:
        pass
    if re.search(r"\.(js|css|png|jpe?g|svg|html?)(\?|$)", path or "", re.I):
        return False
    if AUTH_BOOTSTRAP_RE.search(path) and not is_sensitive_ccr(RCR):
        return False
    if re.search(r"(report|log|track|telemetry|analytics|heartbeat|advert)", path, re.I):
        return False
    # sensitive path OR has bind credentials ⇒ business-relevant op for targeting
    if SENSITIVE_PATH_RE.search(path):
        return True
    if RCR.get("binding_credentials"):
        return True
    creds = (RCR.get("request_semantics") or {}).get("credentials") or []
    return any(is_business_bind_field(str(c if isinstance(c, str) else (c.get("name") or ""))) for c in creds)


def select_targets(
    ccrs: List[Dict[str, Any]],
    nodes: List[Dict[str, Any]],
    edges: Optional[List[Dict[str, Any]]] = None,
    *,
    limit: int = 80,
) -> List[Dict[str, Any]]:
    """Select RR-Drift targets as (op, canonical_bind_cred), not every sensitive node."""
    by_oid = {c.get("operation_id"): c for c in ccrs}
    edges = edges or []
    by_op: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for node in nodes:
        by_op[node.get("operation_id") or ""].append(node)

    strong_list: List[Dict[str, Any]] = []
    fallback_list: List[Dict[str, Any]] = []
    seen_keys: Set[Tuple[str, str]] = set()

    for oid, op_nodes in by_op.items():
        if not oid:
            continue
        RCR = by_oid.get(oid) or {}
        path = ((RCR.get("endpoint") or {}).get("path") or (op_nodes[0].get("path") if op_nodes else "") or "")
        if not _is_business_operation(RCR, path):
            continue

        creds: List[str] = []
        # Prefer explicit binding_credentials
        for c in RCR.get("binding_credentials") or []:
            creds.append(str(c))
        if not creds:
            for n in op_nodes:
                c = n.get("credential") or ""
                if c and c != PATH_CONTEXT_CRED and not str(c).startswith("__"):
                    creds.append(c)
            for c in credential_set(RCR, allow_path_context=False):
                if c and c != PATH_CONTEXT_CRED:
                    creds.append(c)

        op_strong: List[Dict[str, Any]] = []
        op_fallback: List[Dict[str, Any]] = []

        for cred in creds:
            canon = canonicalize_credential(cred)
            if not canon:
                continue
            if cred == PATH_CONTEXT_CRED:
                continue
            # Session tokens never targets; subject ids (userId/loginId) allowed on
            # auth/realname/gov paths where they are the resource handle.
            if _is_identity_or_session(cred) or _is_identity_or_session(canon):
                if not re.search(
                    r"(alipay|mzt|idcard|realname|auth/|login|register|face)",
                    path,
                    re.I,
                ):
                    continue
                if re.fullmatch(r"(token|access_?token|session|authorization|openid)", str(cred), re.I):
                    continue
            # Require business-bind shape (subject ids on auth paths qualify via role)
            if not is_business_bind_field(cred) and not re.search(
                r"(userid|loginid|idcard)", str(cred), re.I
            ):
                continue

            in_bind_list = any(
                canonicalize_credential(str(x)) == canon for x in (RCR.get("binding_credentials") or [])
            )
            strong = (in_bind_list or _has_binding_use(RCR, cred)) and not _is_identity_or_session(cred)
            # Stricter: name length / not generic
            if canon in {"id", "code", "no", "name", "type", "data", "list"}:
                continue
            if len(canon) < 4:
                continue

            fallback = (
                not strong
                and _has_continuity_support(cred, nodes, edges)
                and not _is_identity_or_session(cred)
            )
            if not (strong or fallback):
                continue

            key = (oid, canon)
            if key in seen_keys:
                continue
            seen_keys.add(key)

            node = None
            for n in op_nodes:
                if canonicalize_credential(n.get("credential") or "") == canon:
                    node = n
                    break
            if node is None:
                node = {
                    "node_id": f"{oid}::{cred}",
                    "operation_id": oid,
                    "credential": cred,
                    "path": path,
                    "scope": (op_nodes[0].get("scope") if op_nodes else None),
                }

            score = 3.0 if in_bind_list else (2.0 if strong else 1.0)
            if SENSITIVE_PATH_RE.search(path):
                score += 1.0
            if re.search(r"(detail|pay|bind|upload|verify|order|create)", path, re.I):
                score += 1.0

            item = {
                "target_node_id": node.get("node_id") or f"{oid}::{cred}",
                "operation_id": oid,
                "credential": cred,
                "canonical_credential": canon,
                "path": path,
                "score": score,
                "strong": bool(strong or in_bind_list),
            }
            if strong or in_bind_list:
                op_strong.append(item)
            elif fallback:
                op_fallback.append(item)

        # Path-context singleton targets (§5.2.3): sensitive business ops with no
        # named bind field still form W_t = {target} ∪ auth/init closure.
        if not op_strong and not op_fallback:
            sens = bool(is_sensitive_ccr(RCR) or SENSITIVE_PATH_RE.search(path))
            if sens and re.search(
                r"(order|pay|invoice|member|user|account|coupon|address|booking|"
                r"cert|rent|register|realname|detail|bind|upload|verify|device|"
                r"rescue|accident|bank|qualify|tenant|express|mail|parcel)",
                path,
                re.I,
            ):
                node = None
                for n in op_nodes:
                    if (n.get("credential") or "") == PATH_CONTEXT_CRED or str(
                        n.get("credential") or ""
                    ).startswith("__"):
                        node = n
                        break
                if node is None and op_nodes:
                    node = op_nodes[0]
                if node is not None:
                    key = (oid, "__resource_ctx__")
                    if key not in seen_keys:
                        seen_keys.add(key)
                        op_strong.append({
                            "target_node_id": node.get("node_id") or f"{oid}::{PATH_CONTEXT_CRED}",
                            "operation_id": oid,
                            "credential": PATH_CONTEXT_CRED,
                            "canonical_credential": "__resource_ctx__",
                            "path": path,
                            "score": 2.5,
                            "strong": True,
                        })

        # One primary φ_i target per op keeps the workflow budget diverse.
        op_strong.sort(key=lambda x: (-x["score"], x["canonical_credential"]))
        strong_list.extend(op_strong[:1])
        # Fallback only when this op has no strong targets
        if not op_strong:
            op_fallback.sort(key=lambda x: -x["score"])
            fallback_list.extend(op_fallback[:1])

    candidates = strong_list + fallback_list
    candidates.sort(key=lambda x: (-x["score"], x["path"], x["canonical_credential"]))
    return candidates[:limit]


def _valid_continuity_edge(e: Dict[str, Any]) -> bool:
    kind = e.get("kind") or ""
    if kind not in {"DirectProp", "RespHandoff"}:
        return False
    # Drop pure resource_ctx ↔ resource_ctx soft handoffs from slice dependency
    src_f = (e.get("src") or "").partition("::")[2]
    dst_f = (e.get("dst") or "").partition("::")[2]
    if src_f.startswith("__") and dst_f.startswith("__"):
        return False
    return True


def _backward_slice(target_node_id: str, edges: List[Dict[str, Any]]) -> Tuple[Set[str], List[Dict[str, Any]]]:
    rev_edges: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for e in edges:
        if not _valid_continuity_edge(e):
            continue
        rev_edges[e["dst"]].append(e)

    visited: Set[str] = set()
    selected: List[Dict[str, Any]] = []
    work = [target_node_id]
    while work:
        node = work.pop()
        if node in visited:
            continue
        visited.add(node)
        for e in rev_edges.get(node) or []:
            selected.append(e)
            src = e["src"]
            if src not in visited:
                work.append(src)
    return visited, selected


def _workflow_edge_keyset(selected_edges: List[Dict[str, Any]], node_by_id: Dict[str, Any]) -> frozenset:
    keys = []
    for e in selected_edges:
        sn = node_by_id.get(e["src"]) or {}
        dn = node_by_id.get(e["dst"]) or {}
        sc = canonicalize_credential(sn.get("credential") or e["src"].partition("::")[2])
        dc = canonicalize_credential(dn.get("credential") or e["dst"].partition("::")[2])
        sp = (sn.get("path") or "").lower()
        dp = (dn.get("path") or "").lower()
        keys.append((sp, sc, dp, dc, e.get("kind") or ""))
    return frozenset(keys)


def _dominance_prune(workflows: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], int]:
    """Drop supersets with same target and binding edge set containment."""
    # Group by (target_op, canonical_cred)
    groups: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
    for w in workflows:
        t = w.get("target") or {}
        key = (t.get("operation_id") or "", canonicalize_credential(t.get("credential") or ""))
        groups[key].append(w)

    kept: List[Dict[str, Any]] = []
    dropped = 0
    for _, group in groups.items():
        # Sort by |edges| ascending — prefer smaller
        group = sorted(group, key=lambda w: len(w.get("_edge_keys") or frozenset()))
        winners: List[Dict[str, Any]] = []
        for w in group:
            ek = w.get("_edge_keys") or frozenset()
            dominated = False
            for other in winners:
                ok = other.get("_edge_keys") or frozenset()
                # if other ⊂ w (strict) and same target → drop w
                if ok and ek and ok < ek:
                    dominated = True
                    break
                # identical → drop duplicate
                if ok == ek:
                    dominated = True
                    break
            if dominated:
                dropped += 1
                continue
            winners.append(w)
        kept.extend(winners)
    return kept, dropped


def recover_workflows(
    graph: Dict[str, Any],
    ccrs: List[Dict[str, Any]],
    *,
    max_workflows: int = 120,
) -> Dict[str, Any]:
    nodes = graph.get("nodes") or []
    edges = graph.get("edges") or []
    fwd = _adj(edges)
    rev = _rev_adj(edges)
    by_oid = {c.get("operation_id"): c for c in ccrs}
    node_by_id = {n["node_id"]: n for n in nodes}
    op_scope = (graph.get("identity_scopes") or {}).get("operation_scope") or {}

    scope_exec: Dict[str, List[str]] = defaultdict(list)
    for RCR in ccrs:
        oid = RCR.get("operation_id")
        path = ((RCR.get("endpoint") or {}).get("path") or "")
        if AUTH_BOOTSTRAP_RE.search(path):
            scope_exec[op_scope.get(oid) or "⊥"].append(oid)

    # Cap targets near max_workflows — avoid 2× inflation that hits truncation
    targets = select_targets(ccrs, nodes, edges, limit=min(80, max(max_workflows, 40)))
    workflows: List[Dict[str, Any]] = []
    zero_edge_dropped = 0
    seen_canon: Set[Tuple[str, str, frozenset]] = set()

    for t in targets:
        tid = t["target_node_id"]
        # Ensure target node exists in graph; else try alias node ids
        if tid not in node_by_id:
            # find any node with same op+canonical cred
            for n in nodes:
                if n.get("operation_id") == t["operation_id"] and canonicalize_credential(
                    n.get("credential") or ""
                ) == t.get("canonical_credential"):
                    tid = n["node_id"]
                    t["target_node_id"] = tid
                    break
        if tid not in node_by_id:
            continue

        s_bind, selected_edges = _backward_slice(tid, edges)
        # Paper §5.2.3: when no upstream continuity edges exist, still keep a
        # target-directed workflow = {target} ∪ auth/init closure under SameScope.
        # Dropping these zeros out sensitive_workflow/drift metrics on wrapper-heavy apps.
        singleton_fallback = False
        if not selected_edges:
            if t.get("strong"):
                s_bind = {tid}
                selected_edges = []
                singleton_fallback = True
            else:
                zero_edge_dropped += 1
                continue

        edge_keys = _workflow_edge_keyset(selected_edges, node_by_id)
        canon_key = (
            t["operation_id"],
            t.get("canonical_credential") or canonicalize_credential(t.get("credential") or ""),
            edge_keys if edge_keys else frozenset({("singleton", tid)}),
        )
        if canon_key in seen_canon:
            continue
        seen_canon.add(canon_key)

        bind_ops = {node_by_id[n]["operation_id"] for n in s_bind if n in node_by_id}
        sc = node_by_id[tid].get("scope") or op_scope.get(t["operation_id"]) or "⊥"
        r_exec = sorted(set(scope_exec.get(sc) or []) | set(bind_ops))
        ops = sorted(set(bind_ops) | set(r_exec))

        prec_pairs = []
        pair_set = {
            (p["pred"], p["succ"])
            for p in ((graph.get("precedence") or {}).get("pairs") or [])
        }
        for a in ops:
            for b in ops:
                if a != b and (a, b) in pair_set:
                    prec_pairs.append({"pred": a, "succ": b})

        workflows.append({
            "workflow_id": f"wf:{tid}",
            "target": t,
            "binding_slice_nodes": sorted(s_bind),
            "binding_slice_operations": sorted(bind_ops),
            "execution_closure_operations": r_exec,
            "operations": ops,
            "precedence": prec_pairs,
            "scope": sc,
            "slice_edge_count": len(selected_edges),
            "singleton_fallback": singleton_fallback,
            "_edge_keys": edge_keys if edge_keys else frozenset({("singleton", tid)}),
        })

    workflows, dominated_dropped = _dominance_prune(workflows)
    # strip internal keys
    for w in workflows:
        w.pop("_edge_keys", None)

    truncated = False
    if len(workflows) > max_workflows:
        workflows = workflows[:max_workflows]
        truncated = True

    return {
        "workflow_count": len(workflows),
        "target_count": len(targets),
        "workflows": workflows,
        "zero_edge_dropped": zero_edge_dropped,
        "dominated_dropped": dominated_dropped,
        "workflow_truncated": truncated,
    }


def plan_drifts(workflows: Dict[str, Any], graph: Dict[str, Any]) -> Dict[str, Any]:
    edges = graph.get("edges") or []
    fwd = _adj(edges)
    rev = _rev_adj(edges)
    plans = []
    for wf in workflows.get("workflows") or []:
        tid = (wf.get("target") or {}).get("target_node_id")
        if not tid:
            continue
        s_bind = set(wf.get("binding_slice_nodes") or [])
        for s in sorted(s_bind):
            if s == tid:
                continue
            desc = _descendants(fwd, s) & s_bind
            d_nodes = {v for v in desc if _reachable(fwd, v, tid) or v == tid}
            d_nodes.add(s)
            if tid not in d_nodes and not _reachable(fwd, s, tid):
                if s in _ancestors(rev, tid):
                    d_nodes = {s, tid}
                else:
                    continue
            plans.append({
                "plan_id": f"plan:{s}->{tid}",
                "workflow_id": wf.get("workflow_id"),
                "drift_source": s,
                "target": tid,
                "dependent_nodes": sorted(d_nodes),
                "mutate_only": s,
                "identity_scope": wf.get("scope"),
                "execution_closure_operations": wf.get("execution_closure_operations") or [],
            })
    return {
        "drift_plan_count": len(plans),
        "drift_plans": plans,
    }
