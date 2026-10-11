# -*- coding: utf-8 -*-
"""Chain Composer: 自动拼接多步利用链（静态+动态反馈闭环）。

核心能力：
1. 从 RPGraph / Cross-API Business Credential Dependency Graph + HAR 中提取「认证→换 token→读敏感数据」链
2. 自动识别可组合的「跳板接口」（如 getAccessToken → personalCenter/get）
3. 生成可执行的 PoC 步骤序列
4. 与 Feedback Engine 集成：执行结果反哺下一轮链优化
"""
from __future__ import annotations

import json
import re
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from minidrifter.core.utils import write_json
from minidrifter.runtime_trace.feedback_alts import attach_step_feedback_metadata
from minidrifter.optimizers.url_utils import (
    is_chain_business_path,
    is_frontend_route_path,
    is_json_rpc_path,
)

SCHEMA_VERSION = '1.0.0'

_ENVELOPE_KEYS = frozenset({
    'code', 'msg', 'status', 'message', 'errorcode', 'issuccess',
    'operationid', 'extraproperties',
})
_HANDOFF_SKIP = frozenset({
    'result', 'data', 'channelid', 'orderid', 'bycityid', 'lastorderid',
    'token', 'authorization', 'appidentity',
})
_WRITE_PATH_RE = re.compile(r'unbind|un-bind|delete|putoff|puton|save|modify|remove', re.I)
# 身份类交接：房源 owner 字段常与 userId 同指
_IDENTITY_ALIASES = {
    'adduser': frozenset({'userid', 'uid', 'memberid', 'openid'}),
    'userid': frozenset({'adduser', 'uid', 'memberid', 'openid', 'personid'}),
    'memberid': frozenset({'userid', 'uid', 'adduser'}),
    'uid': frozenset({'userid', 'adduser', 'memberid'}),
}
_IDENTITY_HANDOFF_FIELDS = frozenset({
    'unionid', 'bindid', 'titleid', 'title', 'openid', 'phonenumber', 'phone', 'mobile',
    'userid', 'memberid', 'houseid', 'adduser', 'uid', 'personid',
})


def _expand_identity_aliases(fields: Set[str]) -> Set[str]:
    out = {str(x).lower() for x in fields}
    for f in list(out):
        out |= set(_IDENTITY_ALIASES.get(f, ()))
    return out


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _load_json(path: Path) -> Any:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding='utf-8'))


def _walk_json_field_names(obj: Any, acc: Set[str], depth: int = 0) -> None:
    """Collect nested JSON keys, skipping transport envelope names."""
    if depth > 6 or obj is None:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            kl = str(k).lower()
            if kl not in _ENVELOPE_KEYS and kl not in ('result', 'data'):
                acc.add(str(k))
            _walk_json_field_names(v, acc, depth + 1)
    elif isinstance(obj, list) and obj:
        _walk_json_field_names(obj[0], acc, depth + 1)


# Resource stems → canonical φ_i field (path-shape inference, app-agnostic).
_PATH_RESOURCE_STEMS = {
    'order': 'orderId', 'orders': 'orderId', 'orderdetail': 'orderId', 'orderdtail': 'orderId',
    'address': 'addressId', 'addressinfo': 'addressId',
    'account': 'accountId', 'user': 'userId', 'member': 'memberId',
    'device': 'deviceId', 'invoice': 'invoiceId', 'booking': 'bookingId',
    'coupon': 'couponId', 'accident': 'accidentId', 'rescue': 'rescueId',
    'bank': 'bankId', 'qualify': 'qualifyId', 'qualification': 'qualificationId',
    'customer': 'customerId', 'proof': 'proofId', 'house': 'houseId',
    'title': 'titleId', 'bind': 'bindId', 'tenant': 'tenantId',
    'rent': 'rentId', 'pay': 'payId', 'payment': 'paymentId',
    'bike': 'bikeId', 'bikeno': 'bikeNo', 'cinema': 'cinemaId',
    'card': 'cardId', 'goods': 'goodsId', 'movie': 'movieId',
    'express': 'expressId', 'parcel': 'parcelId', 'mail': 'mailId',
}
_PATH_ACTION_LEAVES = {
    'detail', 'info', 'get', 'query', 'submit', 'delete', 'upload', 'verify',
    'update', 'save', 'create', 'add', 'list', 'recommend', 'auth', 'unbind',
    'bind', 'register', 'remove', 'edit', 'modify', 'search',
}
_PATH_GENERIC_SEGS = {
    'wechat', 'api', 'v1', 'v2', 'v3', 'mini', 'app', 'wx', 'page', 'pages',
    'list', 'common', 'public', 'service', 'services', 'gateway',
}


def infer_binding_fields_from_path(path: str) -> List[str]:
    """Infer client-bound fields from the URL (ByTitle → title, Title/Detail → titleId)."""
    if not path:
        return []
    p = path.strip().rstrip('/')
    low = p.lower()
    # Never invent φ_i from engine/bundler/page noise paths.
    try:
        from minidrifter.optimizers.url_utils import is_engine_noise_path, is_frontend_route_path
        if is_engine_noise_path(p) or is_frontend_route_path(p):
            return []
    except Exception:
        pass
    out: List[str] = []

    def add(*names: str) -> None:
        for n in names:
            if n and n not in out:
                out.append(n)

    def add_resource(field: str) -> None:
        """Emit one canonical camelCase φ_i name (avoid AccidentId/accidentid duplicates)."""
        if field:
            add(field)

    # OpenAPI / 路由模板 {houseId} → houseId
    for m in re.finditer(r'\{([^/}]+)\}', path):
        raw = (m.group(1) or '').strip()
        if not raw:
            continue
        add(raw[0].lower() + raw[1:] if raw and raw[0].isupper() else raw)

    m = re.search(r'/by([a-z][a-z0-9]*)$', low)
    if m:
        raw = m.group(1)
        if raw == 'userid':
            add('userId')
        elif raw == 'title':
            add('title')
        elif raw == 'openid':
            add('openId')
        else:
            add(raw)

    parts = [x for x in low.split('/') if x]
    # Compound segment only: OrderDetail / AddressInfo → resource φ (not bare /Accident/)
    for part in parts:
        for stem, field in _PATH_RESOURCE_STEMS.items():
            if part == stem:
                continue
            if part.startswith(stem) and len(part) > len(stem):
                suffix = part[len(stem):]
                if suffix in _PATH_ACTION_LEAVES or suffix.endswith(('detail', 'info', 'list', 'submit')):
                    add_resource(field)
                    break

    # Parent-of-action: .../Account/Detail → accountId (incl. account/user parents)
    if len(parts) >= 2:
        leaf = parts[-1]
        leaf_is_action = leaf in _PATH_ACTION_LEAVES or any(
            leaf.endswith(s) for s in ('detail', 'info', 'submit', 'list', 'query')
        )
        if leaf_is_action:
            parent = parts[-2]
            if parent == 'title':
                add('titleId', 'title')
            elif parent in ('mysecondhandhouse', 'secondhandhouse', 'house'):
                add('houseId')
            elif parent in _PATH_RESOURCE_STEMS:
                add_resource(_PATH_RESOURCE_STEMS[parent])
            elif (
                parent not in _PATH_GENERIC_SEGS
                and 3 <= len(parent) <= 24
                and '-' not in parent
                and '_' not in parent
                and parent.isalpha()
            ):
                add(parent + 'Id')
            # Walk further back past generics (AddedService/OrderDetail/Accessory/Recommend)
            for seg in reversed(parts[:-1]):
                if seg in _PATH_GENERIC_SEGS or seg in _PATH_ACTION_LEAVES:
                    continue
                if seg in _PATH_RESOURCE_STEMS:
                    add_resource(_PATH_RESOURCE_STEMS[seg])
                    break
                matched = False
                for stem, field in _PATH_RESOURCE_STEMS.items():
                    if seg.startswith(stem) and len(seg) > len(stem):
                        add_resource(field)
                        matched = True
                        break
                if matched:
                    break

    if 'phonenumber' in low and 'unionid' in low:
        add('unionId')
    if parts and 'unbind' in parts[-1]:
        add('bindId')
    # 神州等 form+q 加密：账号读接口业务侧绑定字段常是 memberId（不一定出现在明文 form）
    if re.search(r'personaldata|getuserinfo|getmemberinfo|personal/?info', low):
        add('memberId', 'renterId')
    # 红城等：改资料 / 人脸核验 / 房源详情
    if re.search(r'updatememberinfo|/member/update', low):
        add('memberId', 'linkName')
    if re.search(r'verifiedstatus|face/verified', low):
        add('userId')
    if re.search(r'(my)?secondhandhouse.*/detail|house.*/detail', low):
        add('houseId')
    return out


# ─── 链节点类型 ───
NODE_AUTH_BOOTSTRAP = 'auth_bootstrap'      # 登录/换 token 接口
NODE_IDENTITY_EXTRACT = 'identity_extract'    # 提取 userId/openid 的接口
NODE_SENSITIVE_READ = 'sensitive_read'        # 读敏感数据
NODE_SENSITIVE_WRITE = 'sensitive_write'      # 写敏感数据
NODE_ENUMERATION = 'enumeration'              # 枚举/oracle 接口
NODE_RELAY = 'relay'                          # 纯转发/中继
NODE_CRBD_CANDIDATE = 'crbd_candidate'        # RR-Drift 候选：接受客户端传入用户标识


class ChainNode:
    __slots__ = ('node_id', 'operation_id', 'path', 'method', 'node_type',
                 'consumes', 'produces', 'sensitive_score', 'requires_auth',
                 'auth_bypass', 'crbd_driftable', 'drift_fields', 'evidence', 'metadata',
                 'identity_anchor', 'business_credentials', 'binding_credentials',
                 'provenance', 'materialization_alternatives')

    def __init__(self, node_id: str, operation_id: str, path: str, method: str = 'GET'):
        self.node_id = node_id
        self.operation_id = operation_id
        self.path = path
        self.method = method
        self.node_type = NODE_RELAY
        self.consumes: Set[str] = set()      # 该节点消费的字段
        self.produces: Set[str] = set()      # 该节点产生的字段
        self.sensitive_score = 0.0
        self.requires_auth = True
        self.auth_bypass = False             # 是否可绕过认证
        self.crbd_driftable = False          # 是否可进行 binding drift（token+ID 分离）
        self.drift_fields: Set[str] = set()  # 可漂移的字段（userId/memberId/...）
        self.evidence: List[str] = []
        self.metadata: Dict[str, Any] = {}
        # RCR 对齐字段
        self.identity_anchor: Optional[str] = None      # a_i: 身份锚点
        self.business_credentials: Set[str] = set()      # C_i: 业务凭证
        self.binding_credentials: Set[str] = set()       # C_i^bind: 绑定凭证
        self.provenance: Dict[str, str] = {}             # Π_i: 字段来源
        self.materialization_alternatives: List[Dict[str, Any]] = []  # M_i: 物化替代方案

    def to_dict(self) -> Dict[str, Any]:
        return {
            'node_id': self.node_id,
            'operation_id': self.operation_id,
            'path': self.path,
            'method': self.method,
            'node_type': self.node_type,
            'consumes': sorted(self.consumes),
            'produces': sorted(self.produces),
            'sensitive_score': self.sensitive_score,
            'requires_auth': self.requires_auth,
            'auth_bypass': self.auth_bypass,
            'crbd_driftable': self.crbd_driftable,
            'drift_fields': sorted(self.drift_fields),
            'evidence': self.evidence,
            'metadata': self.metadata,
            'identity_anchor': self.identity_anchor,
            'business_credentials': sorted(self.business_credentials),
            'binding_credentials': sorted(self.binding_credentials),
            'provenance': self.provenance,
            'materialization_alternatives': self.materialization_alternatives,
        }


class ChainEdge:
    __slots__ = ('src', 'dst', 'kind', 'field', 'confidence', 'evidence',
                 'edge_type', 'is_drift_point', 'is_sensitive_target')

    def __init__(self, src: str, dst: str, kind: str = 'dataflow',
                 field: Optional[str] = None, confidence: float = 1.0):
        self.src = src
        self.dst = dst
        self.kind = kind          # dataflow | auth_relay | oracle | drift | binding_drift
        self.field = field        # 传递的字段名
        self.confidence = confidence
        self.evidence: List[str] = []
        self.edge_type = kind     # 兼容 to_dict
        self.is_drift_point = False      # 是否是漂移点
        self.is_sensitive_target = False # 是否是敏感目标

    def to_dict(self) -> Dict[str, Any]:
        return {
            'src': self.src,
            'dst': self.dst,
            'kind': self.kind,
            'field': self.field,
            'confidence': self.confidence,
            'evidence': self.evidence,
            'edge_type': self.edge_type,
            'is_drift_point': self.is_drift_point,
            'is_sensitive_target': self.is_sensitive_target,
        }


class ExploitChain:
    """一条可执行的利用链：节点序列 + 边 + 执行脚本模板

    对齐 approach 论文中的 Workflow Search Space W_t = (R_t, ≺_t)
    和 Drift Plan P(s,t) = ⟨W_t, s, t, D_t(s)⟩
    """

    def __init__(self, chain_id: str, target: str):
        self.chain_id = chain_id
        self.target = target
        self.nodes: Dict[str, ChainNode] = {}
        self.edges: List[ChainEdge] = []
        self.entry_node: Optional[str] = None
        self.exit_node: Optional[str] = None
        self.severity = 'medium'
        self.confidence = 0.0
        self.poc_steps: List[Dict[str, Any]] = []
        self.metadata: Dict[str, Any] = {}
        # 对齐 approach 的 Drift Plan
        self.drift_point: Optional[str] = None       # s: 漂移点
        self.drift_target: Optional[str] = None      # t: 目标
        self.drift_region: Set[str] = set()          # D_t(s): 漂移影响区域
        self.binding_slice: Set[str] = set()         # S_t^bind: 绑定切片
        self.execution_closure: Set[str] = set()     # R_t^exec: 执行闭包

    def add_node(self, node: ChainNode) -> None:
        self.nodes[node.node_id] = node
        if self.entry_node is None:
            self.entry_node = node.node_id
        self.exit_node = node.node_id

    def add_edge(self, edge: ChainEdge) -> None:
        self.edges.append(edge)

    def compute_drift_region(self) -> None:
        """计算漂移影响区域 D_t(s) = {v ∈ S_t^bind | s~→*v ∧ v~→*t}"""
        if not self.drift_point or not self.drift_target:
            return
        # 从 drift_point 到 drift_target 的所有可达节点
        adj: Dict[str, List[str]] = defaultdict(list)
        for e in self.edges:
            adj[e.src].append(e.dst)
        # BFS 从 drift_point 出发
        reachable_from_s: Set[str] = set()
        queue = deque([self.drift_point])
        while queue:
            nid = queue.popleft()
            if nid in reachable_from_s:
                continue
            reachable_from_s.add(nid)
            for nxt in adj.get(nid, []):
                queue.append(nxt)
        # BFS 反向从 drift_target 出发
        radj: Dict[str, List[str]] = defaultdict(list)
        for e in self.edges:
            radj[e.dst].append(e.src)
        reachable_to_t: Set[str] = set()
        queue = deque([self.drift_target])
        while queue:
            nid = queue.popleft()
            if nid in reachable_to_t:
                continue
            reachable_to_t.add(nid)
            for prev in radj.get(nid, []):
                queue.append(prev)
        # D_t(s) = 可达 s 且可达 t 的交集
        self.drift_region = reachable_from_s & reachable_to_t
        # 绑定切片 = 所有能到达 target 的节点
        self.binding_slice = reachable_to_t

    def compute_severity(self) -> None:
        score = 0.0
        has_crbd = False
        for n in self.nodes.values():
            score += n.sensitive_score
            if n.auth_bypass:
                score += 3.0
            if n.node_type == NODE_SENSITIVE_READ:
                score += 2.0
            elif n.node_type == NODE_SENSITIVE_WRITE:
                score += 3.0
            elif n.node_type == NODE_ENUMERATION:
                score += 1.0
            if n.crbd_driftable:
                score += 3.0
                has_crbd = True
        # RR-Drift 策略直接加分
        strategy = (self.metadata or {}).get('strategy') or ''
        if 'RR-Drift' in strategy:
            score += 4.0
        # 漂移区域越大，得分越高
        if self.drift_region:
            score += len(self.drift_region) * 0.5
        self.confidence = min(score / 10.0, 1.0)
        if has_crbd and self.confidence >= 0.5:
            self.severity = 'critical'
        elif self.confidence >= 0.7:
            self.severity = 'critical'
        elif self.confidence >= 0.4:
            self.severity = 'high'
        elif self.confidence >= 0.2:
            self.severity = 'medium'
        else:
            self.severity = 'low'

    def build_poc(self) -> List[Dict[str, Any]]:
        """生成可执行的 PoC 步骤"""
        self.poc_steps = []
        # 拓扑排序
        visited: Set[str] = set()
        order: List[str] = []

        def dfs(nid: str) -> None:
            if nid in visited:
                return
            visited.add(nid)
            for e in self.edges:
                if e.dst == nid:
                    dfs(e.src)
            order.append(nid)

        for nid in self.nodes:
            dfs(nid)

        for i, nid in enumerate(order):
            node = self.nodes[nid]
            incoming = [e for e in self.edges if e.dst == nid]
            step: Dict[str, Any] = {
                'step': i + 1,
                'node_id': nid,
                'operation_id': node.operation_id,
                'method': node.method,
                'path': node.path,
                'node_type': node.node_type,
                'requires_auth': node.requires_auth,
                'auth_bypass': node.auth_bypass,
                'crbd_driftable': node.crbd_driftable,
                'drift_fields': sorted(node.drift_fields),
                'identity_anchor': node.identity_anchor,
                'inputs': {},
                'outputs': {},
                'metadata': dict(node.metadata or {}),
            }
            for e in incoming:
                step['inputs'][e.field or 'data'] = {
                    'from': e.src,
                    'confidence': e.confidence,
                    'is_drift_point': e.is_drift_point,
                }
            for field in node.produces:
                step['outputs'][field] = {'node_id': nid}
            step = attach_step_feedback_metadata(
                step,
                node.to_dict(),
                har_entry=(node.metadata or {}).get('har_entry'),
                has_crypto=bool(node.materialization_alternatives),
            )
            self.poc_steps.append(step)
        return self.poc_steps

    def to_dict(self) -> Dict[str, Any]:
        return {
            'chain_id': self.chain_id,
            'target': self.target,
            'severity': self.severity,
            'confidence': self.confidence,
            'entry_node': self.entry_node,
            'exit_node': self.exit_node,
            'nodes': {k: v.to_dict() for k, v in self.nodes.items()},
            'edges': [e.to_dict() for e in self.edges],
            'poc_steps': self.poc_steps,
            'crbd_related': any(n.crbd_driftable for n in self.nodes.values()),
            'drift_point': self.drift_point,
            'drift_target': self.drift_target,
            'drift_region': sorted(self.drift_region),
            'binding_slice': sorted(self.binding_slice),
            'execution_closure': sorted(self.execution_closure),
            'metadata': self.metadata,
        }


# ─── 核心引擎 ───

class ChainComposer:
    """从静态包 + HAR 中自动组合利用链"""

    def __init__(self, pack_dir: Path, har_path: Optional[Path] = None):
        self.pack_dir = Path(pack_dir)
        self.har_path = har_path
        self.ccrs: List[Dict[str, Any]] = []
        self.graph: Dict[str, Any] = {}
        self.workflows: List[Dict[str, Any]] = []
        self.drift_plans: List[Dict[str, Any]] = []
        self.trace_index: Dict[str, Any] = {}
        self.crypto_profile: Dict[str, Any] = {}
        self._load()

    def _load(self) -> None:
        # 加载 RCR / BCG / workflows / drift_plans
        self.ccrs = (_load_json(self.pack_dir / 'rcr_pack.json') or {}).get('ccrs') or []
        from minidrifter.rpgraph.io import load_rpgraph
        self.graph = load_rpgraph(self.pack_dir) or {}
        self.workflows = (_load_json(self.pack_dir / 'workflows.json') or {}).get('workflows') or []
        self.drift_plans = (_load_json(self.pack_dir / 'drift_plans.json') or {}).get('drift_plans') or []
        self.crypto_profile = _load_json(self.pack_dir / 'crypto_static_profile.json') or {}

        # 加载加密引擎（如果存在）
        self.crypto_engine: Optional[Any] = None
        try:
            from minidrifter.runtime.crypto.registry import get_crypto_engine_for_pack
            self.crypto_engine, _ = get_crypto_engine_for_pack(self.pack_dir)
        except Exception:
            pass

        # 加载 HAR
        if self.har_path and self.har_path.exists():
            from minidrifter.runtime_trace.crbd_probe import load_trace_index
            self.trace_index = load_trace_index(self.har_path)

    # ── 节点提取 ──

    # 通用认证端点模式（平台无关）
    AUTH_BOOTSTRAP_PATH_RE = re.compile(
        r'(getaccesstoken|gettoken|refreshtoken|login|signin|auth/token|oauth/token|api/token|'
        r'session|authenticate|authorize|credential|ticket|sso|cas|oidc|jwt|'
        r'匿名|登录|认证|授权|令牌|凭证)',
        re.I,
    )
    # 通用敏感读端点模式
    SENSITIVE_READ_PATH_RE = re.compile(
        r'(personalcenter|getperson|userinfo|user/info|profile|detail|bill|report|'
        r'signlist|coupon|mycoupon|order|account|balance|wallet|transaction|'
        r'record|history|list|query|search|get|fetch|read|view|show|'
        r'个人|用户|账户|余额|订单|记录|历史|查询|详情)',
        re.I,
    )
    # 通用敏感写端点模式
    SENSITIVE_WRITE_PATH_RE = re.compile(
        r'(bind|unbind|update|save|add|create|delete|remove|pay|upload|'
        r'changepassword|newpassword|forgetpassword|modify|edit|set|put|post|'
        r'绑定|解绑|更新|保存|添加|创建|删除|移除|支付|上传|修改|设置)',
        re.I,
    )
    # 通用枚举端点模式
    ENUM_PATH_RE = re.compile(
        r'(search|check|verify|exist|valid|findby|query|lookup|'
        r'搜索|检查|验证|存在|有效|查找)',
        re.I,
    )
    # 通用 API 前缀（过滤 JS 文件路径）
    REAL_API_PREFIX_RE = re.compile(
        r'^/(api|ylxxptapi|ggfwappbiz|private|public|console|coupon|ylfwpt|neu|mzt|zwyd|'
        r'v\d+|rest|graphql|rpc|service|gateway|open|internal|external|'
        r'app|mini|mp|wechat|alipay|baidu|toutiao|qq|jd|pdd)/',
        re.I,
    )

    # 通用可漂移字段（平台无关，基于常见命名模式）
    DRIFT_FIELDS = frozenset({
        # 用户标识
        'userid', 'uid', 'memberid', 'member_id', 'openid', 'unionid',
        'operatorid', 'accountid', 'account_id', 'personid', 'person_id',
        'customerid', 'customer_id', 'patientid', 'renterid', 'tenantid',
        'loginid', 'login_id', 'username', 'phone', 'mobile', 'telephone',
        'idcard', 'idcardno', 'id_no', 'idnumber', 'id_number', 'identity',
        'certno', 'cert_no', 'credential', 'credentialno',
        # 设备/会话标识
        'deviceid', 'device_id', 'sessionid', 'session_id', 'token',
        'accesstoken', 'access_token', 'refreshtoken', 'refresh_token',
        # 业务标识
        'orderid', 'order_id', 'billid', 'bill_id', 'recordid', 'record_id',
        'themeid', 'theme_id', 'activityid', 'activity_id', 'couponid',
        'title', 'titleid', 'title_id', 'invoicetitle', 'bindid', 'bind_id',
        'houseid', 'house_id', 'adduser', 'linkname',
        # 通用标识
        'id', 'key', 'code', 'no', 'num', 'number', 'serial',
        # 中文标识
        '用户id', '用户编号', '会员id', '会员编号', '客户id', '客户编号',
        '身份证', '身份证号', '手机号', '电话号码', '订单号', '记录号',
    })
    # 高价值 RR-Drift 路径模式（平台无关；含银行/缴费 JSON RPC）
    CRBD_HIGH_VALUE_PATH_RE = re.compile(
        r'(personalcenter|getperson|getuserinfo|personaldata|idcard|identitycard|'
        r'drivinglicense|credentialsupload|getmemberinfo|getcustomerinfo|'
        r'partner[-_]?info|distribute|bindinfo|device/list|invoice|einvoice|'
        r'unbind|bytitle|findbyphone|byphone|telephone|'
        r'mobile|wallet|getbalance|transaction|orderdetail|queryorder|'
        r'findbyordercode|patient|consultation|health|档案|'
        r'verifiedstatus|face/verified|updatememberinfo|member/update|'
        r'(my)?secondhandhouse.*/detail|'
        r'queryaccount|accountinfo|cardbinding|certauth|orderrecords|'
        r'minipro/|lifepayment/|'
        r'个人中心|用户信息|个人信息|身份证|驾驶证|证件|会员信息|客户信息|'
        r'绑定信息|设备列表|发票|订单详情|余额|交易|查询订单|患者|咨询|健康|'
        r'账户|绑卡|认证)',
        re.I,
    )

    def _is_real_api_path(self, path: str) -> bool:
        """判断是否是真实后端 API（HAR-first：拒前端路由/静态资源，放行 JSON RPC）。"""
        if not path:
            return False
        # 业务 JSON RPC（/MiniPro/foo.json）优先放行
        if is_json_rpc_path(path):
            return True
        if is_frontend_route_path(path):
            return False
        # JS/CSS/图片等静态资源（不含业务 .json RPC）
        if re.search(r'\.(js|css|png|jpg|jpeg|gif|svg|woff2?|ttf|html|htm|wxss|wxml)$', path, re.I):
            return False
        if re.search(r'^/(common|modules|pages|page|static|assets|node_modules|components)/', path, re.I):
            return False
        # 误把 host 写进 path 的噪声
        if re.search(r'\.(com|cn|net|org):\d+', path, re.I):
            return False
        if is_chain_business_path(path):
            return True
        # HAR 已观察到的相对 API：多段路径且非 tabBar/router
        segs = [s for s in path.split('/') if s]
        if len(segs) >= 2 and not re.search(r'(tabbar|router|webview)', path, re.I):
            return True
        return bool(self.REAL_API_PREFIX_RE.search(path))

    def _classify_node(self, path: str, RCR: Optional[Dict[str, Any]] = None) -> Tuple[str, float]:
        """根据路径和 RCR 信息分类节点。前端路由不升格为敏感。"""
        p = path.lower()
        if is_frontend_route_path(path) and not is_json_rpc_path(path):
            return NODE_RELAY, 0.0
        if self.AUTH_BOOTSTRAP_PATH_RE.search(p):
            return NODE_AUTH_BOOTSTRAP, 1.0
        business = is_chain_business_path(path) or is_json_rpc_path(path)
        if self.SENSITIVE_WRITE_PATH_RE.search(p) and business:
            return NODE_SENSITIVE_WRITE, 3.0
        if self.SENSITIVE_READ_PATH_RE.search(p) and business:
            return NODE_SENSITIVE_READ, 2.0
        if self.CRBD_HIGH_VALUE_PATH_RE.search(p) and business:
            return NODE_SENSITIVE_READ, 2.5
        if self.ENUM_PATH_RE.search(p) and business:
            return NODE_ENUMERATION, 1.5
        # RCR 中有 binding_credentials 的视为敏感
        if RCR and RCR.get('binding_credentials') and business:
            return NODE_SENSITIVE_READ, 1.5
        return NODE_RELAY, 0.0

    def _detect_crbd_candidate(self, node: ChainNode, RCR: Optional[Dict[str, Any]] = None) -> bool:
        """检测节点是否是 RR-Drift 候选：接受客户端传入的用户标识字段

        自适应检测：不依赖硬编码字段名，而是基于以下启发式规则：
        1. RCR 中的 binding_credentials
        2. RCR 中的 params
        3. HAR 请求参数中的标识性字段
        4. 高价值路径模式
        5. 字段命名模式（id/identity/cert/...）
        """
        # 从 RCR 的 binding_credentials 中检测
        if RCR:
            binds = [str(b).lower() for b in (RCR.get('binding_credentials') or [])]
            for b in binds:
                if self._is_drift_field(b):
                    node.crbd_driftable = True
                    node.drift_fields.add(b)
            # 也从 RCR 的 params 中检测
            params = RCR.get('params') or {}
            if isinstance(params, dict):
                for k in params:
                    if self._is_drift_field(str(k).lower()):
                        node.crbd_driftable = True
                        node.drift_fields.add(str(k).lower())

        query_bag, body_json, body_form = self._plaintext_request_bags(node)
        for bag in (query_bag, body_json, body_form):
            if isinstance(bag, dict):
                for k in bag:
                    node.consumes.add(str(k))
                    if self._is_drift_field(str(k).lower()):
                        node.crbd_driftable = True
                        node.drift_fields.add(str(k).lower())

        # 路径名暗示的绑定字段（ByTitle → title，即使静态 RCR 没抽出参数）
        for name in infer_binding_fields_from_path(node.path):
            node.consumes.add(name)
            if self._is_drift_field(str(name).lower()):
                node.crbd_driftable = True
                node.drift_fields.add(str(name).lower())

        # 高价值路径：即使字段名不是 *Id，也标成可漂移（发票 title / BindInfo 等）
        if self.CRBD_HIGH_VALUE_PATH_RE.search(node.path):
            node.crbd_driftable = True
            node.sensitive_score += 2.0
            node.evidence.append('crbd_high_value_path')
            for bag in (query_bag, body_json, body_form):
                if isinstance(bag, dict):
                    for k in bag:
                        if k:
                            node.drift_fields.add(str(k).lower())
                            node.consumes.add(str(k))

        return node.crbd_driftable

    def _plaintext_request_bags(self, node: ChainNode) -> Tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
        har_entry = (node.metadata or {}).get('har_entry') or {}
        req = har_entry.get('request') or {}
        query_bag = dict(req.get('query') or {})
        if not query_bag and self.crypto_engine and req.get('query_blob'):
            try:
                _, param_dict = self.crypto_engine.decrypt_query_blob(req['query_blob'])
                if isinstance(param_dict, dict):
                    query_bag = param_dict
            except Exception:
                pass
        if isinstance(query_bag, dict) and len(query_bag) == 1 and self.crypto_engine and not query_bag.get('query_blob'):
            only_val = next(iter(query_bag.values()))
            if isinstance(only_val, str) and (only_val.startswith('8aS') or '%' in only_val or len(only_val) > 20):
                try:
                    _, param_dict = self.crypto_engine.decrypt_query_blob(only_val)
                    if isinstance(param_dict, dict):
                        query_bag = param_dict
                except Exception:
                    pass
        body_json = dict(req.get('body_json') or {}) if isinstance(req.get('body_json'), dict) else {}
        body_form = dict(req.get('body_form') or {}) if isinstance(req.get('body_form'), dict) else {}
        # form_cid_q_sign：明文业务参数在加密 q 内
        q_blob = body_form.get('q') if isinstance(body_form, dict) else None
        if self.crypto_engine and isinstance(q_blob, str) and q_blob and not body_json:
            try:
                if hasattr(self.crypto_engine, 'decrypt_params_to_obj'):
                    inner = self.crypto_engine.decrypt_params_to_obj(q_blob)
                else:
                    plain, inner = self.crypto_engine.decrypt_query_blob(q_blob)
                    if not isinstance(inner, dict):
                        try:
                            inner = json.loads(plain)
                        except Exception:
                            inner = {}
                if isinstance(inner, dict) and inner:
                    body_json = dict(inner)
            except Exception:
                pass
        return (
            query_bag if isinstance(query_bag, dict) else {},
            body_json if isinstance(body_json, dict) else {},
            body_form if isinstance(body_form, dict) else {},
        )

    def _is_drift_field(self, field_name: str) -> bool:
        """自适应判断字段是否是可漂移的用户标识"""
        if not field_name:
            return False
        f = field_name.lower().strip()
        # 精确匹配已知字段
        if f in self.DRIFT_FIELDS:
            return True
        # 后缀匹配：*id, *idcard, *cert, *identity, *token, *key
        if f.endswith(('id', 'idcard', 'cert', 'certno', 'identity', 'token', 'key', 'no', 'code')):
            # 排除明显非标识的字段
            if f in ('grid', 'guid', 'uuid'):  # GUID 通常是会话标识
                return False
            return True
        # 前缀匹配：user_*, member_*, customer_*, patient_*, ...
        if f.startswith(('user', 'member', 'customer', 'patient', 'client', 'account', 'person')):
            return True
        # 包含匹配：*idcard*, *identity*, *cert*
        if any(x in f for x in ('idcard', 'identity', 'cert', 'credential')):
            return True
        return False

    def _extract_nodes(self) -> Dict[str, ChainNode]:
        nodes: Dict[str, ChainNode] = {}

        # 1. 从 HAR 提取真实 API 端点（优先，因为路径真实）
        if self.trace_index.get('ok'):
            by_path = self.trace_index.get('by_path') or {}
            for path, items in by_path.items():
                if not items or not self._is_real_api_path(path):
                    continue
                # 取第一个成功响应的
                chosen = None
                for it in items:
                    if int(it.get('response_status') or 0) in range(200, 300):
                        chosen = it
                        break
                chosen = chosen or items[0]
                req = chosen.get('request') or {}
                method = req.get('method') or 'GET'
                nid = f'har:{path}'
                node = ChainNode(nid, nid, path, method)
                node.metadata['source'] = 'har'
                node.metadata['har_entry_count'] = len(items)
                node.metadata['har_entry'] = chosen  # 保存完整 HAR 条目供 executor 使用

                # 从请求中提取 consumes
                query = req.get('query') or {}
                body = req.get('body_form') or {}
                for k in list(query) + list(body):
                    node.consumes.add(k)

                # 从响应中提取 produces（含加密 Result 解密后的嵌套字段）
                resp = chosen.get('response_body')
                if isinstance(resp, dict):
                    result = resp.get('Result')
                    if isinstance(result, str) and self.crypto_engine:
                        try:
                            dec = self.crypto_engine.decrypt_response_result(result)
                            if isinstance(dec, (dict, list)):
                                resp = dict(resp)
                                resp['Result'] = dec
                        except Exception:
                            pass
                    _walk_json_field_names(resp, node.produces)

                # 分类
                node.node_type, node.sensitive_score = self._classify_node(path)
                # 检查是否无认证（HAR 中无 Authorization 头且返回 200）
                headers = {str(k).lower(): str(v) for k, v in (req.get('headers') or {}).items()}
                has_auth = any(k in headers for k in ('authorization', 'token', 'cookie'))
                status = int(chosen.get('response_status') or 0)
                if status == 200 and not has_auth:
                    node.requires_auth = False
                    node.auth_bypass = True
                    node.sensitive_score += 2.0
                    node.evidence.append('har_no_auth_200')
                # 通用规则：认证引导类端点若无需凭证即可调用，视为无认证
                if self.AUTH_BOOTSTRAP_PATH_RE.search(path.lower()) and status == 200 and not has_auth:
                    node.requires_auth = False
                    node.auth_bypass = True
                    node.sensitive_score += 2.0
                    node.evidence.append('auth_endpoint_no_credential')

                # RR-Drift 候选检测
                self._detect_crbd_candidate(node)
                # HAR 高价值业务面加权
                if self.CRBD_HIGH_VALUE_PATH_RE.search(path) or is_json_rpc_path(path):
                    node.sensitive_score += 1.5
                    if not node.crbd_driftable:
                        # 加密壳常见：明文无 id，仍标为可试探（探针侧再解密）
                        node.crbd_driftable = True
                        node.drift_fields.update({'token', 'userid', 'openid', 'accountid', 'cardno'})
                        node.evidence.append('har_high_value_encrypted_candidate')

                nodes[nid] = node

        # 2. 从 RCR 补充（只保留真实业务 API；前端路由不进图）
        for RCR in self.ccrs:
            oid = RCR.get('operation_id') or ''
            raw_path = ((RCR.get('endpoint') or {}).get('path') or '')
            if not self._is_real_api_path(raw_path):
                continue
            if is_frontend_route_path(raw_path) and not is_json_rpc_path(raw_path):
                continue
            path = raw_path  # 保留原始大小写，避免执行时 404
            method = (RCR.get('method') or {}).get('value') or 'GET'
            binds = [str(b) for b in (RCR.get('binding_credentials') or [])]

            def _path_soft_eq(a: str, b: str) -> bool:
                al, bl = a.lower().rstrip('/'), b.lower().rstrip('/')
                if al == bl:
                    return True
                return al.endswith('/' + bl.lstrip('/')) or bl.endswith('/' + al.lstrip('/'))

            # 检查是否已存在（HAR 优先；允许网关前缀差；同 method）
            exists = any(
                _path_soft_eq(n.path, path) and (n.method or '').upper() == (method or '').upper()
                for n in nodes.values()
            )
            if exists:
                # 合并 RCR 信息到已有节点
                for n in nodes.values():
                    if _path_soft_eq(n.path, path) and (n.method or '').upper() == (method or '').upper():
                        # 保留 HAR 原始 path（大小写），但 operation_id 用 RCR 的
                        n.operation_id = oid
                        for b in binds:
                            n.consumes.add(b)
                            n.produces.add(b)
                        n.metadata['RCR'] = RCR
                        n.metadata['has_ccr'] = True
                        # RCR 标记为需要认证
                        if RCR.get('requires_auth', True):
                            n.requires_auth = True
                            n.auth_bypass = False
                        # 提取 RCR 完整语义
                        self._enrich_node_from_ccr(n, RCR)
                        # 重新检测 RR-Drift 候选（现在有了 RCR 语义）
                        self._detect_crbd_candidate(n, RCR)
                        break
                continue

            node = ChainNode(f'RCR:{oid}', oid, path, method)
            node.metadata['source'] = 'RCR'
            node.metadata['RCR'] = RCR
            node.node_type, node.sensitive_score = self._classify_node(path, RCR)
            for b in binds:
                node.consumes.add(b)
                node.produces.add(b)
            node.requires_auth = bool(RCR.get('requires_auth', True))
            if not node.requires_auth:
                node.auth_bypass = True
                node.sensitive_score += 2.0
            # 提取 RCR 完整语义
            self._enrich_node_from_ccr(node, RCR)
            # RR-Drift 候选检测
            self._detect_crbd_candidate(node, RCR)
            nodes[node.node_id] = node

        # HAR 网关前缀（如 /hcapi/wx）补到截断的 RCR 路径上，避免 live 404
        prefix = self._har_api_prefix()
        if prefix:
            pl = prefix.lower().rstrip('/')
            for n in nodes.values():
                if (n.metadata or {}).get('source') != 'RCR':
                    continue
                cur = (n.path or '').lower().rstrip('/')
                if not cur or cur.startswith(pl):
                    continue
                if any(cur == hp.lower().rstrip('/') or hp.lower().rstrip('/').endswith(cur)
                       for hp in (self.trace_index.get('by_path') or {}) if hp):
                    continue
                n.path = prefix.rstrip('/') + (n.path if n.path.startswith('/') else '/' + n.path)
                n.evidence.append('har_gateway_prefix')

        return nodes

    def _har_api_prefix(self) -> Optional[str]:
        """从 HAR 路径推断公共网关前缀（两段，如 /hcapi/wx）。"""
        by_path = (self.trace_index or {}).get('by_path') or {}
        if not by_path:
            return None
        counts: Dict[str, int] = defaultdict(int)
        for path in by_path:
            parts = [p for p in str(path).split('/') if p]
            if len(parts) >= 2:
                counts['/' + '/'.join(parts[:2])] += 1
        if not counts:
            return None
        best, n = max(counts.items(), key=lambda kv: kv[1])
        if n < max(3, len(by_path) // 2):
            return None
        return best

    def _enrich_node_from_ccr(self, node: ChainNode, RCR: Dict[str, Any]) -> None:
        """从 RCR 中提取完整语义到节点"""
        # 身份锚点
        identity = RCR.get('identity') or {}
        if identity.get('anchor'):
            node.identity_anchor = identity['anchor']
        # 业务凭证
        for cred in (RCR.get('business_credentials') or []):
            node.business_credentials.add(str(cred))
        # 绑定凭证
        for cred in (RCR.get('binding_credentials') or []):
            node.binding_credentials.add(str(cred))
        sem = (RCR.get('request_semantics') or {}).get('credentials') or []
        for cred in sem:
            if self._is_drift_field(str(cred).lower()):
                node.consumes.add(str(cred))
                node.drift_fields.add(str(cred).lower())
                node.crbd_driftable = True
        # 来源信息
        provenance = RCR.get('provenance') or {}
        for field, prov in provenance.items():
            node.provenance[field] = str(prov)
        # 物化替代方案
        materialization = RCR.get('materialization') or {}
        if isinstance(materialization, dict) and materialization.get('alternatives'):
            node.materialization_alternatives = materialization['alternatives']
        elif isinstance(materialization, list):
            node.materialization_alternatives = materialization

    # ── 边提取 ──

    def _extract_edges(self, nodes: Dict[str, ChainNode]) -> List[ChainEdge]:
        edges: List[ChainEdge] = []

        # 1. 从 BCG 边恢复
        for e in (self.graph.get('edges') or []):
            src = e.get('src') or ''
            dst = e.get('dst') or ''
            kind = e.get('kind') or 'dataflow'
            field = e.get('field')
            confidence = e.get('confidence', 1.0)
            # 映射到节点
            src_node = self._find_node_by_op(nodes, src.split('::')[0])
            dst_node = self._find_node_by_op(nodes, dst.split('::')[0])
            if src_node and dst_node:
                edge = ChainEdge(src_node.node_id, dst_node.node_id, kind, field, confidence)
                edges.append(edge)

        # 2. 从 HAR 序列推断 dataflow
        if self.trace_index.get('ok'):
            seq = self.trace_index.get('sequence') or []
            for i in range(len(seq) - 1):
                curr = seq[i]
                nxt = seq[i + 1]
                curr_path = (curr.get('request') or {}).get('path') or ''
                nxt_path = (nxt.get('request') or {}).get('path') or ''
                curr_node = self._find_node_by_path(nodes, curr_path)
                nxt_node = self._find_node_by_path(nodes, nxt_path)
                if curr_node and nxt_node and curr_node.node_id != nxt_node.node_id:
                    # 检查是否有字段传递：curr 响应 produces 与 nxt 请求 consumes 的交集
                    shared = curr_node.produces & nxt_node.consumes
                    if shared:
                        field = next(iter(shared))
                        edge = ChainEdge(curr_node.node_id, nxt_node.node_id, 'dataflow', field, 0.9)
                        edge.evidence.append(f'har_seq:{i}->{i+1}')
                        edges.append(edge)
                    # 即使无共享字段，也建立时序边（低置信度）
                    else:
                        edge = ChainEdge(curr_node.node_id, nxt_node.node_id, 'sequence', None, 0.3)
                        edge.evidence.append(f'har_seq:{i}->{i+1}')
                        edges.append(edge)

        # 3. 自动推断 auth_bootstrap → sensitive_read
        auth_nodes = [n for n in nodes.values() if n.node_type == NODE_AUTH_BOOTSTRAP]
        read_nodes = [n for n in nodes.values() if n.node_type == NODE_SENSITIVE_READ]
        for an in auth_nodes:
            for rn in read_nodes:
                if an.node_id != rn.node_id:
                    # 检查是否有 token/userId 传递
                    shared = an.produces & rn.consumes
                    if shared or not rn.requires_auth:
                        edge = ChainEdge(an.node_id, rn.node_id, 'auth_relay', next(iter(shared), None), 0.8)
                        edge.evidence.append('auto_auth_relay')
                        edges.append(edge)

        # 4. RR-Drift 特定：auth_bootstrap → crbd_candidate（binding_drift 边）
        crbd_nodes = [n for n in nodes.values() if n.crbd_driftable]
        for an in auth_nodes:
            for cn in crbd_nodes:
                if an.node_id != cn.node_id:
                    # RR-Drift 链：token 从 auth 来，userId 可以替换
                    edge = ChainEdge(an.node_id, cn.node_id, 'binding_drift', None, 0.9)
                    edge.evidence.append('crbd_token_drift')
                    edge.is_drift_point = True
                    edge.is_sensitive_target = cn.node_type in (NODE_SENSITIVE_READ, NODE_SENSITIVE_WRITE)
                    edges.append(edge)

        # 5. RR-Drift 特定：relay → crbd_candidate（无认证直接漂移）
        relay_nodes = [n for n in nodes.values() if n.node_type == NODE_RELAY and not n.requires_auth]
        for rn in relay_nodes:
            for cn in crbd_nodes:
                if rn.node_id != cn.node_id:
                    edge = ChainEdge(rn.node_id, cn.node_id, 'binding_drift', None, 0.7)
                    edge.evidence.append('crbd_no_auth_drift')
                    edge.is_drift_point = True
                    edge.is_sensitive_target = cn.node_type in (NODE_SENSITIVE_READ, NODE_SENSITIVE_WRITE)
                    edges.append(edge)

        # 6. 从 workflows.json 恢复工作流边（对齐 approach 的 W_t）
        for wf in self.workflows:
            ops = wf.get('operations') or []
            for i in range(len(ops) - 1):
                src_op = ops[i]
                dst_op = ops[i + 1]
                src_node = self._find_node_by_op(nodes, src_op)
                dst_node = self._find_node_by_op(nodes, dst_op)
                if src_node and dst_node and src_node.node_id != dst_node.node_id:
                    edge = ChainEdge(src_node.node_id, dst_node.node_id, 'workflow', None, 0.95)
                    edge.evidence.append(f'workflow:{wf.get("workflow_id")}')
                    edges.append(edge)

        # 7. 从 drift_plans.json 恢复漂移计划边（对齐 approach 的 P(s,t)）
        for plan in self.drift_plans:
            drift_src = plan.get('drift_source') or ''
            target = plan.get('target') or ''
            if drift_src and target:
                src_node = self._find_node_by_op(nodes, drift_src.split('::')[0])
                dst_node = self._find_node_by_op(nodes, target.split('::')[0])
                if src_node and dst_node:
                    edge = ChainEdge(src_node.node_id, dst_node.node_id, 'drift_plan', None, 1.0)
                    edge.evidence.append(f'drift_plan:{plan.get("plan_id")}')
                    edge.is_drift_point = True
                    edge.is_sensitive_target = True
                    edges.append(edge)

        return edges

    def _find_node_by_op(self, nodes: Dict[str, ChainNode], op_id: str) -> Optional[ChainNode]:
        # op_id 可能是 'op_xxx' 或 'har:/path' 或 'RCR:op_xxx'
        for n in nodes.values():
            if n.operation_id == op_id:
                return n
            if n.operation_id.endswith(op_id):
                return n
            if op_id in n.node_id:
                return n
        return None

    def _find_node_by_path(self, nodes: Dict[str, ChainNode], path: str) -> Optional[ChainNode]:
        path = path.lower().rstrip('/')
        for n in nodes.values():
            if n.path.lower().rstrip('/') == path:
                return n
            # soft match: endswith
            if n.path.lower().endswith(path) or path.endswith(n.path.lower()):
                return n
        return None

    def _high_value_single_chains(self, nodes: Dict[str, ChainNode]) -> List[ExploitChain]:
        chains: List[ExploitChain] = []
        for n in nodes.values():
            if not n.crbd_driftable:
                continue
            if n.metadata.get('source') == 'har':
                continue  # 已由 har_crbd_single_node 覆盖
            if not self.CRBD_HIGH_VALUE_PATH_RE.search(n.path):
                continue
            chain = ExploitChain(f'chain:crbd_single:{n.node_id}', n.node_id)
            chain.add_node(n)
            chain.metadata['strategy'] = 'crbd_high_value_single'
            chain.drift_point = n.node_id
            chain.drift_target = n.node_id
            chains.append(chain)
        return chains

    def _field_handoff_chains(self, nodes: Dict[str, ChainNode]) -> List[ExploitChain]:
        """A.produces ∩ B.consumes，跳过写破坏端点作为交接目标。"""
        chains: List[ExploitChain] = []
        node_list = list(nodes.values())
        for a in node_list:
            if not a.produces:
                continue
            a_prod = {str(x).lower() for x in a.produces} - _HANDOFF_SKIP
            if not a_prod:
                continue
            a_exp = _expand_identity_aliases(a_prod)
            for b in node_list:
                if a.node_id == b.node_id:
                    continue
                if _WRITE_PATH_RE.search(a.path or '') or _WRITE_PATH_RE.search(b.path or ''):
                    continue
                b_cons = {str(x).lower() for x in (b.consumes | b.drift_fields)} - _HANDOFF_SKIP
                if not b_cons:
                    continue
                b_exp = _expand_identity_aliases(b_cons)
                common = (a_prod & b_cons) | (a_prod & b_exp) | (a_exp & b_cons)
                if not common:
                    continue
                useful = {
                    f for f in common
                    if f in _IDENTITY_HANDOFF_FIELDS
                    or f.endswith('unionid') or f.endswith('bindid') or f.endswith('titleid')
                }
                if 'title' in useful and not re.search(r'invoice|title', a.path or '', re.I):
                    useful.discard('title')
                if not useful:
                    continue
                field = sorted(useful)[0]
                chain = ExploitChain(f'chain:handoff:{a.node_id}->{b.node_id}', b.node_id)
                chain.add_node(a)
                chain.add_node(b)
                orig = next(
                    (x for x in b.consumes if str(x).lower() == field and any(ch.isupper() for ch in str(x))),
                    None,
                ) or next((x for x in b.consumes if str(x).lower() == field), field)
                edge = ChainEdge(a.node_id, b.node_id, 'dataflow', orig, 0.9)
                chain.add_edge(edge)
                chain.metadata['strategy'] = 'field_handoff'
                chain.metadata['handoff_fields'] = sorted(useful)
                chain.drift_point = a.node_id
                chain.drift_target = b.node_id
                chain.compute_drift_region()
                chains.append(chain)
        return chains

    def _resource_owner_handoff_chains(self, nodes: Dict[str, ChainNode]) -> List[ExploitChain]:
        """房源/资源 detail（houseId）→ 人脸/身份核验（userId）：两跳身份证组合。"""
        producers: List[ChainNode] = []
        consumers: List[ChainNode] = []
        for n in nodes.values():
            pl = (n.path or '').lower()
            if re.search(r'(my)?secondhandhouse.*/detail|house.*/detail', pl):
                n.consumes.add('houseId')
                n.drift_fields.add('houseid')
                n.produces.add('addUser')
                n.produces.add('userId')
                n.crbd_driftable = True
                # OpenAPI 风格：detail/{houseId}，便于 executor 填路径参数
                if '{houseid}' not in pl and pl.rstrip('/').endswith('/detail'):
                    n.path = (n.path or '').rstrip('/') + '/{houseId}'
                producers.append(n)
            if re.search(r'verifiedstatus|face/verified', pl):
                n.consumes.add('userId')
                n.drift_fields.add('userid')
                n.crbd_driftable = True
                consumers.append(n)
        chains: List[ExploitChain] = []
        seen: Set[Tuple[str, str]] = set()
        # 同 path 若有 GET，丢掉 POST（红城 detail：GET 成功 / POST 业务失败）
        get_stems = {
            (n.path or '').lower().split('{')[0].rstrip('/')
            for n in producers
            if (n.method or '').upper() == 'GET'
        }
        if get_stems:
            producers = [
                n for n in producers
                if (n.method or '').upper() == 'GET'
                or (n.path or '').lower().split('{')[0].rstrip('/') not in get_stems
            ]
        producers.sort(key=lambda n: (0 if (n.method or '').upper() == 'GET' else 1, n.node_id))
        consumers.sort(key=lambda n: (0 if (n.metadata or {}).get('source') == 'har' else 1, n.node_id))
        for a in producers:
            for b in consumers:
                key = (a.node_id, b.node_id)
                if key in seen:
                    continue
                seen.add(key)
                chain = ExploitChain(f'chain:handoff:{a.node_id}->{b.node_id}', b.node_id)
                chain.add_node(a)
                chain.add_node(b)
                edge = ChainEdge(a.node_id, b.node_id, 'dataflow', 'userId', 0.95)
                chain.add_edge(edge)
                chain.metadata['strategy'] = 'field_handoff'
                chain.metadata['handoff_fields'] = ['userid', 'adduser', 'houseid']
                chain.metadata['resource_owner_handoff'] = True
                chain.drift_point = a.node_id
                chain.drift_target = b.node_id
                chain.compute_drift_region()
                chains.append(chain)
        return chains

    def compose_coverage_chains(self) -> List[ExploitChain]:
        """评测增强：HAR 单步 + 高价值单步 + 字段交接。不截断。"""
        nodes = self._extract_nodes()
        chains: List[ExploitChain] = []
        for n in nodes.values():
            if n.crbd_driftable and n.metadata.get('source') == 'har':
                chain = ExploitChain(f'chain:har_crbd:{n.node_id}', n.node_id)
                chain.add_node(n)
                chain.metadata['strategy'] = 'har_crbd_single_node'
                chain.drift_point = n.node_id
                chain.drift_target = n.node_id
                chains.append(chain)
        chains.extend(self._high_value_single_chains(nodes))
        chains.extend(self._resource_owner_handoff_chains(nodes))
        chains.extend(self._field_handoff_chains(nodes))
        unique: List[ExploitChain] = []
        seen: Set[Tuple[str, ...]] = set()
        for c in chains:
            key = tuple(sorted(c.nodes.keys()))
            if key in seen:
                continue
            seen.add(key)
            c.compute_severity()
            c.build_poc()
            unique.append(c)
        return unique

    # ── 链组合 ──

    def compose_chains(self, *, max_chains: int = 50) -> List[ExploitChain]:
        """主入口：组合利用链"""
        nodes = self._extract_nodes()
        edges = self._extract_edges(nodes)

        # 构建图
        node_map = {n.node_id: n for n in nodes.values()}
        adj: Dict[str, List[ChainEdge]] = defaultdict(list)
        for e in edges:
            adj[e.src].append(e)

        chains: List[ExploitChain] = []

        # 构建 auth_nodes / sensitive_nodes / crbd_nodes 列表
        auth_nodes = [n for n in nodes.values() if n.node_type == NODE_AUTH_BOOTSTRAP]
        sensitive_nodes = [n for n in nodes.values() if n.node_type in (NODE_SENSITIVE_READ, NODE_SENSITIVE_WRITE)]
        crbd_nodes = [n for n in nodes.values() if n.crbd_driftable]

        # 策略 0（最高优先级）：RR-Drift 链 — auth_bootstrap → crbd_candidate
        for an in auth_nodes:
            for cn in crbd_nodes:
                chain = self._bfs_chain(an.node_id, cn.node_id, adj, node_map, max_depth=3)
                if chain and len(chain.nodes) >= 2:
                    chain.metadata['strategy'] = 'crbd_token_drift'
                    chain.drift_point = an.node_id
                    chain.drift_target = cn.node_id
                    chain.compute_drift_region()
                    chains.append(chain)

        # 策略 0b：RR-Drift 链 — 无认证 relay → crbd_candidate
        relay_noauth = [n for n in nodes.values() if n.node_type == NODE_RELAY and not n.requires_auth]
        for rn in relay_noauth:
            for cn in crbd_nodes:
                chain = self._bfs_chain(rn.node_id, cn.node_id, adj, node_map, max_depth=2)
                if chain and len(chain.nodes) >= 2:
                    chain.metadata['strategy'] = 'crbd_no_auth_drift'
                    chain.drift_point = rn.node_id
                    chain.drift_target = cn.node_id
                    chain.compute_drift_region()
                    chains.append(chain)

        # 策略 0c：RR-Drift 链 — 直接 crbd_candidate（自身就是入口）
        for cn in crbd_nodes:
            if cn.auth_bypass:
                chain = ExploitChain(f'chain:crbd_direct:{cn.node_id}', cn.node_id)
                chain.add_node(cn)
                chain.metadata['strategy'] = 'crbd_direct'
                chain.drift_point = cn.node_id
                chain.drift_target = cn.node_id
                chains.append(chain)

        # 策略 0d：HAR 真实 RR-Drift 端点单步链（确保可执行漂移，覆盖 HAR 中所有用户标识端点）
        for n in nodes.values():
            if n.crbd_driftable and n.metadata.get('source') == 'har':
                chain = ExploitChain(f'chain:har_crbd:{n.node_id}', n.node_id)
                chain.add_node(n)
                chain.metadata['strategy'] = 'har_crbd_single_node'
                chain.drift_point = n.node_id
                chain.drift_target = n.node_id
                chains.append(chain)

        # 策略 0e：高价值路径单步（RCR 也能覆盖 ByTitle / UnBind 等 HAR 未捕获端点）
        chains.extend(self._high_value_single_chains(nodes))

        # 策略 0e2：资源 owner → 身份核验（房源 detail → verifiedStatus）
        chains.extend(self._resource_owner_handoff_chains(nodes))

        # 策略 0f：字段交接多跳 A.produces ∩ B.consumes（BindInfo.UnionId → phoneNumber）
        chains.extend(self._field_handoff_chains(nodes))

        # 策略 1：从 auth_bootstrap 出发，到 sensitive_read/write（最短路径优先）
        for an in auth_nodes:
            for sn in sensitive_nodes:
                chain = self._bfs_chain(an.node_id, sn.node_id, adj, node_map, max_depth=3)
                if chain and len(chain.nodes) >= 2:
                    chain.metadata['strategy'] = 'auth_to_sensitive'
                    chains.append(chain)

        # 策略 2：从 enumeration 出发，到 sensitive_read（最短路径优先）
        enum_nodes = [n for n in nodes.values() if n.node_type == NODE_ENUMERATION]
        for en in enum_nodes:
            for sn in sensitive_nodes:
                chain = self._bfs_chain(en.node_id, sn.node_id, adj, node_map, max_depth=2)
                if chain and len(chain.nodes) >= 2:
                    chain.metadata['strategy'] = 'enum_to_sensitive'
                    chains.append(chain)

        # 策略 3：无认证直接读敏感（最危险）
        for n in nodes.values():
            if n.auth_bypass and n.node_type in (NODE_SENSITIVE_READ, NODE_SENSITIVE_WRITE):
                chain = ExploitChain(f'chain:direct:{n.node_id}', n.node_id)
                chain.add_node(n)
                chain.metadata['strategy'] = 'direct_access'
                chains.append(chain)

        # 策略 4：从 drift_plans.json 恢复预定义漂移计划（对齐 approach P(s,t)）
        for plan in self.drift_plans:
            drift_src = plan.get('drift_source') or ''
            target = plan.get('target') or ''
            wf_id = plan.get('workflow_id') or ''
            if drift_src and target:
                src_node = self._find_node_by_op(nodes, drift_src.split('::')[0])
                dst_node = self._find_node_by_op(nodes, target.split('::')[0])
                if src_node and dst_node:
                    chain = self._bfs_chain(src_node.node_id, dst_node.node_id, adj, node_map, max_depth=5)
                    if chain and len(chain.nodes) >= 2:
                        chain.metadata['strategy'] = 'drift_plan'
                        chain.metadata['plan_id'] = plan.get('plan_id')
                        chain.metadata['workflow_id'] = wf_id
                        chain.drift_point = src_node.node_id
                        chain.drift_target = dst_node.node_id
                        chain.compute_drift_region()
                        chains.append(chain)

        # 去重 + 评分 + 截断
        seen: Set[Tuple[str, ...]] = set()
        unique_chains: List[ExploitChain] = []
        for c in chains:
            key = tuple(sorted(c.nodes.keys()))
            if key not in seen:
                seen.add(key)
                c.compute_severity()
                c.build_poc()
                unique_chains.append(c)

        # HAR / 字段交接 / 高价值单步优先，确保可执行性
        def _chain_priority(c: ExploitChain) -> Tuple[int, float, str]:
            strat = (c.metadata or {}).get('strategy', '')
            boost = 0
            if strat == 'har_crbd_single_node':
                boost = 5
            elif strat == 'resource_owner_handoff':
                boost = 4
            elif strat == 'field_handoff':
                boost = 3
            elif strat == 'crbd_high_value_single':
                boost = 3
            elif strat in ('crbd_direct', 'crbd_token_drift', 'crbd_high_value_single'):
                boost = 2
            # 业务 JSON RPC / 高价值路径再加权
            for n in c.nodes.values():
                if is_json_rpc_path(n.path) or self.CRBD_HIGH_VALUE_PATH_RE.search(n.path or ''):
                    boost += 2
                    break
                if is_frontend_route_path(n.path or ''):
                    boost -= 3
                    break
            return (-boost, -c.confidence, c.chain_id)

        unique_chains.sort(key=_chain_priority)
        return unique_chains[:max_chains]

    def _bfs_chain(self, start: str, goal: str, adj: Dict[str, List[ChainEdge]],
                   node_map: Dict[str, ChainNode], max_depth: int = 5) -> Optional[ExploitChain]:
        """BFS 找最短路径"""
        queue = deque([(start, [start], [])])
        visited: Set[str] = {start}

        while queue:
            nid, path, edges = queue.popleft()
            if len(path) > max_depth:
                continue
            if nid == goal and len(path) >= 2:
                chain = ExploitChain(f'chain:{start}->{goal}', goal)
                for p in path:
                    chain.add_node(node_map[p])
                for e in edges:
                    chain.add_edge(e)
                return chain
            for e in adj.get(nid, []):
                if e.dst not in visited:
                    visited.add(e.dst)
                    queue.append((e.dst, path + [e.dst], edges + [e]))
        return None

    # ── 输出 ──

    def write_output(self, chains: List[ExploitChain]) -> Path:
        out = {
            'schema_version': SCHEMA_VERSION,
            'generated_at': _utc_now(),
            'pack_dir': str(self.pack_dir),
            'har_path': str(self.har_path) if self.har_path else None,
            'chain_count': len(chains),
            'chains': [c.to_dict() for c in chains],
            'summary': {
                'critical': sum(1 for c in chains if c.severity == 'critical'),
                'high': sum(1 for c in chains if c.severity == 'high'),
                'medium': sum(1 for c in chains if c.severity == 'medium'),
                'low': sum(1 for c in chains if c.severity == 'low'),
                'with_auth_bypass': sum(1 for c in chains if any(n.auth_bypass for n in c.nodes.values())),
                'with_poc': sum(1 for c in chains if c.poc_steps),
                'crbd_chains': sum(1 for c in chains if c.metadata.get('strategy', '').startswith('RR-Drift')),
                'crbd_nodes': sum(1 for c in chains for n in c.nodes.values() if n.crbd_driftable),
            },
        }
        path = self.pack_dir / 'exploit_chains.json'
        write_json(path, out)
        return path


def compose_chains_for_pack(
    pack_dir: Path,
    har_path: Optional[Path] = None,
    max_chains: int = 50,
    *,
    har_first: bool = True,
    align_crypto: bool = True,
) -> Dict[str, Any]:
    """Compose exploit chains; optionally align crypto keys against HAR first."""
    align_report = None
    if align_crypto and har_path and Path(har_path).exists():
        try:
            from minidrifter.runtime.crypto.har_key_align import align_pack_crypto_with_har
            align_report = align_pack_crypto_with_har(Path(pack_dir), Path(har_path), persist=True)
        except Exception as ex:
            align_report = {'ok': False, 'error': f'{type(ex).__name__}:{ex}'}
    composer = ChainComposer(pack_dir, har_path)
    chains = composer.compose_chains(max_chains=max_chains)
    # When har_first, drop pure frontend-route chains that slipped through
    if har_first:
        filtered = []
        for c in chains:
            paths = [n.path or '' for n in c.nodes.values()]
            if paths and all(is_frontend_route_path(p) and not is_json_rpc_path(p) for p in paths):
                continue
            filtered.append(c)
        chains = filtered or chains
        composer.write_output(chains)
    else:
        composer.write_output(chains)
    out_path = pack_dir / 'exploit_chains.json'
    return {
        'status': 'ok',
        'chain_count': len(chains),
        'output': str(out_path),
        'har_first': har_first,
        'crypto_align': align_report,
        'summary': {
            'critical': sum(1 for c in chains if c.severity == 'critical'),
            'high': sum(1 for c in chains if c.severity == 'high'),
            'har_crbd': sum(
                1 for c in chains
                if (c.metadata or {}).get('strategy') == 'har_crbd_single_node'
            ),
            'json_rpc': sum(
                1 for c in chains
                for n in c.nodes.values()
                if is_json_rpc_path(n.path or '')
            ),
        },
    }
