# -*- coding: utf-8 -*-
"""Active Probe: 无认证端点扫描 + Oracle 提取 + 枚举。

核心能力：
1. 自动发现无认证/弱认证端点
2. 提取存在性 oracle（用户存在/不存在）
3. 批量枚举（身份证/手机号/userId）
4. 与 Feedback Engine 联动
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

SCHEMA_VERSION = '1.0.0'

# 全局 SSL 上下文（跳过验证，用于测试环境）
_ssl_ctx = ssl.create_default_context()
_ssl_ctx.check_hostname = False
_ssl_ctx.verify_mode = ssl.CERT_NONE


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _http_request(url: str, data: Optional[Dict[str, Any]] = None,
                  headers: Optional[Dict[str, str]] = None,
                  method: Optional[str] = None,
                  timeout: int = 15) -> Tuple[int, str, float]:
    """发送 HTTP 请求，返回 (status_code, body, elapsed_ms)"""
    h = {"Content-Type": "application/x-www-form-urlencoded"}
    if headers:
        h.update(headers)
    body = urllib.parse.urlencode(data).encode() if isinstance(data, dict) else data
    req = urllib.request.Request(url, data=body, headers=h, method=method or ("POST" if body else "GET"))
    start = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ssl_ctx) as r:
            elapsed = (time.time() - start) * 1000
            return r.status, r.read().decode("utf-8", "replace"), elapsed
    except urllib.error.HTTPError as e:
        elapsed = (time.time() - start) * 1000
        return e.code, e.read().decode("utf-8", "replace"), elapsed
    except Exception as e:
        elapsed = (time.time() - start) * 1000
        return -1, str(e), elapsed


def _gbk_decode(s: str) -> str:
    """处理 GBK 编码：先尝试直接当 UTF-8，再尝试 latin1->gbk"""
    if not s:
        return s
    # 如果已经是合法 UTF-8（含中文），直接返回
    try:
        s.encode('utf-8')
        return s
    except UnicodeEncodeError:
        pass
    # 尝试 latin1 -> gbk
    try:
        return s.encode('latin1').decode('gbk')
    except Exception:
        pass
    # 尝试 latin1 -> utf-8
    try:
        return s.encode('latin1').decode('utf-8')
    except Exception:
        pass
    return s


# ─── 无认证端点扫描 ───

class UnauthenticatedEndpointScanner:
    """扫描无认证/弱认证端点"""

    COMMON_PATHS = [
        # 认证/令牌
        '/getAccessToken', '/getToken', '/refreshToken', '/login', '/signin',
        '/auth/token', '/oauth/token', '/api/token',
        # 用户信息
        '/user/info', '/user/profile', '/user/detail', '/user/list',
        '/personalCenter/get', '/personalCenter/getPerson',
        # 枚举/检查
        '/checkUser', '/checkPhone', '/checkIdCard', '/exist', '/valid',
        # 公开数据
        '/area', '/dict', '/config', '/const', '/region',
        '/console/area/childs', '/console/dsrpt/dict/typeWithapp',
        # 文件/资源
        '/upload', '/download', '/file', '/export',
        # 管理/调试
        '/admin', '/debug', '/test', '/swagger', '/actuator', '/health',
        '/metrics', '/info', '/env',
    ]

    def __init__(self, base_url: str, feedback: Optional[FeedbackEngine] = None):
        self.base_url = base_url.rstrip('/')
        self.feedback = feedback
        self.discovered: List[Dict[str, Any]] = []

    def scan(self, paths: Optional[List[str]] = None,
             params_template: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """扫描端点"""
        paths = paths or self.COMMON_PATHS
        results = []

        for path in paths:
            url = self.base_url + path
            # 尝试 GET
            status, body, elapsed = _http_request(url, params_template)
            body = _gbk_decode(body)
            result = {
                'url': url,
                'method': 'GET',
                'status_code': status,
                'body_preview': body[:300],
                'elapsed_ms': elapsed,
                'accessible': status == 200,
                'requires_auth': status in (401, 403),
                'timestamp': _utc_now(),
            }
            results.append(result)
            if self.feedback:
                self.feedback.record_probe(
                    endpoint=path, method='GET', params=params_template or {},
                    status_code=status, response_body=body, elapsed_ms=elapsed,
                )

            # 如果 405，尝试 POST
            if status == 405:
                status2, body2, elapsed2 = _http_request(url, params_template, method='POST')
                body2 = _gbk_decode(body2)
                result2 = {
                    'url': url,
                    'method': 'POST',
                    'status_code': status2,
                    'body_preview': body2[:300],
                    'elapsed_ms': elapsed2,
                    'accessible': status2 == 200,
                    'requires_auth': status2 in (401, 403),
                    'timestamp': _utc_now(),
                }
                results.append(result2)
                if self.feedback:
                    self.feedback.record_probe(
                        endpoint=path, method='POST', params=params_template or {},
                        status_code=status2, response_body=body2, elapsed_ms=elapsed2,
                    )

        self.discovered = [r for r in results if r['accessible'] and not r['requires_auth']]
        return results

    def get_accessible(self) -> List[Dict[str, Any]]:
        return self.discovered


# ─── Oracle 提取器 ───

class OracleExtractor:
    """从端点提取存在性 oracle"""

    def __init__(self, feedback: FeedbackEngine):
        self.feedback = feedback

    def extract(self, endpoint: str, param: str, test_values: List[str],
                method: str = 'GET', base_url: str = '',
                headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """测试一组值，提取 oracle 规律"""
        results = []
        for val in test_values:
            url = base_url + endpoint if base_url else endpoint
            # GET: params in query string; POST: params in body
            if method.upper() == 'GET':
                qs = urllib.parse.urlencode({param: val})
                full_url = f"{url}?{qs}" if qs else url
                status, body, elapsed = _http_request(full_url, None, headers, 'GET')
            else:
                status, body, elapsed = _http_request(url, {param: val}, headers, method)
            body = _gbk_decode(body)

            classification = self.feedback.classifier.classify(status, body, elapsed)
            results.append({
                'value': val,
                'status_code': status,
                'category': classification['category'],
                'confidence': classification['confidence'],
                'body_preview': body[:200],
                'elapsed_ms': elapsed,
            })

            self.feedback.record_probe(
                endpoint=endpoint, method=method, params={param: val},
                status_code=status, response_body=body, elapsed_ms=elapsed,
            )

        # 分析是否区分
        categories = [r['category'] for r in results]
        discriminates = len(set(categories)) > 1

        # 找到区分点
        discriminator = None
        if discriminates:
            # 按类别分组
            by_cat: Dict[str, List[str]] = defaultdict(list)
            for r in results:
                by_cat[r['category']].append(r['value'])
            discriminator = {
                'categories': {k: v[:5] for k, v in by_cat.items()},
                'pattern': self._find_pattern(results),
            }

        oracle = {
            'endpoint': endpoint,
            'param': param,
            'method': method,
            'discriminates': discriminates,
            'discriminator': discriminator,
            'test_count': len(results),
            'results': results,
            'timestamp': _utc_now(),
        }
        self.feedback.oracle_map[endpoint] = oracle
        return oracle

    def _find_pattern(self, results: List[Dict[str, Any]]) -> Optional[str]:
        """找响应文本中的区分模式"""
        texts = [(r['value'], r['body_preview']) for r in results]
        # 简单实现：找第一个不同关键词
        for i in range(len(texts)):
            for j in range(i + 1, len(texts)):
                v1, t1 = texts[i]
                v2, t2 = texts[j]
                if t1 != t2:
                    # 找不同子串
                    for k in range(min(len(t1), len(t2))):
                        if t1[k] != t2[k]:
                            start = max(0, k - 20)
                            end = min(len(t1), k + 20)
                            return f"diff_at_{k}: '{t1[start:end]}' vs '{t2[start:end]}'"
        return None


# ─── 枚举引擎 ───

class EnumerationEngine:
    """批量枚举（身份证/手机号/userId）"""

    def __init__(self, feedback: FeedbackEngine):
        self.feedback = feedback
        self.hits: List[Dict[str, Any]] = []

    def enumerate_idcards(self, endpoint: str, param: str,
                          area_codes: List[str],
                          birth_years: Optional[List[int]] = None,
                          base_url: str = '',
                          headers: Optional[Dict[str, str]] = None,
                          max_attempts: int = 500) -> List[Dict[str, Any]]:
        """枚举身份证"""
        birth_years = birth_years or list(range(1940, 1980))
        weights = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
        check_chars = "10X98765432"

        def gen_idcard(area: str, year: int, month: int, day: int, seq: int) -> str:
            base = f"{area}{year:04d}{month:02d}{day:02d}{seq:03d}"
            total = sum(int(b) * w for b, w in zip(base, weights))
            return base + check_chars[total % 11]

        attempts = 0
        for area in area_codes:
            for year in birth_years:
                for seq in [11, 21, 31, 41, 51, 61, 71, 81, 91, 101]:
                    if attempts >= max_attempts:
                        break
                    idcard = gen_idcard(area, year, 6, 15, seq)
                    url = base_url + endpoint if base_url else endpoint
                    status, body, elapsed = _http_request(url, {param: idcard}, headers)
                    body = _gbk_decode(body)

                    classification = self.feedback.classifier.classify(status, body, elapsed)
                    self.feedback.record_probe(
                        endpoint=endpoint, method='GET', params={param: idcard},
                        status_code=status, response_body=body, elapsed_ms=elapsed,
                    )

                    # 命中条件：不是"不存在"且不是"格式错误"
                    if classification['category'] not in ('user_not_exist', 'empty_data', 'unknown'):
                        hit = {
                            'idcard': idcard,
                            'area': area,
                            'year': year,
                            'category': classification['category'],
                            'body_preview': body[:200],
                            'timestamp': _utc_now(),
                        }
                        self.hits.append(hit)
                        print(f"  [HIT] {idcard} -> {classification['category']}")

                    attempts += 1
                    time.sleep(0.05)  # 限速

        return self.hits

    def enumerate_userids(self, endpoint: str, param: str,
                          base_uuid: str, range_size: int = 1000,
                          base_url: str = '',
                          headers: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
        """基于已知 UUID 枚举邻接值"""
        base = int(base_uuid, 16)
        hits = []

        for i in range(-range_size, range_size + 1):
            uid = format(base + i, '032x')
            url = base_url + endpoint if base_url else endpoint
            status, body, elapsed = _http_request(url, {param: uid}, headers)
            body = _gbk_decode(body)

            classification = self.feedback.classifier.classify(status, body, elapsed)
            self.feedback.record_probe(
                endpoint=endpoint, method='GET', params={param: uid},
                status_code=status, response_body=body, elapsed_ms=elapsed,
            )

            if classification['category'] == 'success':
                hits.append({
                    'user_id': uid,
                    'offset': i,
                    'body_preview': body[:200],
                    'timestamp': _utc_now(),
                })

        return hits


# ─── 主动探测引擎（整合） ───

class ActiveProbeEngine:
    """整合扫描、Oracle 提取、枚举"""

    def __init__(self, pack_dir: Path):
        self.pack_dir = Path(pack_dir)
        self.feedback = FeedbackEngine(pack_dir)
        self.scanner: Optional[UnauthenticatedEndpointScanner] = None
        self.oracle_extractor = OracleExtractor(self.feedback)
        self.enum_engine = EnumerationEngine(self.feedback)

    def setup_scanner(self, base_url: str) -> UnauthenticatedEndpointScanner:
        self.scanner = UnauthenticatedEndpointScanner(base_url, self.feedback)
        return self.scanner

    def run_full_probe(self, base_url: str, *,
                       scan_paths: Optional[List[str]] = None,
                       oracle_tests: Optional[List[Dict[str, Any]]] = None,
                       enum_tasks: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        """运行完整主动探测"""
        results: Dict[str, Any] = {
            'schema_version': SCHEMA_VERSION,
            'generated_at': _utc_now(),
            'base_url': base_url,
            'scan': None,
            'oracles': [],
            'enumerations': [],
        }

        # 1. 端点扫描
        if scan_paths is not None:
            scanner = self.setup_scanner(base_url)
            scan_results = scanner.scan(scan_paths)
            results['scan'] = {
                'total': len(scan_results),
                'accessible': len(scanner.get_accessible()),
                'endpoints': scan_results,
            }

        # 2. Oracle 提取
        for test in (oracle_tests or []):
            oracle = self.oracle_extractor.extract(
                endpoint=test['endpoint'],
                param=test['param'],
                test_values=test['values'],
                method=test.get('method', 'GET'),
                base_url=base_url,
                headers=test.get('headers'),
            )
            results['oracles'].append(oracle)

        # 3. 枚举
        for task in (enum_tasks or []):
            if task['type'] == 'idcard':
                hits = self.enum_engine.enumerate_idcards(
                    endpoint=task['endpoint'],
                    param=task['param'],
                    area_codes=task.get('area_codes', []),
                    birth_years=task.get('birth_years'),
                    base_url=base_url,
                    headers=task.get('headers'),
                    max_attempts=task.get('max_attempts', 500),
                )
                results['enumerations'].append({
                    'type': 'idcard',
                    'endpoint': task['endpoint'],
                    'hits': hits,
                    'hit_count': len(hits),
                })
            elif task['type'] == 'userid':
                hits = self.enum_engine.enumerate_userids(
                    endpoint=task['endpoint'],
                    param=task['param'],
                    base_uuid=task['base_uuid'],
                    range_size=task.get('range_size', 1000),
                    base_url=base_url,
                    headers=task.get('headers'),
                )
                results['enumerations'].append({
                    'type': 'userid',
                    'endpoint': task['endpoint'],
                    'hits': hits,
                    'hit_count': len(hits),
                })

        # 保存反馈状态
        self.feedback.save_state()

        # 统计
        results['stats'] = self.feedback.get_stats()

        out_path = self.pack_dir / 'active_probe_report.json'
        write_json(out_path, results)
        results['output'] = str(out_path)
        return results


def run_active_probe(pack_dir: Path, base_url: str, **kwargs) -> Dict[str, Any]:
    engine = ActiveProbeEngine(pack_dir)
    return engine.run_full_probe(base_url, **kwargs)
