# -*- coding: utf-8 -*-
"""Feedback Engine: 验证结果反哺下一轮探测。

核心能力：
1. 收集每次 HTTP 探测的响应特征（状态码/关键词/耗时/数据量）
2. 基于响应特征自动分类：成功/失败/被拦截/需要认证/存在/不存在
3. 将分类结果反馈给 Chain Composer，调整链优先级
4. 自动学习「有效响应模式」，减少无效探测
"""
from __future__ import annotations

import json
import re
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from minidrifter.core.utils import write_json

SCHEMA_VERSION = '1.0.0'


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _load_json(path: Path) -> Any:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding='utf-8'))


# ─── 响应分类器 ───

class ResponseClassifier:
    """基于规则和历史的响应分类器"""

    # 已知响应模式库
    PATTERNS = {
        'success': [
            (r'"code"\s*:\s*0', 0.9),
            (r'"success"\s*:\s*true', 0.9),
            (r'"data"\s*:\s*\{', 0.7),
            (r'"data"\s*:\s*\[', 0.7),
            (r'status\s*[:=]\s*200', 0.6),
            (r'access_?token', 0.8),
            (r'refresh_?token', 0.8),
        ],
        'auth_required': [
            (r'"code"\s*:\s*401', 0.95),
            (r'用户凭证已过期', 0.95),
            (r'未登录|请先登录|请登录', 0.9),
            (r'authentication.*required', 0.9),
            (r'invalid.*token', 0.85),
        ],
        'not_found': [
            (r'"code"\s*:\s*404', 0.95),
            (r'not.*found', 0.8),
            (r'不存在', 0.85),
        ],
        'forbidden': [
            (r'"code"\s*:\s*403', 0.95),
            (r'forbidden', 0.9),
            (r'权限不足|无权访问', 0.9),
        ],
        'waf_blocked': [
            (r'"code"\s*:\s*461', 0.95),
            (r'waf|防火墙|拦截|攻击', 0.85),
            (r'sql.*inject|xss', 0.9),
        ],
        'user_not_exist': [
            (r'账户不存在|用户不存在|找不到.*用户', 0.95),
            (r'无法找到.*绑定人', 0.9),
            (r'not.*exist', 0.85),
            (r'登.*id不能为空', 0.9),
        ],
        'user_exists': [
            (r'年龄小于|年龄不足', 0.9),
            (r'已注册|已绑定', 0.85),
            (r'该用户已存在', 0.9),
        ],
        # RR-Drift 特定：数据泄露信号
        'data_leak': [
            (r'"idCard"|"id_card"|"idcard"|"idCardNo"', 0.9),
            (r'"phone"|"mobile"|"telephone"', 0.7),
            (r'"name"|"realName"|"userName"', 0.6),
            (r'"address"|"email"', 0.5),
            (r'"bankCard"|"bank_card"', 0.9),
            (r'"orderId"|"order_id"', 0.5),
        ],
        # RR-Drift 特定：写操作被接受
        'write_accepted': [
            (r'"code"\s*:\s*0.*"msg".*成功', 0.9),
            (r'操作成功|修改成功|绑定成功', 0.9),
        ],
        'business_error': [
            (r'"code"\s*:\s*1', 0.7),
            (r'出现了点小意外', 0.8),
            (r'系统繁忙|稍后再试', 0.75),
        ],
        'empty_data': [
            (r'"data"\s*:\s*\[\s*\]', 0.9),
            (r'"data"\s*:\s*null', 0.8),
            (r'"records"\s*:\s*\[\s*\]', 0.9),
            (r'"total"\s*:\s*0', 0.85),
        ],
    }

    def __init__(self):
        self.history: deque = deque(maxlen=10000)
        self.pattern_weights: Dict[str, Dict[str, float]] = defaultdict(dict)
        self._load_patterns()

    def _load_patterns(self) -> None:
        """初始化模式权重"""
        for cat, patterns in self.PATTERNS.items():
            for pat, weight in patterns:
                self.pattern_weights[cat][pat] = weight

    def classify(self, status_code: int, body: str, elapsed_ms: float = 0) -> Dict[str, Any]:
        """分类响应"""
        body_str = str(body)[:2000]  # 截断防大报文
        scores: Dict[str, float] = defaultdict(float)

        # 规则匹配
        for cat, patterns in self.pattern_weights.items():
            for pat, weight in patterns.items():
                if re.search(pat, body_str, re.I):
                    scores[cat] += weight

        # 状态码修正
        if status_code == 200:
            scores['success'] += 0.3
        elif status_code == 401:
            scores['auth_required'] += 0.5
        elif status_code == 403:
            scores['forbidden'] += 0.5
        elif status_code == 404:
            scores['not_found'] += 0.5
        elif status_code == 461:
            scores['waf_blocked'] += 0.5

        # 数据量判断
        if len(body_str) < 50:
            scores['empty_data'] += 0.2
        elif len(body_str) > 1000:
            scores['success'] += 0.1

        # 耗时判断（快速失败通常是无数据）
        if elapsed_ms < 50 and status_code == 200:
            scores['empty_data'] += 0.1

        # RR-Drift 特定：如果同时满足 success + data_leak，提升为 data_leak
        if scores.get('success', 0) > 0.3 and scores.get('data_leak', 0) > 0.3:
            scores['data_leak'] += scores['success'] * 0.5

        # 取最高分
        if scores:
            best = max(scores.items(), key=lambda x: x[1])
            return {
                'category': best[0],
                'confidence': min(best[1], 1.0),
                'scores': dict(scores),
                'status_code': status_code,
                'body_preview': body_str[:200],
                'elapsed_ms': elapsed_ms,
            }
        return {
            'category': 'unknown',
            'confidence': 0.0,
            'scores': {},
            'status_code': status_code,
            'body_preview': body_str[:200],
            'elapsed_ms': elapsed_ms,
        }

    def learn(self, status_code: int, body: str, true_label: str) -> None:
        """在线学习：调整模式权重"""
        body_str = str(body)[:2000]
        result = self.classify(status_code, body_str)
        pred = result['category']

        if pred != true_label:
            # 降低错误预测中匹配模式的权重
            for pat in self.pattern_weights.get(pred, {}):
                if re.search(pat, body_str, re.I):
                    self.pattern_weights[pred][pat] *= 0.95
            # 提升真实标签的权重
            for pat in self.pattern_weights.get(true_label, {}):
                if re.search(pat, body_str, re.I):
                    self.pattern_weights[true_label][pat] = min(
                        self.pattern_weights[true_label][pat] * 1.05, 1.0
                    )

        self.history.append({
            'status_code': status_code,
            'category': result['category'],
            'true_label': true_label,
            'confidence': result['confidence'],
            'at': _utc_now(),
        })


# ─── 反馈闭环引擎 ───

class FeedbackEngine:
    """收集探测结果，反哺 Chain Composer

    对齐 approach 论文 §3.3:
    - Node-Level Feedback: 修复物化选择 M_i
    - Path-Level Feedback: 阻塞分支 B，恢复前缀 RestorePrefix(q)
    """

    def __init__(self, pack_dir: Path):
        self.pack_dir = Path(pack_dir)
        self.classifier = ResponseClassifier()
        self.probe_history: List[Dict[str, Any]] = []
        self.chain_scores: Dict[str, float] = {}
        self.blocked_endpoints: Set[str] = set()
        self.valid_endpoints: Set[str] = set()
        self.oracle_map: Dict[str, Dict[str, Any]] = {}  # endpoint -> oracle 信息
        # Node-Level: 物化替代方案反馈
        self.materialization_feedback: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        # Path-Level: 分支阻塞记录
        self.blocked_branches: Set[str] = set()
        self.branch_history: List[Dict[str, Any]] = []
        self._load_state()

    def _load_state(self) -> None:
        state = _load_json(self.pack_dir / 'feedback_state.json') or {}
        self.probe_history = state.get('probe_history', [])[-1000:]
        self.chain_scores = state.get('chain_scores', {})
        self.blocked_endpoints = set(state.get('blocked_endpoints', []))
        self.valid_endpoints = set(state.get('valid_endpoints', []))
        self.oracle_map = state.get('oracle_map', {})
        self.materialization_feedback = defaultdict(list, state.get('materialization_feedback', {}))
        self.blocked_branches = set(state.get('blocked_branches', []))
        self.branch_history = state.get('branch_history', [])[-500:]

    def save_state(self) -> Path:
        out = {
            'schema_version': SCHEMA_VERSION,
            'generated_at': _utc_now(),
            'probe_history': self.probe_history[-1000:],
            'chain_scores': self.chain_scores,
            'blocked_endpoints': sorted(self.blocked_endpoints),
            'valid_endpoints': sorted(self.valid_endpoints),
            'oracle_map': self.oracle_map,
            'materialization_feedback': dict(self.materialization_feedback),
            'blocked_branches': sorted(self.blocked_branches),
            'branch_history': self.branch_history[-500:],
        }
        path = self.pack_dir / 'feedback_state.json'
        write_json(path, out)
        return path

    # ── Node-Level 反馈 ──

    def record_materialization_attempt(self, node_id: str, alternative_idx: int,
                                       success: bool, feedback: Dict[str, Any]) -> None:
        """记录物化替代方案的尝试结果（Node-Level Feedback）"""
        record = {
            'node_id': node_id,
            'alternative_idx': alternative_idx,
            'success': success,
            'feedback': feedback,
            'at': _utc_now(),
        }
        self.materialization_feedback[node_id].append(record)

    def get_materialization_alternatives(self, node_id: str) -> List[Dict[str, Any]]:
        """获取节点的物化替代方案，按历史成功率排序"""
        history = self.materialization_feedback.get(node_id, [])
        if not history:
            return []
        # 统计每个替代方案的成功率
        alt_stats: Dict[int, Dict[str, int]] = defaultdict(lambda: {'success': 0, 'fail': 0})
        for h in history:
            idx = h['alternative_idx']
            if h['success']:
                alt_stats[idx]['success'] += 1
            else:
                alt_stats[idx]['fail'] += 1
        # 按成功率排序
        sorted_alts = sorted(
            alt_stats.items(),
            key=lambda x: x[1]['success'] / max(x[1]['success'] + x[1]['fail'], 1),
            reverse=True
        )
        return [{'alternative_idx': idx, 'stats': stats} for idx, stats in sorted_alts]

    # ── Path-Level 反馈 ──

    def record_branch_blocked(self, branch_choice: str, reason: str,
                              checkpoint: Optional[Dict[str, Any]] = None) -> None:
        """记录被阻塞的分支（Path-Level Feedback）"""
        self.blocked_branches.add(branch_choice)
        record = {
            'branch_choice': branch_choice,
            'reason': reason,
            'checkpoint': checkpoint,
            'at': _utc_now(),
        }
        self.branch_history.append(record)

    def is_branch_blocked(self, branch_choice: str) -> bool:
        """检查分支是否被阻塞"""
        return branch_choice in self.blocked_branches

    def get_unblocked_branches(self, candidates: List[str]) -> List[str]:
        """从候选分支中筛选未阻塞的"""
        return [c for c in candidates if c not in self.blocked_branches]

    # ── 探测结果记录 ──

    def record_probe(self, *, endpoint: str, method: str, params: Dict[str, Any],
                     status_code: int, response_body: str, elapsed_ms: float,
                     chain_id: Optional[str] = None) -> Dict[str, Any]:
        """记录一次探测结果"""
        classification = self.classifier.classify(status_code, response_body, elapsed_ms)
        record = {
            'endpoint': endpoint,
            'method': method,
            'params': params,
            'status_code': status_code,
            'classification': classification,
            'chain_id': chain_id,
            'at': _utc_now(),
        }
        self.probe_history.append(record)

        # 更新端点状态
        cat = classification['category']
        if cat in ('success', 'user_exists', 'user_not_exist'):
            self.valid_endpoints.add(endpoint)
        elif cat in ('waf_blocked', 'forbidden', 'auth_required'):
            self.blocked_endpoints.add(endpoint)

        # 更新链评分
        if chain_id:
            self._update_chain_score(chain_id, cat, classification['confidence'])

        # 学习
        self.classifier.learn(status_code, response_body, cat)

        return record

    def _update_chain_score(self, chain_id: str, category: str, confidence: float) -> None:
        """根据探测结果更新链评分"""
        delta = 0.0
        if category == 'success':
            delta = 0.1 * confidence
        elif category == 'user_exists':
            delta = 0.05 * confidence
        elif category == 'data_leak':
            delta = 0.2 * confidence  # RR-Drift 数据泄露：大幅加分
        elif category == 'write_accepted':
            delta = 0.15 * confidence  # RR-Drift 写接受：大幅加分
        elif category == 'empty_data':
            delta = -0.02
        elif category in ('waf_blocked', 'forbidden'):
            delta = -0.1
        elif category == 'auth_required':
            delta = -0.05

        self.chain_scores[chain_id] = self.chain_scores.get(chain_id, 0.5) + delta
        self.chain_scores[chain_id] = max(0.0, min(1.0, self.chain_scores[chain_id]))

    # ── Oracle 提取 ──

    def extract_oracle(self, endpoint: str, param: str, values: List[str],
                       method: str = 'GET', headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """从多次探测中提取 oracle 规律"""
        responses = []
        for v in values:
            # 这里只是模板，实际执行由调用方完成
            responses.append({
                'value': v,
                'endpoint': endpoint,
                'param': param,
            })

        oracle = {
            'endpoint': endpoint,
            'param': param,
            'method': method,
            'values_tested': len(values),
            'responses': responses,
            'discriminates': False,  # 是否区分存在/不存在
            'pattern': None,
        }

        # 分析已有历史
        relevant = [r for r in self.probe_history if r['endpoint'] == endpoint]
        if len(relevant) >= 2:
            cats = [r['classification']['category'] for r in relevant]
            if len(set(cats)) > 1:
                oracle['discriminates'] = True
                oracle['pattern'] = {
                    'categories': list(set(cats)),
                    'discriminator': 'response_category',
                }

        self.oracle_map[endpoint] = oracle
        return oracle

    # ── 链优化建议 ──

    def get_chain_recommendations(self, chains: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """根据反馈历史，对链进行重新排序"""
        scored = []
        for chain in chains:
            cid = chain.get('chain_id')
            base_score = chain.get('confidence', 0.5)
            feedback_score = self.chain_scores.get(cid, base_score)

            # 检查是否包含被拦截的端点
            blocked = any(
                n.get('path') in self.blocked_endpoints
                for n in (chain.get('nodes') or {}).values()
            )
            if blocked:
                feedback_score *= 0.5

            # 检查是否包含已验证有效的端点
            valid = any(
                n.get('path') in self.valid_endpoints
                for n in (chain.get('nodes') or {}).values()
            )
            if valid:
                feedback_score *= 1.2

            scored.append({
                **chain,
                'feedback_score': min(feedback_score, 1.0),
                'original_score': base_score,
                'blocked_endpoints': [n.get('path') for n in (chain.get('nodes') or {}).values()
                                      if n.get('path') in self.blocked_endpoints],
            })

        scored.sort(key=lambda x: -x['feedback_score'])
        return scored

    # ── 统计报告 ──

    def get_endpoint_history(self, endpoint: str) -> List[Dict[str, Any]]:
        """获取指定端点的探测历史"""
        return [r for r in self.probe_history if r.get('endpoint') == endpoint]

    def get_stats(self) -> Dict[str, Any]:
        cats = defaultdict(int)
        for r in self.probe_history:
            cats[r['classification']['category']] += 1
        return {
            'total_probes': len(self.probe_history),
            'category_distribution': dict(cats),
            'blocked_endpoints': len(self.blocked_endpoints),
            'valid_endpoints': len(self.valid_endpoints),
            'oracle_count': len(self.oracle_map),
            'chain_scores': dict(sorted(self.chain_scores.items(), key=lambda x: -x[1])[:20]),
            # 新增：Node-Level + Path-Level 统计
            'materialization_feedback_nodes': len(self.materialization_feedback),
            'blocked_branches': len(self.blocked_branches),
            'branch_history_count': len(self.branch_history),
        }


def create_feedback_engine(pack_dir: Path) -> FeedbackEngine:
    return FeedbackEngine(pack_dir)
