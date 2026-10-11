# -*- coding: utf-8 -*-
"""Generic static-analysis issue taxonomy.

Multiple project-specific symptoms map to a small set of root issue classes.
"""
from __future__ import annotations

from typing import Dict, FrozenSet

# Root classes — every concrete symptom rolls up to one of these.
CLASS_HOST_RESOLUTION = 'HOST_RESOLUTION'
CLASS_URL_ROLE = 'URL_ROLE'
CLASS_GRAPH_SEMANTICS = 'GRAPH_SEMANTICS'
CLASS_CHAIN_QUALITY = 'CHAIN_QUALITY'
CLASS_MATERIAL_READINESS = 'MATERIAL_READINESS'
CLASS_EXECUTION_ADAPTER = 'EXECUTION_ADAPTER'
CLASS_CALLSITE_BACKTRACE = 'CALLSITE_BACKTRACE'

ISSUE_CLASSES: Dict[str, str] = {
    CLASS_HOST_RESOLUTION: '宿主解析：相对路径/动态域名/第三方 host 误判',
    CLASS_URL_ROLE: 'URL 角色：业务 API 与第三方 SDK/遥测混淆',
    CLASS_GRAPH_SEMANTICS: '图语义：字段桥接、跨域连边、第三方污染',
    CLASS_CHAIN_QUALITY: '链质量：入口选择、page 证据、可执行性',
    CLASS_MATERIAL_READINESS: '材料就绪：baseline 合并、字段覆盖',
    CLASS_EXECUTION_ADAPTER: '执行适配：adapter_profile、replay 前置',
    CLASS_CALLSITE_BACKTRACE: 'Callsite 回溯：混淆分包/sub-common/webpack 页面归属',
}

# Concrete issue codes → (class, default_severity, remediation_hint)
ISSUE_REGISTRY: Dict[str, Dict[str, str]] = {
    'HOST_RELATIVE_ASSIGNED_THIRD_PARTY': {
        'class': CLASS_HOST_RESOLUTION,
        'severity': 'error',
        'hint': '相对业务路径被归到第三方 SDK host；启用 business_relative 池',
    },
    'HOST_RUNTIME_EXTCONFIG': {
        'class': CLASS_HOST_RESOLUTION,
        'severity': 'warning',
        'hint': '检测到 getServerUrl/extConfig 动态域名；需 baseline Host 或 ext 配置',
    },
    'HOST_UNRESOLVED_RELATIVE': {
        'class': CLASS_HOST_RESOLUTION,
        'severity': 'warning',
        'hint': '相对路径无可用业务 host；提供 baseline 抓包',
    },
    'HOST_BASELINE_OVERRIDE': {
        'class': CLASS_HOST_RESOLUTION,
        'severity': 'info',
        'hint': 'baseline Host 已覆盖静态推断',
    },
    'URL_THIRD_PARTY_IN_BUSINESS_POOL': {
        'class': CLASS_URL_ROLE,
        'severity': 'warning',
        'hint': '第三方 SDK URL 进入业务 API 池；应标记 url_role=third_party_sdk',
    },
    'URL_BUSINESS_RELATIVE_NO_HOST': {
        'class': CLASS_URL_ROLE,
        'severity': 'info',
        'hint': '业务相对路径等待 host 回填',
    },
    'GRAPH_THIRD_PARTY_PRODUCER': {
        'class': CLASS_GRAPH_SEMANTICS,
        'severity': 'error',
        'hint': '第三方 API 作为 producer 建边；已剪枝',
    },
    'GRAPH_SUBJECT_ONLY_BRIDGE': {
        'class': CLASS_GRAPH_SEMANTICS,
        'severity': 'warning',
        'hint': '仅 subject 字段桥接；降低置信度或剪枝',
    },
    'GRAPH_CROSS_DOMAIN_WEAK': {
        'class': CLASS_GRAPH_SEMANTICS,
        'severity': 'info',
        'hint': '跨业务域弱桥接',
    },
    'CHAIN_THIRD_PARTY_ENTRY': {
        'class': CLASS_CHAIN_QUALITY,
        'severity': 'error',
        'hint': '链入口为第三方 SDK；rank 应降权',
    },
    'CHAIN_NO_PAGE_EVIDENCE': {
        'class': CLASS_CHAIN_QUALITY,
        'severity': 'warning',
        'hint': '入口无 page/event 证据；可启用 P3 callsite 回溯',
    },
    'CALLSITE_BACKTRACE_APPLIED': {
        'class': CLASS_CALLSITE_BACKTRACE,
        'severity': 'info',
        'hint': 'P3 webpack/sub-common callsite 回溯已解析页面',
    },
    'CALLSITE_BACKTRACE_PARTIAL': {
        'class': CLASS_CALLSITE_BACKTRACE,
        'severity': 'warning',
        'hint': '部分链仍无法从混淆 callsite 回溯到页面',
    },
    'CHAIN_ENTRY_OVER_CONVERGED': {
        'class': CLASS_CHAIN_QUALITY,
        'severity': 'warning',
        'hint': '过多链共享同一入口',
    },
    'MATERIAL_BASELINE_MERGED': {
        'class': CLASS_MATERIAL_READINESS,
        'severity': 'info',
        'hint': 'baseline 增量合并成功',
    },
    'MATERIAL_BASELINE_OVERWRITE_PREVENTED': {
        'class': CLASS_MATERIAL_READINESS,
        'severity': 'info',
        'hint': '阻止了 baseline 全量覆盖',
    },
    'EXEC_ADAPTER_PROFILE_MISSING': {
        'class': CLASS_EXECUTION_ADAPTER,
        'severity': 'error',
        'hint': '缺少 adapter_profile.json；analyze 后应自动生成',
    },
    'EXEC_ADAPTER_PROFILE_WRITTEN': {
        'class': CLASS_EXECUTION_ADAPTER,
        'severity': 'info',
        'hint': 'adapter_profile.json 已写入',
    },
    'HOST_DEFAULT_IS_NOISE': {
        'class': CLASS_HOST_RESOLUTION,
        'severity': 'error',
        'hint': 'default_business_host 为噪声/第三方域；收紧 api_base 并按 score 竞选',
    },
    'HOST_API_BASE_OVERRIDES_HIGHER_SCORE': {
        'class': CLASS_HOST_RESOLUTION,
        'severity': 'warning',
        'hint': 'api_base_config 压过了更高分 observed business host',
    },
    'URL_PAGE_PATH_IN_BUSINESS_POOL': {
        'class': CLASS_URL_ROLE,
        'severity': 'error',
        'hint': '页面路由进入 business_api_operations；应标记 frontend_route',
    },
    'METHOD_UNKNOWN_HIGH_RATE': {
        'class': CLASS_URL_ROLE,
        'severity': 'warning',
        'hint': '业务 ops method UNKNOWN 比例过高；检查 wrapper/callee/path 推断',
    },
    'REQUEST_FACTS_MISSING': {
        'class': CLASS_MATERIAL_READINESS,
        'severity': 'error',
        'hint': '缺少 request_facts.json',
    },
    'CCR_MISSING': {
        'class': CLASS_MATERIAL_READINESS,
        'severity': 'error',
        'hint': '缺少 rcr_pack.json',
    },
    'CCR_IDENTITY_UNRESOLVED_RATE': {
        'class': CLASS_MATERIAL_READINESS,
        'severity': 'info',
        'hint': '多数 RCR identity 为 ⊥（静态未解析，允许）',
    },
    'CCR_BIND_EMPTY_ON_SENSITIVE': {
        'class': CLASS_MATERIAL_READINESS,
        'severity': 'warning',
        'hint': '敏感路径 RCR 无 binding_credentials',
    },
    'CONTRACT_RECOVERY_BELOW_90': {
        'class': CLASS_MATERIAL_READINESS,
        'severity': 'error',
        'hint': '合同恢复质量分 < 90%；检查 method/params/provenance/identity/transforms',
    },
    'WORKFLOW_RECONSTRUCTION_BELOW_90': {
        'class': CLASS_MATERIAL_READINESS,
        'severity': 'warning',
        'hint': '（兼容旧码）工作流重建质量分偏低；见 WORKFLOW_RECONSTRUCTION_BELOW_THRESHOLD',
    },
    'WORKFLOW_RECONSTRUCTION_BELOW_THRESHOLD': {
        'class': CLASS_MATERIAL_READINESS,
        'severity': 'warning',
        'hint': '工作流重建质量分低于论文对齐阈值（默认 75%）；检查 RPGraph / Cross-API Business Credential Dependency Graph / W_t / drift plans',
    },
    'POST_ANALYZE_STEP_FAILED': {
        'class': CLASS_EXECUTION_ADAPTER,
        'severity': 'warning',
        'hint': 'analyze 后置步骤失败；见 evidence',
    },
}

P0_ISSUE_CODES: FrozenSet[str] = frozenset(ISSUE_REGISTRY.keys())
