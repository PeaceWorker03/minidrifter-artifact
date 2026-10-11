# -*- coding: utf-8
"""Business chain graph schema — node/edge types and chain document shapes."""
from __future__ import annotations

SCHEMA_VERSION = '1.0.0'

# Node types (phase-1)
NODE_API = 'api'
NODE_FIELD = 'field'
NODE_OBJECT = 'object'
NODE_CAPABILITY = 'capability'
NODE_STATE = 'state'
NODE_IDENTITY = 'identity'
NODE_PAGE = 'page'
NODE_EVENT = 'event'

# Edge types
EDGE_REQUIRES_AUTH = 'requires_auth'
EDGE_REQUIRES_OBJECT = 'requires_object'
EDGE_REQUIRES_CAPABILITY = 'requires_capability'
EDGE_PRODUCES_OBJECT = 'produces_object'
EDGE_PRODUCES_CAPABILITY = 'produces_capability'
EDGE_PRODUCES_STATE = 'produces_state'
EDGE_PRODUCER_CONSUMER = 'producer_consumer'
EDGE_BINDING_CANDIDATE = 'binding_candidate'
EDGE_MUTATION_TARGET = 'mutation_target'

# Chain types
CHAIN_LIST_DETAIL = 'LIST_DETAIL'
CHAIN_PROFILE_OBJECT = 'PROFILE_OBJECT'
CHAIN_OBJECT_CAPABILITY = 'OBJECT_CAPABILITY'
CHAIN_CAPABILITY_CONSUME = 'CAPABILITY_CONSUME'
CHAIN_BIND_UNBIND = 'BIND_UNBIND'
CHAIN_GENERAL = 'GENERAL'

# Single-account finding claim types (Stage 4)
CLAIM_REPLAY_SIGNAL = 'replay_signal'
CLAIM_SENSITIVE_REPLAY_SIGNAL = 'sensitive_replay_signal'
CLAIM_SINGLE_ACCOUNT_BINDING_INCONSISTENCY = 'single_account_binding_inconsistency'
CLAIM_SINGLE_ACCOUNT_HIGH_CONFIDENCE = 'single_account_high_confidence_hypothesis'
CLAIM_BINDING_ENFORCED = 'binding_enforced'

VERIFICATION_SCOPE_SINGLE_ACCOUNT = 'single_account'

BUSINESS_PURPOSE = (
    '链式绑定一致性验证：在同一登录态下，静态恢复 producer API 产生业务对象字段，'
    'consumer API 使用该字段继续执行；若对绑定字段做 M7 变异后 consumer 仍返回业务成功，'
    '则说明该链路缺少登录态主体与业务对象/能力凭证的一致性校验。'
)

# Runtime context fields excluded from business chain edges
RUNTIME_CONTEXT_EXCLUDE = frozenset({
    'token', 'authorization', 'cookie', 'appidentity', 'sign', 'signature',
    'timestamp', 'timespan', 'appversion', 'host', 'content-type', 'nonce',
    'apitoken', 'api_token', 'logincustomertoken', 'customertoken',
    '_api_version_', 'requestfromtype', 'appletid',
})
