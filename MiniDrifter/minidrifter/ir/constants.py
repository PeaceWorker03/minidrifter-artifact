# -*- coding: utf-8
"""Universal IR constants — core must only use these abstractions."""
from __future__ import annotations

IR_VERSION = '1.0.0'

# ── Universal Failure Model ──────────────────────────────────────────────────
FAILURE_CLASSES = frozenset({
    'AUTH_EXPIRED',
    'MISSING_OBJECT',
    'BUSINESS_STATE_BLOCKED',
    'REQUEST_BUILD_FAILED',
    'CRYPTO_UNSUPPORTED',
    'TRANSPORT_ERROR',
    'ORACLE_UNCERTAIN',
    'SAFETY_BLOCKED',
    'CHAIN_ASSUMPTION_FAILED',
    'USER_MATERIAL_REQUIRED',
})

LEGACY_FAILURE_MAP = {
    'auth_expired': 'AUTH_EXPIRED',
    'app_version_blocked': 'AUTH_EXPIRED',
    'business_state_blocked': 'BUSINESS_STATE_BLOCKED',
    'build_failed': 'REQUEST_BUILD_FAILED',
    'safety_blocked': 'SAFETY_BLOCKED',
    'transport_error': 'TRANSPORT_ERROR',
    'transport_url_routing': 'TRANSPORT_ERROR',
    'validation_error': 'REQUEST_BUILD_FAILED',
    'param_schema_mismatch': 'REQUEST_BUILD_FAILED',
    'unknown_response': 'ORACLE_UNCERTAIN',
    'param_ignored': 'CHAIN_ASSUMPTION_FAILED',
    'no_op_mutation': 'CHAIN_ASSUMPTION_FAILED',
    'subject_object_binding_mismatch': 'CHAIN_ASSUMPTION_FAILED',
    'chain_dead_end': 'CHAIN_ASSUMPTION_FAILED',
}

# ── Universal N-tier runtime requirements ────────────────────────────────────
N_TIERS = frozenset({
    'N0',
    'N1-auth',
    'N1-object',
    'N1-state',
    'N1-capability',
    'N2-cross-subject',
    'N3-audit-only',
})

LEGACY_N0 = 'N0_STATIC_TEMPLATE'
LEGACY_N1 = 'N1_BASELINE_RUNTIME_TEMPLATE'

# ── Universal Object Model roles ─────────────────────────────────────────────
OBJECT_ROLES = frozenset({
    'subject_credential',
    'business_object',
    'capability_credential',
    'state_object',
    'session_credential',
    'environment_context',
    'crypto_material',
    'unknown',
})

FIELD_ROLE_TO_OBJECT_ROLE = {
    'auth_token': 'session_credential',
    'subject_id': 'subject_credential',
    'host_identity': 'subject_credential',
    'object_id': 'business_object',
    'capability_token': 'capability_credential',
    'environment_context': 'environment_context',
    'crypto_derived': 'crypto_material',
    'static_constant': 'environment_context',
    'local_device_context': 'business_object',
    'ordinary_field': 'unknown',
    'unknown': 'unknown',
}

# ── Universal API roles ──────────────────────────────────────────────────────
API_ROLES = frozenset({
    'producer',
    'consumer',
    'transformer',
    'capability_issuer',
    'audit_only',
    'unknown',
})

# ── Universal chain types / domains ──────────────────────────────────────────
CHAIN_TYPES = frozenset({
    'producer_consumer_binding',
    'list_to_detail',
    'list_to_detail_to_action',
    'create_preview_confirm',
    'profile_to_object_query',
    'state_check_to_capability',
    'object_query_to_capability_consume',
    'settlement_submit',
    'order_lifecycle',
})

BUSINESS_DOMAINS = frozenset({
    'invoice', 'order', 'device', 'payment', 'profile', 'coupon',
    'address', 'store', 'member', 'general',
})

SIDE_EFFECT_LEVELS = frozenset({'S0', 'S1', 'S2', 'S3', 'S4'})
