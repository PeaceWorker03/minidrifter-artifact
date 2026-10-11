# -*- coding: utf-8 -*-
"""Typed runtime object pool — subject / object / capability / auth layers."""
from __future__ import annotations

import copy
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from minidrifter.core.schema import SCHEMA_VERSION
from minidrifter.core.utils import stable_id
from minidrifter.verification.pack_loader import classify_field, load_field_ontology

FIELD_CLASS_TO_POOL = {
    'session_credential': 'auth_pool',
    'subject_credential': 'subject_pool',
    'object_identifier': 'object_pool',
    'capability_credential': 'capability_pool',
    'ordinary_business_param': 'environment_pool',
}

GLOBAL_CONTEXT_FIELDS = frozenset({
    'Token', 'Authorization', 'AppIdentity', 'TimeSpan', 'Timestamp',
    'AppVersion', 'AppPlatform', 'Host', 'Version', 'Source', 'Company',
    'ModelVersion', 'Remark', 'Content-Type', 'channelId', 'ticket',
})

POOL_NAMES = (
    'auth_pool', 'subject_pool', 'object_pool',
    'capability_pool', 'environment_pool', 'negative_pool',
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def pool_name_for_class(field_class: str) -> str:
    return FIELD_CLASS_TO_POOL.get(field_class, 'environment_pool')


def empty_object_pool(*, account_label: str = 'A') -> Dict[str, Any]:
    return {
        'schema_version': SCHEMA_VERSION,
        'pool_format': 'typed_pools',
        'generated_at': _utc_now(),
        'account_label': account_label,
        'pools': {name: {} for name in POOL_NAMES},
        'confirmed_fields': [],
        'confirmed_objects': [],
        'frontier_unlocks': [],
    }


def _baseline_value(baseline_context: Dict[str, Any], field: str) -> Optional[str]:
    v = (baseline_context.get('resolved_fields') or {}).get(field)
    if isinstance(v, dict):
        return str(v['value']) if v.get('value') not in (None, '') else None
    return str(v) if v not in (None, '') else None


def infer_usable_for(field_class: str, analysis: Dict[str, Any]) -> List[str]:
    usable = ['baseline_replay']
    if analysis.get('call_outcome') == 'business_success':
        usable.append('same_account_substitution')
    if field_class == 'object_identifier':
        usable.append('object_binding_test')
    if field_class == 'subject_credential':
        usable.append('subject_binding_test')
    return usable


def _make_object(
    *,
    field: str,
    value: str,
    field_class: str,
    owner_account: str,
    phase: str,
    source: str,
    source_api: Optional[str] = None,
    source_test: Optional[str] = None,
    source_path: Optional[str] = None,
    freshness: str,
    confidence: float,
    confirmed: bool,
) -> Dict[str, Any]:
    pool_name = pool_name_for_class(field_class)
    oid = stable_id('obj', phase, field, value[:32])
    return {
        'object_id': oid,
        'field': field,
        'field_class': field_class,
        'pool_name': pool_name,
        'value': value,
        'value_redacted': '***',
        'owner_account': owner_account,
        'source': source,
        'source_api': source_api,
        'source_test': source_test,
        'source_path': source_path,
        'phase': phase,
        'freshness': freshness,
        'confidence': confidence,
        'usable_for': infer_usable_for(field_class, {'call_outcome': 'business_success' if confirmed else 'observed'}),
        'blocked_for': ['cross_account_substitution'],
        'confirmed': confirmed,
    }


def init_object_pool(baseline_context: Dict[str, Any]) -> Dict[str, Any]:
    ontology = load_field_ontology()
    account = baseline_context.get('account_label') or 'A'
    pool = empty_object_pool(account_label=account)

    for k, v in (baseline_context.get('resolved_fields') or {}).items():
        if not isinstance(v, dict) or v.get('value') in (None, ''):
            continue
        field_class = classify_field(k, ontology)
        obj = _make_object(
            field=k,
            value=str(v.get('value')),
            field_class=field_class,
            owner_account=account,
            phase='baseline',
            source=v.get('source') or 'baseline',
            freshness='baseline_confirmed',
            confidence=1.0,
            confirmed=True,
        )
        pool['pools'][obj['pool_name']][obj['object_id']] = obj

    refresh_pool_indexes(pool)
    return pool


def update_pool_from_analysis(
    pool: Dict[str, Any],
    analysis: Dict[str, Any],
    *,
    test_id: str,
) -> Dict[str, Any]:
    ontology = load_field_ontology()
    values = analysis.get('produced_values') or {}
    account = pool.get('account_label') or 'A'
    confirmed = analysis.get('call_outcome') == 'business_success'

    for field, value in values.items():
        if value in (None, ''):
            continue
        field_class = classify_field(field, ontology)
        obj = _make_object(
            field=field,
            value=str(value),
            field_class=field_class,
            owner_account=account,
            phase='runtime_harvest',
            source=f'{test_id}.response',
            source_api=analysis.get('api_id'),
            source_test=test_id,
            source_path=analysis.get('path'),
            freshness='live_confirmed' if confirmed else 'observed',
            confidence=0.9 if confirmed else 0.5,
            confirmed=confirmed,
        )
        pool['pools'][obj['pool_name']][obj['object_id']] = obj

    refresh_pool_indexes(pool)
    return pool


def pool_snapshot_hash(pool: Dict[str, Any]) -> str:
    """Hash confirmed business field set for prune P3."""
    import hashlib
    parts = sorted(pool.get('frontier_unlocks') or pool.get('confirmed_fields') or [])
    return hashlib.sha256('|'.join(parts).encode()).hexdigest()[:16]


def ensure_negative_synthetics(pool: Dict[str, Any], baseline_context: Dict[str, Any]) -> Dict[str, Any]:
    """Seed negative_pool with synthetic wrong IDs for binding mutation tests."""
    import re

    account = pool.get('account_label') or 'A'
    identity_re = re.compile(
        r'^(user_?id|customer_?id|logincustomerid|platformuserid|memberid|openid|operatorid)$',
        re.I,
    )
    seen_fields: Set[str] = set()

    for field, entry in (baseline_context.get('resolved_fields') or {}).items():
        if not isinstance(entry, dict):
            continue
        val = entry.get('value')
        if val in (None, ''):
            continue
        if not identity_re.match(str(field)):
            continue
        fl = str(field).lower()
        if fl in seen_fields:
            continue
        baseline_val = str(val)
        if baseline_val.isdigit():
            wrong = str(int(baseline_val) + 1) if len(baseline_val) < 12 else '9999999999'
        else:
            wrong = f'{baseline_val}_alt'
        if wrong == baseline_val:
            wrong = '9999999999'
        obj = _make_object(
            field=field,
            value=wrong,
            field_class='subject_credential',
            owner_account=account,
            phase='synthetic_negative',
            source='negative_pool_synthetic',
            freshness='synthetic',
            confidence=0.3,
            confirmed=False,
        )
        obj['pool_name'] = 'negative_pool'
        obj['usable_for'] = ['subject_binding_test']
        pool['pools']['negative_pool'][obj['object_id']] = obj
        seen_fields.add(fl)

    refresh_pool_indexes(pool)
    return pool


def refresh_pool_indexes(pool: Dict[str, Any]) -> None:
    confirmed_fields: Set[str] = set()
    confirmed_objects: List[str] = []
    business_fields: Set[str] = set()

    for pool_name, objs in (pool.get('pools') or {}).items():
        for oid, obj in objs.items():
            confirmed_objects.append(oid)
            field = obj.get('field')
            if not field:
                continue
            if obj.get('confirmed'):
                confirmed_fields.add(field)
            if field not in GLOBAL_CONTEXT_FIELDS and pool_name != 'auth_pool':
                business_fields.add(field)

    pool['confirmed_fields'] = sorted(confirmed_fields)
    pool['confirmed_objects'] = sorted(set(confirmed_objects))
    pool['frontier_unlocks'] = sorted(business_fields)
    pool['generated_at'] = _utc_now()


def resolve_baseline_ref(ref: str, baseline_context: Dict[str, Any]) -> Optional[str]:
    if not isinstance(ref, str) or not ref.startswith('$baseline.'):
        return None
    field = ref.split('.', 1)[1]
    return _baseline_value(baseline_context, field)


def object_pool_select(
    pool: Dict[str, Any],
    selector: Dict[str, Any],
    *,
    baseline_context: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    required_pool = selector.get('required_pool')
    field = selector.get('field')
    field_class = selector.get('field_class')
    different_from = selector.get('different_from')
    owner_account = selector.get('owner_account')

    diff_val = None
    if different_from:
        if str(different_from).startswith('$baseline.') and baseline_context:
            diff_val = resolve_baseline_ref(str(different_from), baseline_context)
        else:
            diff_val = str(different_from)

    search_pools: List[str]
    if required_pool == 'negative_pool':
        search_pools = ['negative_pool']
    elif required_pool:
        search_pools = [required_pool]
    elif field_class:
        search_pools = [pool_name_for_class(field_class)]
    else:
        search_pools = [p for p in POOL_NAMES if p != 'negative_pool']

    for pool_name in search_pools:
        for obj in (pool.get('pools') or {}).get(pool_name, {}).values():
            if field and str(obj.get('field', '')).lower() != str(field).lower():
                continue
            if field_class and obj.get('field_class') != field_class:
                continue
            if owner_account and obj.get('owner_account') != owner_account:
                continue
            if diff_val is not None and str(obj.get('value')) == str(diff_val):
                continue
            return obj
    return None


def redact_pool(pool: Dict[str, Any]) -> Dict[str, Any]:
    out = copy.deepcopy(pool)
    for pool_name, objs in (out.get('pools') or {}).items():
        for oid, obj in objs.items():
            obj.pop('value', None)
    return out


def write_object_pools(pack_dir, pool: Dict[str, Any]) -> None:
    from pathlib import Path

    from minidrifter.core.utils import write_json

    root = Path(pack_dir)
    write_json(root / 'workflow_object_pool.json', redact_pool(pool))
    write_json(root / 'workflow_object_pool.private.json', pool)
