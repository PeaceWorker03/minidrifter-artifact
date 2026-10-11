# -*- coding: utf-8
"""Finding tier classification for single-account chain binding verification."""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

FINDING_F1 = 'F1_single_api_weak_binding'
FINDING_F2 = 'F2_chain_consumer_binding_drift'
FINDING_F3 = 'F3_capability_consumer_binding_drift'

_CAPABILITY_RE = re.compile(
    r'(pay|payment|paycode|qrcode|qr_code|verify|redeem|exchange|coupon|invoice|'
    r'cancel|delete|submit|apply|use|claim|withdraw|transfer|refund|核销|领取|兑换|开票|支付)',
    re.I,
)


def _hop_role(test_case: Dict[str, Any], chain_doc: Optional[Dict[str, Any]]) -> str:
    role = test_case.get('chain_hop_role') or test_case.get('chain_role') or ''
    if role:
        return role
    api_id = test_case.get('api_id')
    if chain_doc:
        for hop in chain_doc.get('hops') or []:
            if hop.get('api_id') == api_id:
                return hop.get('role') or ''
    return ''


def classify_binding_finding(
    *,
    test_case: Dict[str, Any],
    analysis: Dict[str, Any],
    chain_doc: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Classify M7/binding signals:
    - F1: entry/list/producer API
    - F2: consumer hop on object chain (LIST_DETAIL etc.)
    - F3: capability consumer (pay/verify/redeem...)
    """
    path = test_case.get('path') or analysis.get('path') or ''
    role = _hop_role(test_case, chain_doc)
    chain_type = (chain_doc or {}).get('chain_type') or ''
    target_hop = (chain_doc or {}).get('target_hop')
    api_id = test_case.get('api_id') or analysis.get('api_id')

    is_capability_chain = chain_type in {'CAPABILITY_CONSUME', 'OBJECT_CAPABILITY'}
    is_capability_path = bool(_CAPABILITY_RE.search(path))
    is_consumer = role in {'consumer', 'hop'} and role != 'producer'
    is_entry = role in {'producer', 'seed', 'entry'} or role == ''

    if api_id and target_hop and api_id == target_hop:
        is_consumer = True

    if is_capability_chain or is_capability_path:
        tier = FINDING_F3
        label = 'Capability-Consumer Binding Drift'
        primary = tier == FINDING_F3 and is_consumer
    elif is_consumer and not is_entry:
        tier = FINDING_F2
        label = 'Chain-Consumer Binding Drift'
        primary = True
    else:
        tier = FINDING_F1
        label = 'Single-API Weak Binding'
        primary = False

    return {
        'finding_tier': tier,
        'finding_tier_label': label,
        'is_primary_chain_finding': primary,
        'hop_role': role,
        'chain_type': chain_type,
        'verification_claim': (
            'chain_consumer_binding_drift' if tier == FINDING_F2
            else 'capability_consumer_binding_drift' if tier == FINDING_F3
            else 'single_api_weak_binding_signal'
        ),
    }


def apply_finding_tier_to_finding(
    finding: Dict[str, Any],
    *,
    test_case: Dict[str, Any],
    analysis: Dict[str, Any],
    chain_doc: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Annotate finding; downgrade auto-confirm for F1."""
    tier_doc = classify_binding_finding(
        test_case=test_case, analysis=analysis, chain_doc=chain_doc,
    )
    finding['finding_tier'] = tier_doc['finding_tier']
    finding['finding_tier_label'] = tier_doc['finding_tier_label']
    finding['is_primary_chain_finding'] = tier_doc['is_primary_chain_finding']
    finding['verification_claim'] = tier_doc['verification_claim']

    if tier_doc['finding_tier'] == FINDING_F1:
        finding['finding_type'] = 'single_api_weak_binding'
        if finding.get('status') == 'confirmed':
            finding['status'] = 'hypothesis'
            finding['lifecycle_reason'] = 'f1_downgrade_not_chain_consumer'
        finding['requires_chain_consumer_confirmation'] = True
    elif tier_doc['finding_tier'] == FINDING_F2:
        finding['finding_type'] = 'chain_consumer_binding_drift'
    else:
        finding['finding_type'] = 'capability_consumer_binding_drift'

    return finding


def filter_primary_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [f for f in findings if f.get('is_primary_chain_finding')]
