# -*- coding: utf-8 -*-
"""Universal safety gates before test execution."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from minidrifter.verification.pack_loader import load_safety_policy_pack


@dataclass
class SafetyVerdict:
    allowed: bool
    reasons: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


def _path_blocked(path: str, patterns: List[str]) -> bool:
    low = path.lower()
    return any(re.search(p, low, re.I) for p in patterns)


def evaluate_test_safety(
    test_case: Dict[str, Any],
    *,
    baseline_context: Dict[str, Any],
    only_safe: bool = True,
    mode: str = 'dry-run',
    policy: Optional[Dict[str, Any]] = None,
) -> SafetyVerdict:
    policy = policy or load_safety_policy_pack()
    reasons: List[str] = []
    warnings: List[str] = []

    safety = test_case.get('safety') or {}
    side = safety.get('side_effect') or test_case.get('side_effect_level') or ''
    path = test_case.get('path') or ''

    if only_safe and side not in set(policy.get('auto_execute_side_effects') or []):
        reasons.append(f'side_effect_not_auto_allowed:{side}')

    if _path_blocked(path, policy.get('blocked_path_patterns') or []):
        reasons.append('path_matches_blocked_pattern')

    if not safety.get('auto_replay', True) and only_safe:
        reasons.append('auto_replay_false')

    if test_case.get('status') not in {
        'materialized_with_crypto_profile', 'materialized_plain', 'ready',
    } and test_case.get('template_status'):
        if test_case.get('template_status') not in {
            'materialized_with_crypto_profile', 'materialized_plain',
        }:
            warnings.append(f'template_status:{test_case.get("template_status")}')

    missing = test_case.get('missing_slots') or []
    plain = test_case.get('plain_template') or {}
    capture_replay = (
        test_case.get('template_status') == 'materialized_plain'
        and plain.get('param_source') in {
            'intake_plaintext_capture', 'intake_decrypted_query', 'intake_decrypted_body',
        }
    )
    if missing and not capture_replay:
        reasons.append(f'missing_slots:{len(missing)}')

    if test_case.get('crypto_required') and not baseline_context.get('crypto_replay_ready'):
        if baseline_context.get('replay_mode') not in {
            'plaintext_direct', 'plaintext_only_fallback',
        } and test_case.get('status') != 'materialized_plain':
            reasons.append('crypto_replay_not_ready')

    if mode == 'execute' and policy.get('require_explicit_execute_flag'):
        pass  # CLI enforces --mode execute

    host = (baseline_context.get('resolved_fields') or {}).get('Host', {}).get('value')
    if not host and test_case.get('crypto_required'):
        warnings.append('host_not_in_baseline_use_base_url')

    return SafetyVerdict(allowed=not reasons, reasons=reasons, warnings=warnings)
