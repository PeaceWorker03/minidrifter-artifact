# -*- coding: utf-8 -*-
"""Response oracle — classify outcomes, harvest fields, detect binding signals."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from minidrifter.verification.pack_loader import is_high_value_produce, load_oracle_for_pack, load_oracle_pack


def _flatten(obj: Any, prefix: str = '') -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            path = f'{prefix}.{k}' if prefix else k
            if not isinstance(v, (dict, list)):
                out[path] = v
                out[k] = v
            else:
                out.update(_flatten(v, path))
    elif isinstance(obj, list):
        for i, item in enumerate(obj[:10]):
            out.update(_flatten(item, f'{prefix}[{i}]'))
    return out


def _has_business_envelope(body: Any) -> bool:
    if not isinstance(body, dict):
        return False
    return any(k in body for k in ('IsSuccess', 'ErrorCode', 'Message', 'Result', 'result'))


def _match_patterns(text: str, patterns: List[str]) -> bool:
    low = (text or '').lower()
    for p in patterns or []:
        try:
            if re.search(str(p), text or '', re.I):
                return True
        except re.error:
            if str(p).lower() in low:
                return True
    return False


def _is_success_indicator(val: Any, success_values: List[Any]) -> bool:
    if val is True:
        return True
    if val is False or val is None:
        return False
    if isinstance(val, bool):
        return val
    for sv in success_values:
        if type(val) is type(sv) and val == sv:
            return True
        if isinstance(val, (int, float, str)) and str(val) == str(sv):
            return True
    if isinstance(val, str) and val.lower() in ('success', 'true', 'ok'):
        return True
    return False


def _bare_json_success(body: Any) -> bool:
    """Recognize envelope-less mini-program JSON success bodies."""
    if isinstance(body, list):
        return len(body) > 0
    if not isinstance(body, dict) or not body:
        return False
    ret = body.get('ret')
    if ret not in (None, 0, 1, '0', '1') and ('msg' in body or 'message' in body):
        return False
    if body.get('success') is False or body.get('ok') is False:
        return False
    success_keys = (
        'customerId', 'customerToken', 'cusAddresses', 'nickName', 'totalSigninCount',
        'remainScore', 'headImeUrl', 'log', 'DaiConfirm', 'obligation', 'cannotOrderWhenOutTimeReserve',
        'showAllShopCartData', 'remainMoney', 'platformUserId',
    )
    if any(k in body for k in success_keys):
        return True
    if len(body) >= 2 and not any(k in body for k in ('IsSuccess', 'ErrorCode', 'errorCode', 'errCode')):
        return True
    return False


def _business_status(body: Any, oracle: Dict[str, Any]) -> str:
    if isinstance(body, list):
        return 'business_success' if body else 'business_empty'
    if not isinstance(body, dict):
        return 'unknown_response'
    flat = _flatten(body)
    success_values = oracle.get('business_success_values') or []

    # Common envelopes: {"status":"SUCCESS", "content":{...}} (启果果 / many H5 APIs)
    # Also {code:10000, message:"成功"} (yipuda / several CN mini-program gateways)
    for sk in ('status', 'Status', 'msg', 'message', 'Message'):
        sv = body.get(sk)
        if isinstance(sv, str) and sv.strip().lower() in {
            'success', 'ok', 'true', 'succeed', 'successful',
            '成功', '操作成功', '请求成功', '查询成功',
        }:
            return 'business_success'
    code_val = body.get('code')
    if code_val in (10000, '10000', 200, '200'):
        return 'business_success'
    # Top-level success / ok booleans
    if body.get('success') is True or body.get('ok') is True or body.get('IsSuccess') is True:
        return 'business_success'

    for field in oracle.get('business_success_fields') or []:
        if field not in flat:
            continue
        val = flat[field]
        if _is_success_indicator(val, success_values):
            return 'business_success'
        if isinstance(val, bool) and val is False:
            return 'business_state_blocked'
        if field.lower() in ('code', 'errorcode', 'errcode') and _is_success_indicator(val, success_values):
            return 'business_success'
        if isinstance(val, int) and val != 0 and field.lower() not in ('code', 'errorcode', 'errcode'):
            return 'business_state_blocked'
        if isinstance(val, str) and val not in ('0', 'success', 'true', 'True', 'ok', 'OK', '1', 'SUCCESS') and field.lower() not in ('code', 'status'):
            return 'business_state_blocked'

    for code_field in ('ErrorCode', 'errorCode', 'code', 'Code', 'errCode'):
        if code_field in flat:
            cv = flat[code_field]
            if _is_success_indicator(cv, success_values):
                return 'business_success'
            if isinstance(cv, int) and cv == 0:
                continue
            if isinstance(cv, str) and cv in ('0', ''):
                continue
            if cv not in (None, False, 0, '0', ''):
                return 'business_state_blocked'

    if flat.get('Result') is not None or flat.get('result') is not None:
        return 'business_success'
    if _bare_json_success(body):
        return 'business_success'
    if not flat:
        return 'business_empty'
    return 'unknown_response'


SUBJECT_IDENTITY_FIELDS = frozenset({
    'userid', 'user_id', 'customerid', 'logincustomerid', 'platformuserid',
    'memberid', 'openid', 'fromcustomerid',
})


def _mutated_identity_fields(test_case: Dict[str, Any], baseline_context: Dict[str, Any]) -> List[str]:
    mut = test_case.get('mutation_type') or ''
    if not (mut.startswith('M7') or mut.startswith('M8')):
        return []
    pool = {
        k: (v.get('value') if isinstance(v, dict) else v)
        for k, v in (baseline_context.get('resolved_fields') or {}).items()
    }
    params = test_case.get('params') or {}
    body = test_case.get('body_params') or {}
    merged = {**params, **body}
    out: List[str] = []
    for key, val in merged.items():
        base = pool.get(key)
        if base is None:
            for bk, bv in pool.items():
                if str(bk).lower() == str(key).lower():
                    base = bv
                    break
        if base is not None and str(val) != str(base):
            out.append(key)
        elif mut.startswith('M8') and key.lower() in {'signature', 'sign', 'nonce', 'timestamp', 'timespan'}:
            if key not in out:
                out.append(key)
    removed = test_case.get('removed_fields') or []
    for rf in removed:
        if rf not in out:
            out.append(rf)
    return out


def _is_binding_rejection(body: Any, test_case: Dict[str, Any], baseline_context: Dict[str, Any]) -> bool:
    """ret/code failures after identity mutation → binding enforced, not generic validation."""
    if not isinstance(body, dict):
        return False
    mut = test_case.get('mutation_type') or ''
    if not mut.startswith('M7'):
        return False
    mutated = _mutated_identity_fields(test_case, baseline_context)
    if not mutated:
        return False
    if not any(str(f).lower() in SUBJECT_IDENTITY_FIELDS for f in mutated):
        return False
    ret = body.get('ret')
    if ret not in (None, 0, 1, '0', '1') and mutated:
        return True
    code = body.get('code') or body.get('ErrorCode') or body.get('errorCode')
    if code not in (None, 0, '0', 200, '200') and mutated:
        msg = str(body.get('msg') or body.get('Message') or body.get('message') or '')
        if 'param' not in msg.lower() and '参数' not in msg:
            return True
    return False


def _infer_business_failure_class(body: Any, test_case: Optional[Dict[str, Any]] = None, baseline_context: Optional[Dict[str, Any]] = None) -> str:
    if not isinstance(body, dict):
        return 'business_state_blocked'
    msg = str(body.get('Message') or body.get('message') or '')
    code = body.get('ErrorCode') or body.get('errorCode') or body.get('code')
    if test_case and baseline_context and _is_binding_rejection(body, test_case, baseline_context):
        return 'binding_rejected'
    if '版本' in msg or 'version' in msg.lower() or code in (1011023, 1011022, '1011023', '1011022'):
        return 'app_version_blocked'
    if 'token' in msg.lower() or '登录' in msg:
        return 'auth_expired'
    if 'param' in msg.lower() or '参数' in msg:
        return 'validation_error'
    return 'business_state_blocked'


def analyze_response(
    execution_result: Dict[str, Any],
    test_case: Dict[str, Any],
    *,
    baseline_context: Dict[str, Any],
    oracle: Optional[Dict[str, Any]] = None,
    pack_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    if oracle is None:
        oracle = load_oracle_for_pack(Path(pack_dir) if pack_dir else None)
    test_id = execution_result.get('test_id')
    build_status = execution_result.get('build_status')
    mode = execution_result.get('mode')

    analysis: Dict[str, Any] = {
        'test_id': test_id,
        'api_id': test_case.get('api_id'),
        'path': test_case.get('path'),
        'call_outcome': execution_result.get('call_outcome'),
    }

    if build_status and build_status != 'ok':
        analysis['call_outcome'] = 'build_failed'
        analysis['failure_class'] = 'build_failed'
        analysis['useful_for_next_step'] = False
        analysis['recommended_action'] = 'fix_build_or_missing_params'
        return analysis

    if mode == 'dry-run':
        analysis['call_outcome'] = 'dry_run_ok'
        analysis['failure_class'] = None
        analysis['useful_for_next_step'] = True
        analysis['recommended_action'] = 'execute_when_ready'
        return analysis

    status = execution_result.get('transport_status')
    body = execution_result.get('body_json')

    if status is None:
        analysis['failure_class'] = 'transport_error'
        analysis['useful_for_next_step'] = False
        analysis['recommended_action'] = 'diagnostic_transport'
        return analysis

    if status in (oracle.get('auth_failure_codes') or []):
        analysis['call_outcome'] = 'auth_required'
        analysis['failure_class'] = 'auth_expired' if status == 401 else 'permission_denied'
        analysis['authz_signal'] = 'denied'
        analysis['useful_for_next_step'] = False
        analysis['recommended_action'] = 'refresh_baseline_capture'
        return analysis

    if status in (oracle.get('rate_limit_codes') or []):
        analysis['call_outcome'] = 'rate_limited'
        analysis['failure_class'] = 'rate_limited'
        analysis['useful_for_next_step'] = False
        analysis['recommended_action'] = 'pause_host'
        return analysis

    if status in (oracle.get('server_error_codes') or []):
        analysis['call_outcome'] = 'server_error'
        analysis['failure_class'] = 'server_error'
        analysis['useful_for_next_step'] = False
        analysis['recommended_action'] = 'retry_later'
        return analysis

    if status == 404 and not _has_business_envelope(body):
        analysis['call_outcome'] = 'transport_error'
        analysis['failure_class'] = 'transport_url_routing'
        analysis['recommended_action'] = 'transport_url_repair'
        analysis['useful_for_next_step'] = True
        return analysis

    success_codes = set(oracle.get('transport_success_codes') or [200])
    if status not in success_codes and not _has_business_envelope(body):
        analysis['call_outcome'] = 'transport_error'
        analysis['failure_class'] = 'transport_error'
        analysis['useful_for_next_step'] = False
        return analysis

    analysis['call_outcome'] = 'transport_success'
    biz = _business_status(body, oracle)
    analysis['business_status'] = biz

    body_text = str(body)[:4000] if body else ''
    handled = False
    if isinstance(body, dict):
        ret = body.get('ret')
        if ret not in (None, 0, 1, '0', '1') and ('msg' in body or 'message' in body):
            fc = _infer_business_failure_class(body, test_case, baseline_context)
            analysis['failure_class'] = fc
            if fc == 'binding_rejected':
                analysis['call_outcome'] = 'binding_rejected'
                analysis['recommended_action'] = 'identity_binding_enforced'
            elif fc == 'validation_error':
                analysis['call_outcome'] = 'validation_error'
                analysis['recommended_action'] = 'schema_repair'
            else:
                analysis['call_outcome'] = 'business_state_blocked'
                analysis['recommended_action'] = 'recheck_object_pool'
            analysis['useful_for_next_step'] = True
            handled = True

    if not handled:
        if biz == 'business_success':
            analysis['call_outcome'] = 'business_success'
            analysis['failure_class'] = None
        elif _match_patterns(body_text, oracle.get('auth_expired_patterns') or []):
            analysis['call_outcome'] = 'auth_expired'
            analysis['failure_class'] = 'auth_expired'
            analysis['recommended_action'] = 'refresh_baseline_capture'
            analysis['useful_for_next_step'] = False
            return analysis
        elif _match_patterns(body_text, oracle.get('validation_error_patterns') or []):
            fc = _infer_business_failure_class(body, test_case, baseline_context)
            if fc == 'binding_rejected':
                analysis['call_outcome'] = 'binding_rejected'
                analysis['failure_class'] = 'binding_rejected'
                analysis['recommended_action'] = 'identity_binding_enforced'
                analysis['useful_for_next_step'] = True
            else:
                analysis['call_outcome'] = 'validation_error'
                analysis['failure_class'] = 'validation_error'
                analysis['recommended_action'] = 'schema_repair'
                analysis['useful_for_next_step'] = True
            handled = True
        elif biz == 'business_empty':
            analysis['call_outcome'] = 'business_empty'
            analysis['failure_class'] = 'business_empty'
        elif biz == 'business_state_blocked':
            analysis['call_outcome'] = 'business_state_blocked'
            fc = _infer_business_failure_class(body, test_case, baseline_context)
            if fc == 'binding_rejected':
                analysis['call_outcome'] = 'binding_rejected'
            analysis['failure_class'] = fc
        else:
            analysis['call_outcome'] = 'unknown_response'
            analysis['failure_class'] = 'unknown_response'

    flat = _flatten(body) if body else {}
    produces = execution_result.get('produces_fields_hint') or {}
    for k, v in flat.items():
        if is_high_value_produce(k) and v not in (None, ''):
            produces[k] = v
    analysis['produced_fields'] = sorted(set(produces.keys()))
    analysis['produced_values'] = {k: produces[k] for k in analysis['produced_fields']}
    analysis['produced_values_redacted'] = {
        k: '***' if k.lower() in {'token', 'authorization'} else produces[k]
        for k in analysis['produced_fields']
    }

    pool = {
        k: (v.get('value') if isinstance(v, dict) else v)
        for k, v in (baseline_context.get('resolved_fields') or {}).items()
    }
    subject = pool.get('UserId') or pool.get('userId') or pool.get('loginCustomerId') or pool.get('customerId')
    binding_status = 'unknown'
    mut = test_case.get('mutation_type') or ''
    mutated_subject = False
    mutated_fields = _mutated_identity_fields(test_case, baseline_context)
    signals: List[str] = []
    if mut.startswith('M7'):
        for key in mutated_fields:
            if str(key).lower() in SUBJECT_IDENTITY_FIELDS:
                mutated_subject = True
                break

    if mut.startswith('M8') and analysis.get('call_outcome') == 'business_success':
        binding_status = 'credential_guard_ignored'
        signals.append('credential_guard_bypass')
        if any('signature' in str(f).lower() for f in mutated_fields):
            signals.append('signature_not_enforced')

    if subject and produces:
        uid_in_resp = str(
            produces.get('UserId') or produces.get('userId')
            or produces.get('customerId') or flat.get('customerId') or flat.get('UserId') or ''
        )
        if uid_in_resp:
            if uid_in_resp == str(subject):
                if mutated_subject and analysis.get('call_outcome') == 'business_success':
                    binding_status = 'server_accepts_mutated_subject'
                else:
                    binding_status = 'consistent'
            else:
                binding_status = 'subject_object_binding_mismatch'
    if analysis.get('call_outcome') == 'binding_rejected' and mut.startswith('M7'):
        binding_status = 'identity_binding_enforced'
        signals.append('identity_binding_enforced')
    analysis['binding_observation'] = {
        'subject_field': test_case.get('target_field') or 'UserId',
        'subject_value_redacted': '***' if subject else None,
        'binding_status': binding_status,
        'mutated_subject_under_m7': mutated_subject,
        'mutated_fields': mutated_fields,
    }

    if binding_status == 'subject_object_binding_mismatch':
        signals.append('subject_object_binding_mismatch')
    if binding_status == 'server_accepts_mutated_subject':
        signals.append('binding_anomaly')
        signals.append('server_accepts_mutated_subject')
    if binding_status == 'credential_guard_ignored':
        signals.append('credential_weakness')
    if analysis.get('call_outcome') == 'business_success' and produces:
        signals.append('data_returned')
    analysis['security_signals'] = signals

    hv = [f for f in analysis.get('produced_fields') or [] if is_high_value_produce(f)]
    analysis['useful_for_next_step'] = bool(hv) or analysis.get('call_outcome') == 'business_success'
    analysis['next_unlocked_fields'] = hv
    analysis['recommended_action'] = 'expand_frontier' if hv else 'continue_single_point'

    return analysis


def extract_signals(
    analysis: Dict[str, Any],
    test_case: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Structured signals for search controller depth/breadth decisions."""
    security = list(analysis.get('security_signals') or [])
    suspicious: List[str] = []
    harvest = list(analysis.get('produced_fields') or [])
    binding = (analysis.get('binding_observation') or {}).get('binding_status')

    if 'subject_object_binding_mismatch' in security:
        suspicious.append('binding_anomaly')
    if binding in {'subject_object_binding_mismatch', 'server_accepts_mutated_subject'}:
        suspicious.append('binding_anomaly')
    if analysis.get('call_outcome') == 'business_success' and harvest:
        suspicious.append('data_harvest')
    mut = (test_case or {}).get('mutation_type') or ''
    if mut.startswith('M7') and analysis.get('call_outcome') == 'business_success':
        suspicious.append('mutation_bypass')

    depth_continue = bool(suspicious) or binding in {
        'subject_object_binding_mismatch', 'server_accepts_mutated_subject',
    }

    return {
        'suspicious': suspicious,
        'harvest': harvest,
        'security_signals': security,
        'depth_continue': depth_continue,
        'breadth_retire_ok': not depth_continue and analysis.get('call_outcome') not in {
            'build_failed', 'dry_run_ok',
        },
        'outcome': analysis.get('call_outcome'),
    }
