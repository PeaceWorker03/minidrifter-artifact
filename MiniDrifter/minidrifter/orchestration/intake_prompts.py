# -*- coding: utf-8
"""Structured user input requests — what to paste, when, and why (Workbench output panel)."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# Maps failure_diagnoser / policy actions → human action cards
ACTION_TO_REQUEST = {
    'refresh_baseline': 'provide_http_capture',
    'refresh_baseline_field': 'provide_field_value',
    'intake_baseline': 'provide_http_capture',
    'acquire_object': 'provide_business_capture',
    'version_baseline_repair': 'provide_field_value',
    'transport_url_repair': 'provide_http_capture',
    'schema_repair': 'provide_http_capture',
    'fix_build_or_skip': 'provide_http_capture',
    'pause_execute_class': 'provide_http_capture',
}

REQUEST_TEMPLATES: Dict[str, Dict[str, Any]] = {
    'provide_http_capture': {
        'title': '粘贴一条新的 HTTP 抓包',
        'instruction': (
            '请在 Charles/Fiddler/浏览器 DevTools 中复制完整 Raw HTTP 请求（含请求行、Headers、Body）。'
            ' 建议从下方「推荐接口」重新操作小程序触发该请求。'
        ),
        'input_format': 'raw_http',
        'cli_command': 'intake-baseline --import-after',
        'fields_expected': ['Token', 'AppVersion', 'Authorization'],
    },
    'provide_field_value': {
        'title': '提供运行时字段新值',
        'instruction': '请粘贴包含该字段的最新抓包，或单独提供字段名与新值。',
        'input_format': 'field_or_capture',
        'cli_command': 'import-baseline',
    },
    'provide_business_capture': {
        'title': '提供业务前置对象抓包',
        'instruction': (
            '当前账户缺少业务前置状态。请在小程序中完成对应业务流程（如浏览订单列表、设备列表），'
            '然后粘贴产生 OrderId/DeviceId 等字段的 API 抓包。'
        ),
        'input_format': 'raw_http',
        'cli_command': 'intake-baseline --import-after',
    },
    'confirm_side_effect': {
        'title': '确认可执行写操作验证',
        'instruction': '该链路包含 side_effect≥S2 的接口。请确认后继续，或跳过该链。',
        'input_format': 'yes_no',
    },
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _load_pack_context(pack_dir: Path) -> Dict[str, Any]:
    """Load acquisition plan, template preview, crypto profile from pack dir."""
    pack_dir = Path(pack_dir)
    ctx: Dict[str, Any] = {}
    for name, key in (
        ('acquisition_plan.json', 'acquisition_plan'),
        ('baseline_material_template.json', 'template'),
        ('crypto_static_profile.json', 'crypto_static'),
        ('adapter_profile.json', 'adapter_profile'),
    ):
        p = pack_dir / name
        if p.exists():
            import json
            ctx[key] = json.loads(p.read_text(encoding='utf-8'))
    return ctx


def _example_paths_from_pack(pack_ctx: Dict[str, Any], *, limit: int = 8) -> List[str]:
    paths: List[str] = []
    template = pack_ctx.get('template') or {}
    for item in (template.get('stage_1_target_preview') or [])[:limit]:
        p = item.get('path')
        if p and p not in paths:
            paths.append(p)
    plan = pack_ctx.get('acquisition_plan') or {}
    for item in (plan.get('stage_1_target_apis') or [])[:limit]:
        p = item.get('path')
        if p and p not in paths:
            paths.append(p)
    return paths[:limit]


def _material_steps_from_template(pack_ctx: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Build required/recommended steps from baseline_material_template (universal)."""
    template = pack_ctx.get('template') or {}
    steps: List[Dict[str, Any]] = []
    preview_paths = _example_paths_from_pack(pack_ctx)
    for bucket, phase in (('required_materials', 'required'), ('recommended_materials', 'recommended')):
        for mat in template.get(bucket) or []:
            mid = mat.get('material_id') or ''
            steps.append({
                'material_id': mid,
                'phase': phase,
                'request_type': 'provide_business_capture' if 'list' in mid or 'hop' in mid else 'provide_http_capture',
                'purpose': mat.get('user_instruction') or mat.get('why_needed') or mat.get('label') or mid,
                'example_paths': preview_paths[:5],
                'covers_fields': mat.get('covers_fields') or [],
                'paste_to': 'intake-baseline',
            })
    return steps


def build_intake_checklist(
    *,
    pack_dir: str,
    acquisition_plan: Optional[Dict[str, Any]] = None,
    preflight: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Stage-1 checklist before live verify — chain-first, legacy fallback."""
    pack_path = Path(pack_dir)
    from minidrifter.business_chain.chain_intake import build_chain_intake_checklist as build_chain_steps

    chain_doc = build_chain_steps(pack_path)
    if chain_doc.get('steps'):
        if preflight:
            step_n = len(chain_doc['steps'])
            for w in preflight.get('warnings') or []:
                if 'AppVersion' in str(w.get('message', '')):
                    step_n += 1
                    chain_doc['steps'].append({
                        'step': step_n,
                        'phase': 'warning',
                        'request_type': 'provide_field_value',
                        'field': 'AppVersion',
                        'purpose': 'Preflight 警告：AppVersion 可能被服务端拒绝，请从最新小程序抓包更新',
                        'paste_to': 'intake-baseline',
                        'source': 'preflight',
                    })
        return chain_doc

    pack_ctx = _load_pack_context(pack_path)
    if acquisition_plan is None:
        acquisition_plan = pack_ctx.get('acquisition_plan')

    steps: List[Dict[str, Any]] = []
    step_n = 0
    template_steps = _material_steps_from_template(pack_ctx)

    if template_steps:
        for ts in template_steps:
            step_n += 1
            steps.append({'step': step_n, **ts})
    else:
        example_paths = _example_paths_from_pack(pack_ctx) or ['(登录后任意成功业务 API)']
        step_n += 1
        steps.append({
            'step': step_n,
            'phase': 'required',
            'request_type': 'provide_http_capture',
            'material_id': 'authenticated_request_sample',
            'purpose': '登录后成功业务请求：提取 Token/uid/sign/加密上下文字段',
            'example_paths': example_paths,
            'paste_to': 'intake-baseline',
        })

    crypto = pack_ctx.get('crypto_static') or {}
    if crypto.get('can_replay'):
        step_n += 1
        steps.append({
            'step': step_n,
            'phase': 'info',
            'request_type': 'provide_http_capture',
            'material_id': 'crypto_replay_ready',
            'purpose': (
                f"静态加密 profile={crypto.get('profile_id')} 已就绪；"
                '可粘贴含密文 q/AppIdentity 的抓包，工具将自动解密并 parametric replay。'
            ),
            'example_paths': _example_paths_from_pack(pack_ctx)[:3],
            'paste_to': 'intake-baseline',
        })
    elif crypto.get('chain_available'):
        step_n += 1
        steps.append({
            'step': step_n,
            'phase': 'warning',
            'request_type': 'provide_http_capture',
            'material_id': 'crypto_keys_pending',
            'purpose': '检测到加密链但密钥未解析；请确保 --source-dir 指向反编译源码，或仅提供明文 session 抓包。',
            'paste_to': 'intake-baseline --source-dir <decompiled_root>',
        })

    if acquisition_plan:
        seen = {s.get('material_id') for s in steps}
        for mat in (acquisition_plan.get('material_packages') or [])[:5]:
            mid = mat.get('material_id')
            if mid in seen:
                continue
            step_n += 1
            steps.append({
                'step': step_n,
                'phase': 'recommended',
                'request_type': 'provide_business_capture',
                'material_id': mid,
                'purpose': mat.get('purpose') or mat.get('label'),
                'example_paths': mat.get('example_paths') or _example_paths_from_pack(pack_ctx)[:3],
                'paste_to': 'intake-baseline',
            })

    if preflight:
        for w in preflight.get('warnings') or []:
            if 'AppVersion' in str(w.get('message', '')):
                step_n += 1
                steps.append({
                    'step': step_n,
                    'phase': 'warning',
                    'request_type': 'provide_field_value',
                    'field': 'AppVersion',
                    'purpose': 'Preflight 警告：AppVersion 可能被服务端拒绝，请从最新小程序抓包更新',
                    'paste_to': 'intake-baseline',
                })

    return {
        'schema_version': '1.0.0',
        'generated_at': _utc_now(),
        'pack_dir': pack_dir,
        'title': 'MiniDrifter 运行态材料输入清单',
        'summary': (
            '按顺序粘贴 HTTP 抓包。每条抓包执行: '
            'python -m minidrifter.cli intake-baseline -i <pack> --raw-file <capture.txt> --import-after'
        ),
        'steps': steps,
        'templates': REQUEST_TEMPLATES,
    }


def build_operator_request(
    *,
    trigger: str,
    attribution: Optional[Dict[str, Any]] = None,
    policy: Optional[Dict[str, Any]] = None,
    test_case: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Convert runtime failure → actionable user prompt (HITL)."""
    attr = attribution or {}
    pol = policy or {}
    tc = test_case or {}

    action = attr.get('primary_action') or pol.get('action') or trigger
    request_type = ACTION_TO_REQUEST.get(action, 'provide_http_capture')
    template = REQUEST_TEMPLATES.get(request_type, REQUEST_TEMPLATES['provide_http_capture'])

    field = pol.get('target_field')
    fc = attr.get('failure_class') or trigger
    path = tc.get('path') or attr.get('path') or ''

    if fc == 'auth_expired' or action in ('refresh_baseline', 'pause_execute_class'):
        request_type = 'provide_http_capture'
        template = REQUEST_TEMPLATES['provide_http_capture']
        purpose = (
            f'Token/会话已过期（接口 {path}）。请重新登录小程序，复制**同路径或登录/bootstrap 路径**的新 Raw HTTP，'
            f'然后粘贴到工具输入区继续测试。'
        )
        example_paths = [path] if path else _example_paths_from_pack(_load_pack_context(Path('.')))[:3]
    elif fc == 'business_state_blocked' or action == 'acquire_object':
        request_type = 'provide_business_capture'
        template = REQUEST_TEMPLATES['provide_business_capture']
        purpose = (
            f'账户缺少业务前置（{attr.get("diagnosis")}）。请在小程序中触发产生 OrderId/业务 ID 的操作，'
            f'粘贴对应 list/detail 接口抓包。'
        )
        example_paths = [path] if path else []
    elif fc == 'build_failed':
        purpose = f'请求构建失败（{attr.get("diagnosis")}）。请粘贴**同 API** 在真机/开发者工具中成功发出的 Raw HTTP。'
        example_paths = [path] if path else []
    else:
        purpose = attr.get('diagnosis') or pol.get('reason') or '需要补充运行态材料'
        example_paths = [path] if path else []

    return {
        'schema_version': '1.0.0',
        'generated_at': _utc_now(),
        'status': 'waiting_user',
        'request_id': f'req_{fc}_{path.replace("/", "_")[:40]}',
        'trigger': trigger,
        'failure_class': fc,
        'layer': attr.get('layer'),
        'action': action,
        'request_type': request_type,
        'title': template.get('title'),
        'instruction': template.get('instruction'),
        'purpose': purpose,
        'path': path,
        'field': field,
        'example_paths': example_paths,
        'input_format': template.get('input_format'),
        'resume_hint': '粘贴抓包后执行 intake-baseline --import-after，工具将自动 resume 验证',
        'cli_command': template.get('cli_command'),
    }


def format_request_for_console(req: Dict[str, Any]) -> str:
    """Human-readable block for terminal / output panel."""
    lines = [
        '',
        '=' * 60,
        f"[MiniDrifter · 需要您的配合] {req.get('title')}",
        '=' * 60,
        f"原因: {req.get('purpose')}",
        f"触发: {req.get('failure_class')} @ {req.get('path') or '(global)'}",
        f"操作: {req.get('instruction')}",
    ]
    examples = req.get('example_paths') or []
    if examples:
        lines.append('推荐重新抓包的接口:')
        for p in examples[:5]:
            lines.append(f'  - {p}')
    lines.append(f"输入格式: {req.get('input_format')} → {req.get('cli_command')}")
    lines.append('=' * 60)
    return '\n'.join(lines)


USER_INPUT_PROMPT_MD = """# MiniDrifter 运行态材料输入指南

请提供用于**基准账户 A** 的运行材料。推荐直接粘贴 Burp、Charles、mitmproxy 或浏览器抓包中的原始 HTTP request/response。

## 必填材料

### 1. 登录后一条成功业务请求
请粘贴完整 request 和 response，至少包含 method、URL、headers、query/body、响应体。
该请求用于提取 Token、Authorization、AppIdentity、AppVersion、Host、Timestamp、签名字段和加密上下文。

### 2. 登录接口、个人中心或用户信息接口响应
请提供能体现当前账户主体的 response，例如包含 UserId、userId、CustomerId、Phone、OpenId、UserJwt 等字段的响应。

## 推荐材料

### 一跳对象列表接口
如设备列表、订单列表、发票列表、地址列表、优惠券列表、会员卡列表等。
工具会自动从 response 中提取 OrderId、DeviceId、InvoiceId、AddressId、CouponId 等业务对象，**不需要**手工填写深层 ID。

### 你重点关注的业务方向
可以输入：订单、发票、会员、支付、设备、优惠券、地址、核销、二维码、储值余额等。工具会优先规划相关链路。

## 暂不需要你提供

验证码、支付密码、短信码、付款码、PaySign、PrepayId、二维码明文、银行卡号、身份证号等高敏感或高副作用材料。
遇到这些材料时，工具只会提示人工确认，**不会**默认自动执行。

---

粘贴后执行：
```
python -m minidrifter.cli intake-baseline -i <pack_dir> --raw-file capture.txt --import-after
```
验证中断时查看 `blocking_tickets.json` 与 `resume_plan.json`。
"""


def build_material_requirements(
    *,
    acquisition_plan: Optional[Dict[str, Any]] = None,
    pack_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    """Structured material tiers — legacy fallback; chain plan is primary."""
    pack_ctx = _load_pack_context(pack_dir) if pack_dir else {}
    chain_primary: List[Dict[str, Any]] = []
    if pack_dir:
        from minidrifter.business_chain.chain_intake import load_chain_material_plan
        plan = load_chain_material_plan(Path(pack_dir))
        for req in (plan.get('requests') or [])[:8]:
            chain_primary.append({
                'material_id': req.get('request_id'),
                'tier': 'required' if req.get('minimum') else 'recommended',
                'label': req.get('recommended_user_action') or 'chain_seed_capture',
                'purpose': req.get('why_needed'),
                'example_paths': req.get('example_paths') or [],
                'covers_fields': req.get('target_fields') or [],
                'chain_id': req.get('chain_id'),
                'source': 'chain_material_request_plan',
            })
    if chain_primary:
        return {
            'schema_version': '1.0.0',
            'generated_at': _utc_now(),
            'primary_source': 'chain_material_request_plan.json',
            'priority': 'chain_first',
            'required': [x for x in chain_primary if x.get('tier') == 'required'],
            'recommended': [x for x in chain_primary if x.get('tier') != 'required'],
            'legacy': {'note': 'Below fields are generic fallback only'},
            'not_required': [{
                'material_id': 'high_side_effect',
                'tier': 'not_required',
                'label': '高敏感/高副作用材料',
                'examples': ['PaySign', 'PrepayId', 'SMS code', 'payment password'],
                'policy': 'human_confirm_only',
            }],
        }

    if acquisition_plan is None:
        acquisition_plan = pack_ctx.get('acquisition_plan')
    example_paths = _example_paths_from_pack(pack_ctx) or ['(pack stage_1_target_preview)']
    template = pack_ctx.get('template') or {}

    required: List[Dict[str, Any]] = []
    for mat in template.get('required_materials') or []:
        required.append({
            'material_id': mat.get('material_id'),
            'tier': 'required',
            'label': mat.get('material_id'),
            'purpose': mat.get('user_instruction') or mat.get('why_needed'),
            'example_paths': example_paths[:5],
            'covers_fields': mat.get('covers_fields') or [],
        })
    if not required:
        required = [{
            'material_id': 'authenticated_request_sample',
            'tier': 'required',
            'label': '登录后成功业务请求',
            'purpose': '提取 Token、AppVersion、签名字段、加密上下文',
            'example_paths': example_paths[:5],
        }]

    recommended: List[Dict[str, Any]] = []
    for mat in template.get('recommended_materials') or []:
        recommended.append({
            'material_id': mat.get('material_id'),
            'tier': 'recommended',
            'label': mat.get('material_id'),
            'purpose': mat.get('user_instruction'),
            'example_paths': example_paths[:5],
        })
    if acquisition_plan:
        for mat in (acquisition_plan.get('material_packages') or [])[:8]:
            recommended.append({
                'material_id': mat.get('material_id'),
                'tier': 'recommended',
                'label': mat.get('label') or mat.get('material_id'),
                'purpose': mat.get('purpose'),
                'example_paths': mat.get('example_paths') or [],
            })
    not_required = [
        {
            'material_id': 'high_side_effect',
            'tier': 'not_required',
            'label': '高敏感/高副作用材料',
            'examples': ['PaySign', 'PrepayId', 'SMS code', 'payment password', 'QR plaintext'],
            'policy': 'human_confirm_only',
        },
    ]
    return {
        'schema_version': '1.0.0',
        'generated_at': _utc_now(),
        'required': required,
        'recommended': recommended,
        'not_required': not_required,
    }


def write_user_input_artifacts(pack_dir: Path, *, acquisition_plan: Optional[Dict[str, Any]] = None) -> None:
    """Write chain-first intake + legacy fallback artifacts."""
    pack_dir = Path(pack_dir)
    from minidrifter.business_chain.chain_intake import (
        build_chain_intake_checklist,
        render_chain_intake_prompt,
    )
    from minidrifter.core.utils import write_json

    chain_prompt = render_chain_intake_prompt(pack_dir, use_llm=True)
    (pack_dir / 'chain_intake_prompt.md').write_text(chain_prompt, encoding='utf-8')
    write_json(pack_dir / 'chain_intake_checklist.json', build_chain_intake_checklist(pack_dir))

    pack_ctx = _load_pack_context(pack_dir)
    if acquisition_plan is None:
        acquisition_plan = pack_ctx.get('acquisition_plan')

    crypto = pack_ctx.get('crypto_static') or {}
    crypto_note = ''
    if crypto.get('can_replay'):
        crypto_note = (
            f'\n\n## 加密 transport 说明\n\n'
            f'本 pack 静态 profile **{crypto.get("profile_id")}** 已就绪。'
            '粘贴含密文字段的抓包后，工具会自动解密并启用 parametric replay。\n'
        )
    elif crypto.get('chain_available'):
        crypto_note = (
            '\n\n## 加密 transport 说明\n\n'
            '检测到加密链但密钥未解析。请提供 `--source-dir` 反编译目录，'
            '或仅粘贴含明文 Token/uid 的抓包（密文段将被跳过）。\n'
        )

    (pack_dir / 'user_input_prompt.md').write_text(chain_prompt + crypto_note, encoding='utf-8')
    write_json(
        pack_dir / 'material_requirements.json',
        build_material_requirements(acquisition_plan=acquisition_plan, pack_dir=pack_dir),
    )
    write_json(pack_dir / 'user_intake_checklist.json', build_intake_checklist(
        pack_dir=str(pack_dir), acquisition_plan=acquisition_plan,
    ))
