# -*- coding: utf-8
"""Pre-static gates: is this project ready for MiniDrifter N0/N1 pipeline?"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from minidrifter.core.profile import ProjectProfileDetector
from minidrifter.orchestration.workspace_scanner import discover_projects

READY_SHAPES = frozenset({
    'decompiled_config_based',
    'app_service_bundle',
    'source_like',
    'framework_compiled',
})


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def baseline_replay_ready(ctx: Optional[Dict[str, Any]]) -> bool:
    """True when baseline supports live replay (crypto chain OR plaintext_direct captures)."""
    if not ctx:
        return False
    if int(ctx.get('field_count') or 0) <= 0:
        return False
    if ctx.get('crypto_replay_ready'):
        return True
    strategy = (ctx.get('intake_strategy') or {}).get('strategy') or ctx.get('replay_mode')
    return strategy == 'plaintext_direct' and bool(ctx.get('n1_materialize_allowed'))


def check_decompile_readiness(project_root: Path) -> Dict[str, Any]:
    """Like wedecode pre-check: can we run static extraction on this tree?"""
    project_root = Path(project_root).resolve()
    blockers: List[Dict[str, Any]] = []
    warnings: List[Dict[str, Any]] = []

    if not project_root.is_dir():
        return {
            'ready': False,
            'blockers': [{'code': 'not_a_directory', 'message': str(project_root)}],
            'warnings': [],
        }

    profile = ProjectProfileDetector(project_root).run()
    shape = profile.get('shape') or 'mixed_or_unknown'

    if shape not in READY_SHAPES:
        blockers.append({
            'code': 'not_decompiled_or_unrecognized',
            'message': (
                f'Project shape={shape}. Expected decompiled wxapkg output '
                '(app.json + pages/ or app-config.json + app-service.js). '
                'Run wedecode/unpack first.'
            ),
            'shape': shape,
        })

    if not profile.get('has_app_json') and not profile.get('has_app_config_json'):
        blockers.append({
            'code': 'missing_app_manifest',
            'message': 'Missing app.json and app-config.json — cannot locate mini-program entry.',
        })

    js_count = sum(1 for _ in project_root.rglob('*.js') if _.is_file())
    if js_count == 0:
        blockers.append({
            'code': 'no_javascript',
            'message': 'No .js files found — static API recovery impossible.',
        })

    obf = (profile.get('obfuscation') or {}).get('level')
    if obf == 'high':
        warnings.append({
            'code': 'high_obfuscation',
            'message': 'Heavy obfuscation may reduce API recovery quality.',
        })

    if profile.get('platform_guess') != 'wechat':
        warnings.append({
            'code': 'platform_uncertain',
            'message': 'Platform not confidently identified as WeChat mini-program.',
        })

    return {
        'schema_version': '1.0.0',
        'generated_at': _utc_now(),
        'project_root': str(project_root),
        'profile': profile,
        'ready': len(blockers) == 0,
        'blockers': blockers,
        'warnings': warnings,
        'next_stage': 'static_analyze' if not blockers else None,
    }


def check_pack_readiness(pack_dir: Path) -> Dict[str, Any]:
    """After static analyze: N0/N1 pack artifacts present for verification?"""
    pack_dir = Path(pack_dir)
    blockers: List[Dict[str, Any]] = []
    warnings: List[Dict[str, Any]] = []
    checks: List[Dict[str, Any]] = []

    required = [
        ('api_cards.json', 'N0 frozen API cards'),
        ('evidence_requirements.json', 'N0/N1 ERD classification'),
    ]
    optional_verify = [
        ('baseline_runtime_context.json', 'N1 baseline for replay'),
        ('materialized_api_templates.json', 'N1 materialized templates'),
        ('workflow_graph.json', 'workflow consumer/producer graph'),
    ]

    for fname, label in required:
        ok = (pack_dir / fname).exists()
        checks.append({'name': fname, 'label': label, 'ok': ok, 'required': True})
        if not ok:
            blockers.append({'code': f'missing_{fname}', 'message': f'Missing {label}: {fname}'})

    for fname, label in optional_verify:
        ok = (pack_dir / fname).exists()
        checks.append({'name': fname, 'label': label, 'ok': ok, 'required': False})
        if not ok:
            warnings.append({'code': f'missing_{fname}', 'message': f'Missing {label} (needed before live verify)'})

    ctx_path = pack_dir / 'baseline_runtime_context.json'
    n1_ready = False
    if ctx_path.exists():
        import json
        ctx = json.loads(ctx_path.read_text(encoding='utf-8'))
        n1_ready = baseline_replay_ready(ctx)
        strategy = (ctx.get('intake_strategy') or {}).get('strategy') or ctx.get('replay_mode')
        if not n1_ready:
            warnings.append({
                'code': 'crypto_replay_not_ready',
                'message': 'baseline crypto_replay_ready=false — paste captures via intake-baseline',
            })
        elif strategy == 'plaintext_direct' and not ctx.get('crypto_replay_ready'):
            warnings.append({
                'code': 'plaintext_direct_replay',
                'message': 'Using plaintext capture replay (no crypto engine)',
            })

    return {
        'schema_version': '1.0.0',
        'generated_at': _utc_now(),
        'pack_dir': str(pack_dir),
        'ready_for_static_review': len(blockers) == 0,
        'ready_for_live_verify': len(blockers) == 0 and n1_ready,
        'blockers': blockers,
        'warnings': warnings,
        'checks': checks,
        'next_stage': 'intake_baseline' if not n1_ready else 'plan_verify',
    }


def gate_workspace_project(workspace: Path, project_id: Optional[str] = None) -> Dict[str, Any]:
    """Pick one project under workspace and run decompile readiness."""
    roots = discover_projects(Path(workspace))
    if not roots:
        return {'ready': False, 'blockers': [{'code': 'no_projects', 'message': 'No mini-program projects found'}]}
    root = roots[0]
    if project_id:
        matched = [r for r in roots if r.name == project_id]
        if matched:
            root = matched[0]
    report = check_decompile_readiness(root)
    report['selected_project'] = root.name
    return report
