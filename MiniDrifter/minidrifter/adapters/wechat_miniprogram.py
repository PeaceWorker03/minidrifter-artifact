# -*- coding: utf-8
"""WeChat mini-program project adapter."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

from minidrifter.adapters.base import ProjectAdapter
from minidrifter.core.profile import ProjectProfileDetector
from minidrifter.workspace.decompile_gate import classify_project_state


class WeChatProjectAdapter(ProjectAdapter):
    def detect(self, project_root: Path) -> Dict[str, Any]:
        root = Path(project_root)
        profile = ProjectProfileDetector(root).run()
        gate = classify_project_state(root)
        return {
            'adapter': 'wechat_miniprogram',
            'profile': profile,
            'ready': gate.get('state') == 'READY_DECOMPILED',
            'audit_state': gate.get('state'),
            'message': gate.get('message'),
        }

    def extract_pages(self, project_root: Path) -> List[Dict[str, Any]]:
        root = Path(project_root)
        pages: List[Dict[str, Any]] = []
        app_json = root / 'app.json'
        if app_json.exists():
            import json
            doc = json.loads(app_json.read_text(encoding='utf-8'))
            for p in doc.get('pages') or []:
                pages.append({'route': p, 'source': 'app.json'})
        return pages

    def extract_api_callsites(self, project_root: Path) -> List[Dict[str, Any]]:
        return []
