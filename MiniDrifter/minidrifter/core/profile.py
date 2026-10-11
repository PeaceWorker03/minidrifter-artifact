# -*- coding: utf-8 -*-
from __future__ import annotations
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List
from .utils import iter_files, normalize_rel, try_json


class ProjectProfileDetector:
    def __init__(self, root: Path):
        self.root = root
        self.files = iter_files(root)

    def run(self) -> Dict[str, Any]:
        suffix_counts = Counter(p.suffix or '<noext>' for p in self.files)
        has_app_config = (self.root / 'app-config.json').exists()
        has_app_json = (self.root / 'app.json').exists()
        has_app_service = any(p.name == 'app-service.js' for p in self.files)
        has_pages = (self.root / 'pages').exists()
        has_services = (self.root / 'services').exists()
        has_utils = (self.root / 'utils').exists()
        package_json = try_json(self.root / 'package.json') if (self.root / 'package.json').exists() else None
        deps = ' '.join((package_json or {}).get(k, {}) if isinstance((package_json or {}).get(k, {}), str) else ' '.join((package_json or {}).get(k, {}).keys()) for k in ['dependencies','devDependencies']) if package_json else ''
        frameworks = []
        for name in ['taro', 'uni-app', 'mpvue', 'wepy']:
            if name in deps.lower():
                frameworks.append(name)
        if has_app_service and not has_pages:
            shape = 'app_service_bundle'
        elif frameworks:
            shape = 'framework_compiled'
        elif has_app_config:
            shape = 'decompiled_config_based'
        elif has_app_json and has_pages:
            shape = 'source_like'
        else:
            shape = 'mixed_or_unknown'
        js_files = [p for p in self.files if p.suffix == '.js']
        short_names = 0
        total_names = 0
        for p in js_files[:200]:
            text = p.read_text(encoding='utf-8', errors='ignore')
            # rough signal: many single-letter vars/function params
            import re
            names = re.findall(r'\b(?:var|let|const)\s+([A-Za-z_$][\w$]*)\b', text)
            total_names += len(names)
            short_names += sum(1 for n in names if len(n) <= 2)
        obfuscation_score = round(short_names / total_names, 3) if total_names else 0.0
        if obfuscation_score > 0.55:
            obfuscation_level = 'high'
        elif obfuscation_score > 0.25:
            obfuscation_level = 'medium'
        else:
            obfuscation_level = 'low'
        return {
            'project_root': str(self.root),
            'shape': shape,
            'platform_guess': 'wechat' if has_app_json or has_app_config else 'unknown',
            'has_app_json': has_app_json,
            'has_app_config_json': has_app_config,
            'has_app_service_js': has_app_service,
            'has_pages_dir': has_pages,
            'has_services_dir': has_services,
            'has_utils_dir': has_utils,
            'framework_hints': frameworks,
            'file_count': len(self.files),
            'suffix_counts': dict(suffix_counts),
            'obfuscation': {
                'level': obfuscation_level,
                'score': obfuscation_score,
                'note': 'score is based on short local variable prevalence and should be treated as a rough signal'
            },
        }
