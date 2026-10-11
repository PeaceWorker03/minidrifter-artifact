# -*- coding: utf-8 -*-
from __future__ import annotations
import re
from pathlib import Path
from typing import Any, Dict, List
from minidrifter.core.utils import normalize_rel, read_text


class ModuleAliasResolver:
    """Lightweight alias recovery for decompiled mini-program JS.

    It does not try to be a complete JS interpreter. It recovers the stable aliases we need:
    require aliases, getApp aliases, getApp().url aliases, and HTTP wrapper method aliases.
    """
    REQUIRE_RE = re.compile(r'\b(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*require\(["\']([^"\']+)["\']\)')
    DESTRUCT_RE = re.compile(r'\b(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*([A-Za-z_$][\w$]*)\.([A-Za-z_$][\w$]*)')
    GETAPP_RE = re.compile(r'\b(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*getApp\(\)')
    URL_ALIAS_RE = re.compile(r'\b(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*([A-Za-z_$][\w$]*)\.url\b')
    ASSIGN_URL_ALIAS_RE = re.compile(r'\b([A-Za-z_$][\w$]*)\s*=\s*([A-Za-z_$][\w$]*)\.url\b')

    def __init__(self, root: Path):
        self.root = root

    def _resolve_require_path(self, file: Path, req: str) -> str:
        if req.startswith('.'):
            base = (file.parent / req).resolve()
            for cand in [base, base.with_suffix('.js'), base / 'index.js']:
                if cand.exists():
                    return normalize_rel(cand, self.root)
        return req

    def run(self) -> Dict[str, Any]:
        by_file: Dict[str, Dict[str, Any]] = {}
        for js in self.root.rglob('*.js'):
            text = read_text(js)
            rel = normalize_rel(js, self.root)
            aliases: Dict[str, str] = {}
            require_aliases: Dict[str, str] = {}
            app_aliases: List[str] = []
            url_aliases: List[str] = []
            for m in self.REQUIRE_RE.finditer(text):
                alias, req = m.group(1), m.group(2)
                resolved = self._resolve_require_path(js, req)
                aliases[alias] = f"require:{resolved}"
                require_aliases[alias] = resolved
                aliases[f'{alias}.default'] = f"require:{resolved}:default"
            for m in self.GETAPP_RE.finditer(text):
                alias = m.group(1)
                aliases[alias] = 'getApp()'
                app_aliases.append(alias)
            for regex in [self.URL_ALIAS_RE, self.ASSIGN_URL_ALIAS_RE]:
                for m in regex.finditer(text):
                    alias, base = m.group(1), m.group(2)
                    if aliases.get(base) == 'getApp()' or base in app_aliases:
                        aliases[alias] = 'getApp().url'
                        url_aliases.append(alias)
            # transitive destructuring/aliasing: var u = t.default; var h = app.url;
            changed = True
            rounds = 0
            while changed and rounds < 3:
                changed = False
                rounds += 1
                for m in self.DESTRUCT_RE.finditer(text):
                    alias, base, prop = m.group(1), m.group(2), m.group(3)
                    val = aliases.get(base)
                    if val:
                        new_val = f'{val}.{prop}'
                        if aliases.get(alias) != new_val:
                            aliases[alias] = new_val
                            changed = True
                            if new_val == 'getApp().url':
                                url_aliases.append(alias)
            by_file[rel] = {
                'aliases': aliases,
                'require_aliases': require_aliases,
                'getapp_aliases': sorted(set(app_aliases)),
                'url_aliases': sorted(set(url_aliases)),
            }
        return {'files': by_file}
