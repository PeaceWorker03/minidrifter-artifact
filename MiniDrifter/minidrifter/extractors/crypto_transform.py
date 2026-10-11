# -*- coding: utf-8 -*-
from __future__ import annotations
import re
from pathlib import Path
from typing import Any, Dict, List
from minidrifter.core.patterns import CRYPTO_KEYS
from minidrifter.core.utils import line_no, normalize_rel, read_text, short_snippet, stable_id


class CryptoTransformAnalyzer:
    FUNC_HEAD_RE = re.compile(r'(?:function\s+([A-Za-z_$][\w$]*)\s*\([^)]*\)|([A-Za-z_$][\w$]*)\s*[:=]\s*function\s*\([^)]*\)|([A-Za-z_$][\w$]*)\s*[:=]\s*\([^)]*\)\s*=>)')

    def __init__(self, root: Path):
        self.root = root

    def _infer(self, name: str, snippet: str) -> Dict[str, Any]:
        s = f'{name} {snippet}'.lower()
        if 'decrypt' in s or 'decode' in s and 'response' in s:
            operation = 'decrypt'
            direction = 'response'
        elif 'encrypt' in s or 'encode' in s or 'aes' in s or 'des' in s:
            operation = 'encrypt'
            direction = 'request'
        elif 'sign' in s or 'authorization' in s or 'appidentity' in s or 'md5' in s or 'sha' in s:
            operation = 'sign_or_header_transform'
            direction = 'request'
        else:
            operation = 'crypto_related'
            direction = 'unknown'
        if any(k in s for k in ['header', 'authorization', 'appidentity', 'token', 'timespan']):
            stage = 'header'
        elif any(k in s for k in ['response', 'decrypt', 'res.data']):
            stage = 'response_body'
        elif any(k in s for k in ['query', 'params']):
            stage = 'query'
        elif 'body' in s or 'data' in s:
            stage = 'body'
        else:
            stage = 'unknown'
        algos = sorted(set(a.upper() for a in re.findall(r'\b(AES|DES|RSA|MD5|SHA1|SHA256|HMAC|BASE64|CryptoJS)\b', snippet, re.I)))
        outputs = []
        for h in ['Authorization', 'AppIdentity', 'Appidentity', 'Token', 'TimeSpan', 'sign', 'query', 'body', 'data']:
            if re.search(r'\b' + re.escape(h) + r'\b', snippet, re.I):
                outputs.append(h)
        return {'operation': operation, 'direction': direction, 'stage': stage, 'algorithm_hints': algos, 'output_hints': sorted(set(outputs))}

    def run(self) -> List[Dict[str, Any]]:
        cards = []
        for js in self.root.rglob('*.js'):
            text = read_text(js)
            if not CRYPTO_KEYS.search(text):
                continue
            rel = normalize_rel(js, self.root)
            # function-level candidates
            for m in self.FUNC_HEAD_RE.finditer(text):
                name = next(g for g in m.groups() if g) if any(m.groups()) else '<anonymous>'
                snippet = short_snippet(text, m.start(), 500)
                if not CRYPTO_KEYS.search(snippet):
                    continue
                info = self._infer(name, snippet)
                cards.append({
                    'crypto_id': stable_id('crypto', rel, name, m.start()),
                    'file': rel,
                    'function': name,
                    **info,
                    'input_hints': sorted(set(re.findall(r'\b(url|params|query|body|data|Token|TimeSpan|timestamp|nonce|key|iv|secret)\b', snippet, re.I))),
                    'used_by': [],
                    'evidence': {'file': rel, 'line': line_no(text, m.start()), 'snippet': snippet},
                })
            # if no function candidate, still capture file-level snippets around crypto keywords
            if not any(c['file'] == rel for c in cards):
                for km in CRYPTO_KEYS.finditer(text):
                    snippet = short_snippet(text, km.start(), 500)
                    info = self._infer('<file_scope>', snippet)
                    cards.append({
                        'crypto_id': stable_id('crypto', rel, km.group(0), km.start()),
                        'file': rel,
                        'function': '<file_scope>',
                        **info,
                        'input_hints': sorted(set(re.findall(r'\b(url|params|query|body|data|Token|TimeSpan|timestamp|nonce|key|iv|secret)\b', snippet, re.I))),
                        'used_by': [],
                        'evidence': {'file': rel, 'line': line_no(text, km.start()), 'snippet': snippet},
                    })
                    break
        # de-dup strongly similar cards
        seen, out = set(), []
        for c in cards:
            key = (c['file'], c['function'], c['operation'], c['stage'])
            if key not in seen:
                seen.add(key); out.append(c)
        return out
