# -*- coding: utf-8 -*-
from __future__ import annotations
import re
from pathlib import Path
from typing import Any, Dict, List
from minidrifter.core.patterns import CRYPTO_KEYS, PLATFORM_APIS
from minidrifter.core.utils import line_no, normalize_rel, read_text, short_snippet, stable_id


class RequestWrapperAnalyzer:
    METHOD_RE = re.compile(r'\b(?:function\s+([A-Za-z_$][\w$]*)|([A-Za-z_$][\w$]*)\s*[:=]\s*function|([A-Za-z_$][\w$]*)\s*[:=]\s*\([^)]*\)\s*=>)')

    def __init__(self, root: Path, platform: str = 'wechat'):
        self.root = root
        self.platform = platform

    def run(self) -> List[Dict[str, Any]]:
        wrappers = []
        req_apis = PLATFORM_APIS.get(self.platform, PLATFORM_APIS['wechat'])['request']
        for js in self.root.rglob('*.js'):
            rel = normalize_rel(js, self.root)
            text = read_text(js)
            lower_name = js.name.lower()
            file_hint = any(k in lower_name for k in ['http', 'request', 'network', 'api', 'gateway', 'fetch'])
            calls_platform = any(api in text for api in req_apis)
            method_names = set()
            for name in ['get', 'post', 'put', 'delete', 'request', 'fetch']:
                if re.search(r'\b' + re.escape(name) + r'\s*[:=]\s*(?:function|\([^)]*\)\s*=>|[A-Za-z_$])', text) or re.search(r'\bfunction\s+' + name + r'\s*\(', text):
                    method_names.add(name)
            crypto_hits = sorted(set(m.group(0) for m in CRYPTO_KEYS.finditer(text)))[:40]
            header_hits = sorted(set(re.findall(r'\b(Token|Authorization|AppIdentity|Appidentity|TimeSpan|timestamp|nonce|sign|signature)\b', text, re.I)))
            if calls_platform or (file_hint and (method_names or crypto_hits or header_hits)):
                idx = min([text.find(api) for api in req_apis if api in text] + [0])
                wrappers.append({
                    'wrapper_id': stable_id('wrap', rel),
                    'file': rel,
                    'file_hint': file_hint,
                    'calls_platform_request': calls_platform,
                    'platform_request_apis': [api for api in req_apis if api in text],
                    'exported_or_defined_methods': sorted(method_names),
                    'header_hints': header_hits,
                    'crypto_hints': crypto_hits,
                    'likely_url_params': sorted(set(re.findall(r'\b(url|requestUrl|api|path)\b', text)))[:20],
                    'likely_data_params': sorted(set(re.findall(r'\b(data|params|query|body|formData)\b', text)))[:20],
                    'evidence': {'file': rel, 'line': line_no(text, idx), 'snippet': short_snippet(text, idx, 600)},
                })
        return wrappers
