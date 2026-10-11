# -*- coding: utf-8 -*-
from __future__ import annotations
import re
from pathlib import Path
from typing import Any, Dict, List
from minidrifter.core.patterns import DATA_ATTR_RE, EVENT_ATTR_RE, TAG_RE, TEXT_CLEAN_RE
from minidrifter.core.utils import line_no, normalize_rel, read_text, short_snippet, stable_id


class WxmlEventExtractor:
    def __init__(self, root: Path):
        self.root = root

    def run(self) -> List[Dict[str, Any]]:
        events = []
        for wxml in self.root.rglob('*.wxml'):
            text = read_text(wxml)
            rel = normalize_rel(wxml, self.root)
            page = rel[:-5] if rel.endswith('.wxml') else rel
            for tag_m in TAG_RE.finditer(text):
                tag = tag_m.group(1)
                attrs = tag_m.group(2) or ''
                data = {m.group(1): m.group(2) for m in DATA_ATTR_RE.finditer(attrs)}
                nearby = short_snippet(text, tag_m.start(), 240)
                component_text = TEXT_CLEAN_RE.sub('', nearby).strip()[:80]
                for ev_m in EVENT_ATTR_RE.finditer(attrs):
                    prefix, ev_type, handler = ev_m.group(1), ev_m.group(2), ev_m.group(3)
                    if not handler or handler.startswith('{{'):
                        continue
                    event_id = stable_id('evt', rel, str(tag_m.start()), ev_type, handler)
                    events.append({
                        'event_id': event_id,
                        'page': page,
                        'event_type': prefix + ev_type,
                        'handler': handler,
                        'tag': tag,
                        'dataset': data,
                        'component_text': component_text,
                        'source': {
                            'file': rel,
                            'line': line_no(text, tag_m.start()),
                            'snippet': nearby,
                        },
                    })
        return events
