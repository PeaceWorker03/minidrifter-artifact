# -*- coding: utf-8 -*-
"""Extract wrapper crypto material from decompiled JS sources."""
from __future__ import annotations

import re
from typing import Optional

from minidrifter.runtime.crypto.aes_cfb_md5_wrapper import WrapperCryptoKeys

UTF8_PARSE_RE = re.compile(r'Utf8\.parse\("([^"]+)"\)')
MD5_AESKEY_RE = re.compile(r'md5_aeskey\s*[:=]\s*["\']([^"\']+)["\']')


def extract_wrapper_keys_from_js(text: str) -> Optional[WrapperCryptoKeys]:
    parses = UTF8_PARSE_RE.findall(text)
    if len(parses) < 3:
        return None
    md5_key = extract_md5_aeskey_from_snippets(text) or (parses[5] if len(parses) > 5 else parses[-1])
    return WrapperCryptoKeys(
        des_key=parses[0].encode() if len(parses) > 0 else b'',
        des_iv=parses[1].encode() if len(parses) > 1 else b'',
        aes_key=parses[2].encode(),
        aes_iv=(parses[5] if len(parses) > 5 else parses[min(4, len(parses) - 1)]).encode(),
        md5_aeskey=md5_key,
    )


def extract_md5_aeskey_from_snippets(text: str) -> Optional[str]:
    m = MD5_AESKEY_RE.search(text)
    return m.group(1) if m else None
