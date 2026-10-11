# -*- coding: utf-8 -*-
"""Triple-string key mixer used by baselifeConfig / myCrypto getKey."""
from __future__ import annotations


def derive_triple_mix_key(key_a: str, key_b: str, key_c: str, *, upper: bool = True) -> str:
    """Reproduce JS x()/getKey() — 4 rounds of charCode mixing."""
    if not key_a or not key_b or not key_c:
        return ''
    u = len(key_a)
    if len(key_b) != u or len(key_c) != u:
        return ''

    e, n, r = key_a, key_b, key_c
    buckets = [e, n, r]
    for g in range(4):
        mixed: list[str] = []
        for d in range(u):
            s = ord(e[d]) + ord(n[d]) + ord(r[d])
            p = s % 3
            f = s % u
            mixed.append(buckets[p][f])
        if g == 0:
            buckets[0] = mixed
            e = ''.join(mixed)
        elif g == 1:
            buckets[1] = mixed
            n = ''.join(mixed)
        elif g == 2:
            buckets[2] = mixed
            r = ''.join(mixed)
        else:
            out = ''.join(mixed)
            return out.upper() if upper else out
    return ''
