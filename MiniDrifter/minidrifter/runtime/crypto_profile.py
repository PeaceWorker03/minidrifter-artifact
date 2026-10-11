# -*- coding: utf-8 -*-
"""Backward-compatible re-exports — crypto detection lives in runtime.crypto.registry."""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from minidrifter.runtime.crypto.aes_cfb_md5_wrapper import AesCfbMd5WrapperEngine
from minidrifter.runtime.crypto.registry import (
    CryptoCapability,
    get_crypto_engine_for_pack,
    load_crypto_capability,
    normalize_profile_id,
)

__all__ = [
    'CryptoCapability',
    'load_crypto_capability',
    'get_crypto_engine',
    'get_crypto_engine_for_pack',
    'normalize_profile_id',
]


def get_crypto_engine(
    capability: CryptoCapability,
    *,
    output_dir: Optional[Path] = None,
    source_dir: Optional[Path] = None,
) -> Optional[AesCfbMd5WrapperEngine]:
    if not output_dir:
        return None
    engine, _ = get_crypto_engine_for_pack(Path(output_dir), source_dir=source_dir)
    return engine
