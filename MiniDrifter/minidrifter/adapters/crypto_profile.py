# -*- coding: utf-8
"""Crypto adapter delegating to runtime/crypto registry."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional

from minidrifter.adapters.base import CryptoAdapter
from minidrifter.runtime.crypto.registry import get_crypto_engine_for_pack, load_crypto_capability


class PackCryptoAdapter(CryptoAdapter):
    def __init__(self, profile: Dict[str, Any] | None = None) -> None:
        self._profile = profile or {}

    def detect_profile(self, output_dir: Path, source_dir: Optional[Path] = None) -> Dict[str, Any]:
        cap = load_crypto_capability(Path(output_dir), source_dir=source_dir)
        doc = cap.to_dict() if hasattr(cap, 'to_dict') else {
            'profile_id': cap.profile_id,
            'can_replay': cap.can_replay,
            'can_decrypt': cap.can_decrypt,
            'md5_aeskey': cap.md5_aeskey,
            'reason': cap.reason,
        }
        pid = doc.get('profile_id')
        if pid:
            from minidrifter.adapters.registry import load_crypto_profile
            pack_prof = load_crypto_profile(pid)
            doc['pack_meta'] = pack_prof
        return doc

    def build_request(
        self,
        template: Dict[str, Any],
        runtime_context: Dict[str, Any],
        *,
        source_dir: Optional[Path] = None,
    ) -> Dict[str, Any]:
        pack_dir = Path(template.get('pack_dir') or runtime_context.get('pack_dir') or '.')
        engine, _cap = get_crypto_engine_for_pack(pack_dir, source_dir=source_dir)
        if not engine:
            return {'build_status': 'unsupported', 'reason': 'no_crypto_engine'}
        return {'build_status': 'delegated', 'engine': type(engine).__name__}
