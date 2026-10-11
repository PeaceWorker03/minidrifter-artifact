# -*- coding: utf-8 -*-
"""Load verification packs (field ontology, safety policy, oracle rules)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

PACKS_DIR = Path(__file__).resolve().parent / 'packs'
ORACLE_DIR = Path(__file__).resolve().parent / 'oracle_packs'


def _load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding='utf-8'))


def load_field_ontology() -> Dict[str, Any]:
    return _load_json(PACKS_DIR / 'field_ontology.json')


def load_safety_policy_pack() -> Dict[str, Any]:
    return _load_json(PACKS_DIR / 'safety_policy.json')


def load_oracle_pack(name: str = 'common') -> Dict[str, Any]:
    path = ORACLE_DIR / f'{name}.json'
    if not path.exists():
        return _load_json(ORACLE_DIR / 'common.json')
    return _load_json(path)


def _merge_oracle(base: Dict[str, Any], overlay: Dict[str, Any]) -> Dict[str, Any]:
    merged = dict(base)
    for key, val in overlay.items():
        if key in ('schema_version', 'description'):
            merged[key] = val
            continue
        if isinstance(val, list) and isinstance(merged.get(key), list):
            seen = set()
            combined = []
            for item in merged[key] + val:
                marker = json.dumps(item, sort_keys=True) if isinstance(item, (dict, list)) else item
                if marker in seen:
                    continue
                seen.add(marker)
                combined.append(item)
            merged[key] = combined
        elif isinstance(val, dict) and isinstance(merged.get(key), dict):
            merged[key] = {**merged[key], **val}
        else:
            merged[key] = val
    return merged


def load_oracle_for_profile(profile: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Merge common oracle + profile oracle_pack and/or inline response_oracle rules."""
    base = load_oracle_pack('common')
    if not profile:
        return base
    pack_name = profile.get('oracle_pack') or profile.get('response_oracle_pack')
    if pack_name:
        base = _merge_oracle(base, load_oracle_pack(str(pack_name)))
    inline = profile.get('response_oracle')
    if isinstance(inline, dict):
        base = _merge_oracle(base, inline)
    return base


def load_oracle_for_pack(pack_dir: Optional[Path] = None) -> Dict[str, Any]:
    """Load merged oracle using adapter_profile.json or shape-based profile resolution."""
    if not pack_dir:
        return load_oracle_pack('common')
    pack_dir = Path(pack_dir)
    adapter = _load_json(pack_dir / 'adapter_profile.json')
    if adapter and adapter.get('oracle_pack'):
        profile = {'oracle_pack': adapter['oracle_pack'], 'response_oracle': adapter.get('response_oracle')}
        return load_oracle_for_profile(profile)
    try:
        from minidrifter.adapters.pack_resolver import resolve_pack_profile
        return load_oracle_for_profile(resolve_pack_profile(pack_dir))
    except Exception:
        return load_oracle_pack('common')


def classify_field(name: str, ontology: Optional[Dict[str, Any]] = None) -> str:
    ontology = ontology or load_field_ontology()
    classes = ontology.get('field_classes') or {}
    for cls, names in classes.items():
        if name in names or name.lower() in {n.lower() for n in names}:
            return cls
    return 'ordinary_business_param'


def is_high_value_produce(field: str, ontology: Optional[Dict[str, Any]] = None) -> bool:
    ontology = ontology or load_field_ontology()
    targets = {f.lower() for f in (ontology.get('high_value_produces') or [])}
    return field.lower() in targets


def is_chain_bridge_field(field: str, ontology: Optional[Dict[str, Any]] = None) -> bool:
    ontology = ontology or load_field_ontology()
    targets = {f.lower() for f in (ontology.get('chain_bridge_fields') or [])}
    return field.lower() in targets


def chain_bridge_fields(ontology: Optional[Dict[str, Any]] = None) -> Set[str]:
    ontology = ontology or load_field_ontology()
    return set(ontology.get('chain_bridge_fields') or [])
