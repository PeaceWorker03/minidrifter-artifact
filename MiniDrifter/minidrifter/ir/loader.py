# -*- coding: utf-8
"""Load Universal IR bundle for verification engine consumption."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from minidrifter.ir.chain_agent import build_hypothesis_from_seed, match_chain_template
from minidrifter.ir.constants import IR_VERSION
from minidrifter.ir.export import export_universal_ir


def _read_json(path: Path) -> Any:
    if path.exists():
        return json.loads(path.read_text(encoding='utf-8'))
    return None


class UniversalIRSession:
    """In-memory Universal IR view for one verification pack."""

    def __init__(self, pack_dir: Path, *, auto_export: bool = True) -> None:
        self.pack_dir = Path(pack_dir)
        self.ir_dir = self.pack_dir / 'universal_ir'
        bundle_path = self.ir_dir / 'universal_ir_bundle.json'
        if auto_export and not bundle_path.exists():
            export_universal_ir(self.pack_dir)
        self._load()

    def _load(self) -> None:
        self.bundle = _read_json(self.ir_dir / 'universal_ir_bundle.json') or {}
        api_doc = _read_json(self.ir_dir / 'universal_api_cards.json') or {}
        self.api_cards: List[Dict[str, Any]] = api_doc.get('items') or []
        self.api_by_id: Dict[str, Dict[str, Any]] = {
            c['api_id']: c for c in self.api_cards if c.get('api_id')
        }
        self.api_by_path: Dict[str, Dict[str, Any]] = {
            c['path']: c for c in self.api_cards if c.get('path')
        }

        obj = _read_json(self.ir_dir / 'universal_object_model.json') or {}
        self.object_model = obj

        ch_doc = _read_json(self.ir_dir / 'universal_chain_hypotheses.json') or {}
        self.chain_hypotheses: List[Dict[str, Any]] = ch_doc.get('items') or []

        live_doc = _read_json(self.ir_dir / 'universal_chain_hypotheses_live.json') or {}
        self.chain_hypotheses_live: List[Dict[str, Any]] = live_doc.get('items') or []
        self._live_seed_scores: Dict[str, float] = self._build_live_seed_scores()

        tk_doc = _read_json(self.ir_dir / 'universal_feedback_tickets.json') or {}
        self.feedback_tickets: List[Dict[str, Any]] = tk_doc.get('items') or []

        n_doc = _read_json(self.ir_dir / 'universal_n_tier_summary.json') or {}
        self.n_tier_distribution = n_doc.get('distribution') or {}

        self.profile_id = self.bundle.get('profile_id') or 'default'
        self._seed_order = self._build_seed_order()

    def _build_seed_order(self) -> List[str]:
        """Priority: producers with binding risk, then N1-object, then consumers."""
        scored: List[tuple[float, str]] = []
        for api_id, card in self.api_by_id.items():
            tier = (card.get('runtime_tier') or {}).get('tier') or ''
            role = card.get('api_role') or 'unknown'
            side = card.get('side_effect_level') or 'S3'
            score = 0.0
            if role == 'producer':
                score += 3.0
            if role == 'consumer':
                score += 1.5
            if tier == 'N1-object':
                score += 2.0
            elif tier == 'N1-auth':
                score += 2.5
            elif tier == 'N0':
                score += 2.5
            elif tier == 'N1-capability':
                score -= 1.0
            elif tier == 'N1-state':
                score -= 2.0
            if side in {'S0', 'S1'}:
                score += 1.0
            if tier == 'N3-audit-only':
                score -= 5.0
            score += float(card.get('confidence') or 0) * 0.5
            scored.append((score, api_id))
        scored.sort(reverse=True)
        return [aid for _, aid in scored]

    def _build_live_seed_scores(self) -> Dict[str, float]:
        scores: Dict[str, float] = {}
        for ch in self.chain_hypotheses_live:
            nodes = ch.get('nodes') or []
            seed = nodes[0] if nodes else {}
            api_id = seed.get('api_id') or ''
            if not api_id:
                continue
            status = ch.get('status') or ''
            depth = len(nodes)
            score = float(ch.get('confidence') or 0.5)
            if status == 'active':
                score += 2.0
            elif status == 'quarantined':
                score += 0.5
            score += min(depth, 5) * 0.3
            scores[api_id] = max(scores.get(api_id, 0.0), score)
        return scores

    def live_priority_boost(self, api_id: str) -> float:
        return round(self._live_seed_scores.get(api_id, 0.0) * 0.4, 4)

    def get_api(self, api_id: str) -> Optional[Dict[str, Any]]:
        return self.api_by_id.get(api_id)

    def get_api_for_path(self, path: str) -> Optional[Dict[str, Any]]:
        return self.api_by_path.get(path)

    def priority_boost(self, api_id: str) -> float:
        """IR-based priority delta for atomic scheduler."""
        card = self.get_api(api_id)
        if not card:
            try:
                idx = self._seed_order.index(api_id)
                return max(0.0, 2.0 - idx * 0.02)
            except ValueError:
                return 0.0
        boost = 0.0
        tier = (card.get('runtime_tier') or {}).get('tier') or ''
        role = card.get('api_role') or ''
        if role == 'producer':
            boost += 1.2
        if role == 'capability_issuer':
            boost += 0.8
        if tier == 'N1-object':
            boost += 1.0
        if tier == 'N1-auth':
            boost += 1.5
        if tier == 'N0':
            boost += 1.5
        if tier == 'N1-state':
            boost -= 1.5
        if tier == 'N1-capability':
            boost -= 1.0
        if tier == 'N3-audit-only':
            boost -= 3.0
        if card.get('side_effect_level') in {'S0', 'S1'}:
            boost += 0.5
        boost += self.live_priority_boost(api_id)
        try:
            idx = self._seed_order.index(api_id)
            boost += max(0.0, 1.5 - idx * 0.015)
        except ValueError:
            pass
        return round(boost, 4)

    def seed_candidates(self, *, limit: int = 50) -> List[str]:
        return self._seed_order[:limit]

    def open_ticket_summary(self) -> List[Dict[str, Any]]:
        return [t for t in self.feedback_tickets if t.get('status') == 'open']

    def chain_hypothesis_for_seed(self, api_id: str) -> Optional[Dict[str, Any]]:
        card = self.get_api(api_id)
        path = (card or {}).get('path') or ''
        for ch in self.chain_hypotheses:
            if ch.get('chain_id') == f'hyp_{api_id}':
                return ch
            producers = ch.get('producer_candidates') or []
            if path and path in producers:
                return ch
        if card:
            return build_hypothesis_from_seed(card, chain_id=f'hyp_{api_id}')
        return None

    def next_hypothesis_hop(
        self,
        seed_api_id: str,
        *,
        chain_nodes: List[Dict[str, Any]],
        available_fields: Set[str],
        templates_by_id: Dict[str, Any],
        exclude_apis: Set[str],
    ) -> Optional[Dict[str, Any]]:
        """Next consumer from IR hypothesis sequence when fields satisfy requires."""
        from minidrifter.verification.frontier_expander import (
            _field_set_satisfied,
            get_required_business_fields,
        )
        from minidrifter.verification.graph_loader import load_workflow_graph

        hyp = self.chain_hypothesis_for_seed(seed_api_id)
        if not hyp:
            return None
        tested = {n.get('api_id') for n in chain_nodes if n.get('api_id')}
        candidates: List[str] = []
        for path in (hyp.get('consumer_candidates') or []):
            card = self.get_api_for_path(path)
            if card and card.get('api_id'):
                candidates.append(card['api_id'])
        graph = load_workflow_graph(self.pack_dir) or {}
        for api_id in candidates:
            if api_id in tested or api_id in exclude_apis:
                continue
            tpl = templates_by_id.get(api_id)
            if not tpl or tpl.get('status') != 'materialized_with_crypto_profile':
                continue
            required = get_required_business_fields(graph, api_id)
            if required and not _field_set_satisfied(available_fields, required):
                continue
            card = self.get_api(api_id) or {}
            return {
                'api_id': api_id,
                'path': card.get('path') or tpl.get('path'),
                'template': tpl,
                'required': sorted(required),
                'hypothesis_id': hyp.get('chain_id'),
                'source': 'ir_hypothesis_sequence',
            }
        return None

    def ir_candidates_for_chain(
        self,
        *,
        domain: str,
        available_fields: Set[str],
        templates_by_id: Dict[str, Any],
        exclude_apis: Set[str],
    ) -> List[Dict[str, Any]]:
        """Suggest next-hop APIs from Universal IR (producer→consumer patterns)."""
        from minidrifter.verification.frontier_expander import (
            _field_set_satisfied,
            get_required_business_fields,
        )
        from minidrifter.verification.graph_loader import load_workflow_graph

        graph = load_workflow_graph(self.pack_dir) or {}
        candidates: List[Dict[str, Any]] = []
        for api_id, card in self.api_by_id.items():
            if api_id in exclude_apis:
                continue
            if card.get('business_domain') not in {domain, 'general'}:
                continue
            tpl = templates_by_id.get(api_id)
            if not tpl or tpl.get('status') != 'materialized_with_crypto_profile':
                continue
            role = card.get('api_role') or ''
            if role not in {'consumer', 'producer', 'capability_issuer'}:
                continue
            tier = (card.get('runtime_tier') or {}).get('tier') or ''
            if tier == 'N3-audit-only':
                continue
            required = get_required_business_fields(graph, api_id)
            if required and not _field_set_satisfied(available_fields, required):
                continue
            score = self.priority_boost(api_id)
            if role == 'consumer':
                score += 0.5
            candidates.append({
                'api_id': api_id,
                'path': card.get('path'),
                'template': tpl,
                'domain': card.get('business_domain') or domain,
                'ir_score': score,
                'chain_type': match_chain_template(card) or {},
                'source': 'universal_ir',
            })
        candidates.sort(key=lambda x: x.get('ir_score', 0), reverse=True)
        return candidates[:15]

    def object_pool_hints(self) -> Dict[str, List[str]]:
        hints: Dict[str, List[str]] = {}
        for bucket in (
            'subject_credential', 'business_object', 'capability_credential',
            'session_credential', 'environment_context',
        ):
            items = self.object_model.get(bucket) or []
            hints[bucket] = [i.get('name') for i in items if i.get('name')]
        return hints

    def to_search_context(self) -> Dict[str, Any]:
        return {
            'ir_version': IR_VERSION,
            'profile_id': self.profile_id,
            'api_count': len(self.api_cards),
            'n_tier_distribution': self.n_tier_distribution,
            'open_tickets': len(self.open_ticket_summary()),
            'chain_hypotheses': len(self.chain_hypotheses),
            'chain_hypotheses_live': len(self.chain_hypotheses_live),
            'object_field_count': self.object_model.get('field_count') or 0,
            'top_seeds': self.seed_candidates(limit=10),
        }

    def persist_runtime_chains(self, chains: List[Dict[str, Any]]) -> Path:
        """Append live chain state back to universal IR."""
        out = self.ir_dir / 'universal_chain_hypotheses_live.json'
        doc = {
            'ir_version': IR_VERSION,
            'generated_at': self.bundle.get('generated_at'),
            'count': len(chains),
            'items': chains,
        }
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding='utf-8')
        return out


def load_universal_ir(pack_dir: Path, *, auto_export: bool = True) -> UniversalIRSession:
    return UniversalIRSession(pack_dir, auto_export=auto_export)
