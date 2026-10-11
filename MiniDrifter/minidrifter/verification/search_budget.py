# -*- coding: utf-8 -*-
"""Search budget — HTTP + partitioned LLM pools for Apex/PBWS."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Literal

LLMPurpose = Literal['policy', 'chain', 'global']


@dataclass
class SearchBudget:
    max_http: int = 100
    max_seeds: int = 10
    max_depth: int = 5
    max_llm: int = 50
    used_http: int = 0
    seeds_used: int = 0
    used_llm: int = 0
    used_llm_policy: int = 0
    used_llm_chain: int = 0
    used_llm_global: int = 0
    deep_think: bool = False
    _policy_share: float = field(default=0.35, repr=False)
    _chain_share: float = field(default=0.50, repr=False)
    _global_share: float = field(default=0.15, repr=False)

    def consume(self, n: int = 1) -> bool:
        if self.used_http + n > self.max_http:
            return False
        self.used_http += n
        return True

    def _cap(self, purpose: LLMPurpose) -> int:
        if not self.deep_think:
            return self.max_llm if purpose == 'policy' else 0
        total = max(1, self.max_llm)
        shares = {
            'policy': self._policy_share,
            'chain': self._chain_share,
            'global': self._global_share,
        }
        return max(1, int(total * shares[purpose]))

    def _used_for(self, purpose: LLMPurpose) -> int:
        return {
            'policy': self.used_llm_policy,
            'chain': self.used_llm_chain,
            'global': self.used_llm_global,
        }[purpose]

    def llm_remaining(self, purpose: LLMPurpose) -> int:
        if not self.deep_think and purpose != 'policy':
            return 0
        return max(0, self._cap(purpose) - self._used_for(purpose))

    def consume_llm(self, purpose: LLMPurpose = 'policy') -> bool:
        if self.used_llm >= self.max_llm:
            return False
        if self.deep_think:
            if self._used_for(purpose) >= self._cap(purpose):
                return False
        elif purpose != 'policy':
            return False
        self.used_llm += 1
        if purpose == 'policy':
            self.used_llm_policy += 1
        elif purpose == 'chain':
            self.used_llm_chain += 1
        else:
            self.used_llm_global += 1
        return True

    def can_seed(self) -> bool:
        return self.seeds_used < self.max_seeds

    def to_dict(self) -> Dict[str, Any]:
        return {
            'max_http': self.max_http,
            'used_http': self.used_http,
            'http_remaining': max(0, self.max_http - self.used_http),
            'max_seeds': self.max_seeds,
            'seeds_used': self.seeds_used,
            'seeds_remaining': max(0, self.max_seeds - self.seeds_used),
            'max_depth': self.max_depth,
            'max_llm': self.max_llm,
            'used_llm': self.used_llm,
            'llm_remaining': max(0, self.max_llm - self.used_llm),
            'deep_think': self.deep_think,
            'llm_pools': {
                'policy': {'cap': self._cap('policy'), 'used': self.used_llm_policy},
                'chain': {'cap': self._cap('chain'), 'used': self.used_llm_chain},
                'global': {'cap': self._cap('global'), 'used': self.used_llm_global},
            },
        }
