# -*- coding: utf-8 -*-
"""Unified Apex-PoC search configuration."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class ApexSearchConfig:
    mode: str = 'dry-run'
    only_safe: bool = True
    max_http: int = 250
    max_seeds: int = 50
    max_depth: int = 5
    max_llm: int = 80
    beam_width: int = 5
    ig_threshold: float = 0.25
    ig_prune: bool = True
    policy_interval: int = 8
    with_llm_policy: bool = False
    with_llm_chain: bool = False
    deep_think: bool = False
    llm_dry_run: bool = False
    with_mutations: bool = True
    skip_preflight: bool = False
    anchor_api_id: Optional[str] = None
    verbose: bool = True
    source_dir: Optional[Path] = None
    base_url: Optional[str] = None

    def resolved_llm_chain(self) -> bool:
        """Chain/workflow LLM: explicit chain flag, --with-llm, or deep_think + policy."""
        if self.with_llm_chain:
            return True
        return bool(self.with_llm_policy)

    def resolved_policy_interval(self) -> int:
        if self.deep_think and self.policy_interval == 8:
            return 5
        return self.policy_interval

    @classmethod
    def from_cli(
        cls,
        *,
        mode: str = 'dry-run',
        only_safe: bool = True,
        max_http: int = 250,
        max_seeds: int = 50,
        max_depth: int = 5,
        max_llm: int = 80,
        beam_width: int = 5,
        ig_threshold: float = 0.25,
        ig_prune: bool = True,
        with_llm: bool = False,
        with_llm_policy: bool = False,
        with_llm_chain: bool = False,
        deep_think: bool = False,
        llm_dry_run: bool = False,
        with_mutations: bool = True,
        skip_preflight: bool = False,
        anchor_api_id: Optional[str] = None,
        verbose: bool = True,
        source_dir: Optional[Path] = None,
        base_url: Optional[str] = None,
    ) -> 'ApexSearchConfig':
        policy = with_llm or with_llm_policy
        chain = with_llm_chain or with_llm or (deep_think and policy)
        return cls(
            mode=mode,
            only_safe=only_safe,
            max_http=max_http,
            max_seeds=max_seeds,
            max_depth=max_depth,
            max_llm=max_llm,
            beam_width=beam_width,
            ig_threshold=ig_threshold,
            ig_prune=ig_prune,
            with_llm_policy=policy,
            with_llm_chain=chain,
            deep_think=deep_think,
            llm_dry_run=llm_dry_run,
            with_mutations=with_mutations,
            skip_preflight=skip_preflight,
            anchor_api_id=anchor_api_id,
            verbose=verbose,
            source_dir=source_dir,
            base_url=base_url,
        )
