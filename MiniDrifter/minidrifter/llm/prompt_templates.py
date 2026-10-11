# -*- coding: utf-8 -*-
"""Prompt templates reserved for later LLM-assisted semantic enrichment.

The static layer should produce deterministic facts. LLM calls should consume API Cards and Replay
Contracts, not raw source trees.
"""

API_SEMANTIC_CLASSIFIER = """
You are given a MiniDrifter API Card extracted from a decompiled mini-program.
Classify the business domain, credential roles, and safe validation strategy.
Return strict JSON only.

API Card:
{api_card_json}
"""

REPLAY_SKELETON_GENERATOR = """
You are given a MiniDrifter Replay Contract and source snippets of crypto functions.
Generate a conservative Node.js replay skeleton that mutates only plain-stage parameters and recomputes required transforms.
Do not generate enumeration or destructive actions.
Return code only.

Replay Contract:
{replay_contract_json}
"""
