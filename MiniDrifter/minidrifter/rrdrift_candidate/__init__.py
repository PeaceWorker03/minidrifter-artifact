# -*- coding: utf-8 -*-
"""RR-Drift static candidate recovery for E1 (Field + Relation).

Implements paper §5.2 role recovery (C_i^bind) and §5.3 evidence-backed
relations. Internal RPGraph edges may be wider; this module emits
only output Candidate Field / Relation sets.
"""
from .recover import recover_crbd_candidates, write_crbd_candidates

__all__ = ["recover_crbd_candidates", "write_crbd_candidates"]
