# -*- coding: utf-8 -*-
"""Request-level fact recovery F_i for RR-Drift-aware static analysis."""
from __future__ import annotations

SCHEMA_VERSION = '1.0.0'

# F_i = <e_i, m_i, P_i, Π_i, κ_i, Θ_i>
REQUEST_FACT_KEYS = (
    'endpoint',          # e_i
    'method',            # m_i
    'params',            # P_i
    'provenance',        # Π_i
    'invocation_context',  # κ_i
    'transforms',        # Θ_i
)
