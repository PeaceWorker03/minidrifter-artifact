# -*- coding: utf-8 -*-
"""Universal end-to-end MiniDrifter pack flow (static → crypto → baseline → verify)."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional

from minidrifter.orchestration.account_closed_loop import run_account_closed_loop


def run_unified_pack_flow(
    *,
    pack_dir: Path,
    project_root: Optional[Path] = None,
    capture_file: Optional[Path] = None,
    source_dir: Optional[Path] = None,
    skip_analyze: bool = False,
    mode: str = 'dry-run',
    max_http: int = 5,
    max_seeds: int = 2,
    materialize: bool = True,
    verify: bool = True,
    with_llm: bool = False,
) -> Dict[str, Any]:
    """One pipeline: analyze → intake → chain materialize → chain_strict verify."""
    result = run_account_closed_loop(
        pack_dir=pack_dir,
        project_root=project_root,
        capture_file=capture_file,
        source_dir=source_dir,
        skip_analyze=skip_analyze,
        mode=mode,
        max_http=max_http,
        materialize=materialize,
        verify=verify,
        with_llm=with_llm,
    )
    from minidrifter.core.utils import write_json
    write_json(pack_dir / 'unified_flow_report.json', result)
    return result
