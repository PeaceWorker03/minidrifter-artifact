# -*- coding: utf-8 -*-
"""Export validated LLM proposals as placeholder replay scripts (not auto-executed)."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


def _utc_now() -> str:
    from datetime import timezone
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


SCRIPT_TEMPLATE = '''# MiniDrifter LLM-assisted replay script (placeholders — fill from baseline_runtime_context)
# proposal_id: {proposal_id}
# mutation: {mutation_type}
# rationale: {rationale}
# AUTHORITY: advisory only — run through: python -m minidrifter.cli run-campaign

import os

BASE_URL = os.environ.get("MiniDrifter_BASE_URL", "{base_url}")
TOKEN = os.environ.get("MiniDrifter_TOKEN", "")
USER_ID = os.environ.get("MiniDrifter_USER_ID", "")

# Use CLI for crypto signing:
# python -m minidrifter.cli crypto-replay -i {pack_dir} \\
#   --path "{path}" --params "{params_hint}" --source-dir $MiniDrifter_SOURCE_DIR

print("Script hint only. Execute via guarded MiniDrifter CLI, not raw requests.")
'''


def write_proposal_scripts(
    pack_dir: Path,
    proposals: List[Dict[str, Any]],
    test_cases_by_parent: Dict[str, Dict[str, Any]],
    *,
    base_url: str = 'https://HOST_FROM_BASELINE',
) -> List[str]:
    out_dir = Path(pack_dir) / 'llm_test_scripts'
    out_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for prop in proposals:
        parent = test_cases_by_parent.get(prop.get('parent_test_id') or '')
        if not parent:
            continue
        params = dict(parent.get('params') or {})
        params.update(prop.get('param_overrides') or {})
        params_hint = '&'.join(f'{k}={v}' for k, v in params.items())
        content = SCRIPT_TEMPLATE.format(
            proposal_id=prop.get('proposal_id'),
            mutation_type=prop.get('mutation_type'),
            rationale=(prop.get('rationale') or '')[:200],
            base_url=base_url,
            pack_dir=str(pack_dir),
            path=parent.get('path'),
            params_hint=params_hint,
        )
        path = out_dir / f"{prop.get('proposal_id', 'prop')}.py"
        path.write_text(content, encoding='utf-8')
        written.append(str(path))
    return written
