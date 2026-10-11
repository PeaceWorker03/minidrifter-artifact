#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MiniDrifter 向导入口 — 从 MiniDrifter/ 或仓库根目录运行均可。"""
from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent  # MiniDrifter/
REPO_ROOT = ROOT.parent                 # Fse/
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if Path.cwd().resolve() != REPO_ROOT and (REPO_ROOT / 'Workspace').is_dir():
    os.chdir(REPO_ROOT)

from minidrifter.orchestration.console.app import main

if __name__ == '__main__':
    main(default_workspace=str(REPO_ROOT / 'Workspace'))
