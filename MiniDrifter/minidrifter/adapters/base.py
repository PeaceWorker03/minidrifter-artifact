# -*- coding: utf-8
"""Adapter interfaces — app/framework differences inject here, not in core."""
from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List, Optional


class ProjectAdapter(ABC):
    """Detect project shape and extract static structure."""

    @abstractmethod
    def detect(self, project_root: Path) -> Dict[str, Any]:
        """Return shape, platform, obfuscation, readiness."""

    @abstractmethod
    def extract_pages(self, project_root: Path) -> List[Dict[str, Any]]:
        """Return page routes and subpackage hints."""

    @abstractmethod
    def extract_api_callsites(self, project_root: Path) -> List[Dict[str, Any]]:
        """Return raw API call sites for request adapter."""


class RequestAdapter(ABC):
    """Recover operations from wrapper patterns."""

    @abstractmethod
    def detect_wrapper(self, project_root: Path, output_dir: Path) -> Optional[Dict[str, Any]]:
        """Identify primary request wrapper."""

    @abstractmethod
    def recover_operation(self, callsite: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize one call site to method/path/params."""


class CryptoAdapter(ABC):
    """Crypto profile detection and replay construction."""

    @abstractmethod
    def detect_profile(self, output_dir: Path, source_dir: Optional[Path] = None) -> Dict[str, Any]:
        """Return crypto capability document."""

    @abstractmethod
    def build_request(
        self,
        template: Dict[str, Any],
        runtime_context: Dict[str, Any],
        *,
        source_dir: Optional[Path] = None,
    ) -> Dict[str, Any]:
        """Build replay-ready HTTP request."""


class RuntimeAdapter(ABC):
    """Parse user capture input and update runtime state."""

    @abstractmethod
    def parse_user_input(self, raw: str, *, source_dir: Optional[Path] = None) -> Dict[str, Any]:
        """Parse raw HTTP / HAR / etc."""

    @abstractmethod
    def update_object_pool(self, parsed: Dict[str, Any], pool: Dict[str, Any]) -> Dict[str, Any]:
        """Merge parsed fields into object pool."""
