# -*- coding: utf-8
"""Transport/path-family failure tracking — universal downrank for broken route families."""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set, Tuple


def path_family(path: str) -> str:
    """First two URL segments as family key, e.g. /User/List -> /User."""
    if not path:
        return '/'
    parts = [p for p in re.split(r'[/\\]+', path.strip()) if p]
    if not parts:
        return '/'
    if len(parts) == 1:
        return f'/{parts[0]}'
    return f'/{parts[0]}/{parts[1]}'


def domain_of(template: Optional[Dict[str, Any]], path: str = '') -> str:
    if template:
        return template.get('domain') or 'general'
    parts = [p for p in re.split(r'[/\\]+', path.strip()) if p]
    return parts[0].lower() if parts else 'general'


class TransportFamilyTracker:
    """Aggregate L1 transport failures by path family and domain."""

    def __init__(self) -> None:
        self.family_failures: Dict[str, int] = {}
        self.family_success: Dict[str, int] = {}
        self.domain_transport_failures: Dict[str, int] = {}
        self.blocked_families: Set[str] = set()
        self.blocked_domains: Set[str] = set()
        self._threshold = 2

    def record(
        self,
        *,
        path: str,
        domain: str,
        outcome: str,
        failure_class: Optional[str] = None,
    ) -> Dict[str, Any]:
        fam = path_family(path)
        transport_fc = failure_class in {
            'transport_error', 'transport_url_routing', 'build_failed',
        } or outcome in {'transport_error', 'build_failed', 'safety_blocked'}

        if outcome == 'business_success':
            self.family_success[fam] = self.family_success.get(fam, 0) + 1
            if fam in self.blocked_families and self.family_success[fam] >= 1:
                self.blocked_families.discard(fam)
            return {'family': fam, 'action': 'success'}

        if not transport_fc:
            return {'family': fam, 'action': 'ignored'}

        self.family_failures[fam] = self.family_failures.get(fam, 0) + 1
        self.domain_transport_failures[domain] = self.domain_transport_failures.get(domain, 0) + 1

        escalated = False
        if self.family_failures[fam] >= self._threshold:
            self.blocked_families.add(fam)
            escalated = True
        if self.domain_transport_failures[domain] >= self._threshold + 1:
            self.blocked_domains.add(domain)
            escalated = True

        return {
            'family': fam,
            'domain': domain,
            'failures': self.family_failures[fam],
            'family_blocked': fam in self.blocked_families,
            'domain_blocked': domain in self.blocked_domains,
            'escalated': escalated,
        }

    def penalty(self, path: str, domain: str = 'general') -> float:
        fam = path_family(path)
        pen = 0.0
        if fam in self.blocked_families:
            pen += 5.0
        elif self.family_failures.get(fam, 0) >= 1:
            pen += 1.5 * self.family_failures[fam]
        if domain in self.blocked_domains:
            pen += 3.0
        return pen

    def should_skip(self, path: str, domain: str = 'general') -> bool:
        fam = path_family(path)
        if fam in self.blocked_families and self.family_success.get(fam, 0) == 0:
            return True
        return domain in self.blocked_domains and self.domain_transport_failures.get(domain, 0) >= 4

    def healthy_domains(self) -> List[str]:
        all_domains = set(self.domain_transport_failures) | set(self.blocked_domains)
        return sorted(d for d in all_domains if d not in self.blocked_domains)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'family_failures': dict(self.family_failures),
            'family_success': dict(self.family_success),
            'blocked_families': sorted(self.blocked_families),
            'blocked_domains': sorted(self.blocked_domains),
            'domain_transport_failures': dict(self.domain_transport_failures),
        }
