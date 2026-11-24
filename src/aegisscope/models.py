from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


@dataclass(slots=True)
class Finding:
    check_id: str
    title: str
    severity: str
    confidence: str
    url: str
    description: str
    evidence: str
    remediation: str
    cwe: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ScanStats:
    pages_visited: int = 0
    requests_sent: int = 0
    urls_discovered: int = 0
    blocked_urls: int = 0
    errors: int = 0


@dataclass(slots=True)
class ScanResult:
    target: str
    started_at: str
    profile: str = "passive"
    completed_at: str = ""
    active_probes_used: bool = False
    findings: list[Finding] = field(default_factory=list)
    stats: ScanStats = field(default_factory=ScanStats)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "profile": self.profile,
            "active_probes_used": self.active_probes_used,
            "stats": asdict(self.stats),
            "findings": [finding.to_dict() for finding in self.findings],
        }
