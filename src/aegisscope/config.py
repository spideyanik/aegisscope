from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .scope import ScopeError, ScopePolicy, normalize_url


@dataclass(slots=True)
class ScanConfig:
    target: str
    allowed_hosts: list[str]
    authorization_owner: str
    authorization_reference: str
    allow_subdomains: bool = False
    allowed_schemes: list[str] = field(default_factory=lambda: ["https"])
    active_probes: bool = False
    reconnaissance: bool = True
    max_pages: int = 50
    max_requests: int = 150
    requests_per_second: float = 2.0
    timeout_seconds: float = 10.0
    max_response_bytes: int = 2_000_000
    user_agent: str = "AegisScope/0.1 authorized-security-assessment"
    headers: dict[str, str] = field(default_factory=dict)

    @property
    def scope(self) -> ScopePolicy:
        return ScopePolicy(
            tuple(self.allowed_hosts),
            self.allow_subdomains,
            tuple(self.allowed_schemes),
        )

    def validate(self) -> None:
        self.target = normalize_url(self.target)
        if not self.authorization_owner.strip():
            raise ValueError("authorization_owner is required")
        if not self.authorization_reference.strip():
            raise ValueError("authorization_reference is required")
        if not self.scope.is_allowed(self.target):
            raise ScopeError("target is not covered by allowed_hosts and allowed_schemes")
        if not 1 <= self.max_pages <= 5_000:
            raise ValueError("max_pages must be between 1 and 5000")
        if not 1 <= self.max_requests <= 20_000:
            raise ValueError("max_requests must be between 1 and 20000")
        if not 0.1 <= self.requests_per_second <= 20:
            raise ValueError("requests_per_second must be between 0.1 and 20")
        if not 1 <= self.timeout_seconds <= 120:
            raise ValueError("timeout_seconds must be between 1 and 120")
        if not 1_024 <= self.max_response_bytes <= 10_000_000:
            raise ValueError("max_response_bytes must be between 1024 and 10000000")

    def resolved_headers(self) -> dict[str, str]:
        resolved: dict[str, str] = {}
        for name, value in self.headers.items():
            if value.startswith("${") and value.endswith("}"):
                variable = value[2:-1]
                if variable not in os.environ:
                    raise ValueError(f"required environment variable is missing: {variable}")
                value = os.environ[variable]
            resolved[name] = value
        return resolved

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "allowed_hosts": self.allowed_hosts,
            "allow_subdomains": self.allow_subdomains,
            "allowed_schemes": self.allowed_schemes,
            "authorization": {
                "owner": self.authorization_owner,
                "reference": self.authorization_reference,
            },
            "active_probes": self.active_probes,
            "reconnaissance": self.reconnaissance,
            "limits": {
                "max_pages": self.max_pages,
                "max_requests": self.max_requests,
                "requests_per_second": self.requests_per_second,
                "timeout_seconds": self.timeout_seconds,
                "max_response_bytes": self.max_response_bytes,
            },
            "user_agent": self.user_agent,
            "headers": self.headers,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ScanConfig":
        authorization = data.get("authorization", {})
        limits = data.get("limits", {})
        config = cls(
            target=data["target"],
            allowed_hosts=list(data.get("allowed_hosts", [])),
            authorization_owner=authorization.get("owner", ""),
            authorization_reference=authorization.get("reference", ""),
            allow_subdomains=bool(data.get("allow_subdomains", False)),
            allowed_schemes=list(data.get("allowed_schemes", ["https"])),
            active_probes=bool(data.get("active_probes", False)),
            reconnaissance=bool(data.get("reconnaissance", True)),
            max_pages=int(limits.get("max_pages", 50)),
            max_requests=int(limits.get("max_requests", 150)),
            requests_per_second=float(limits.get("requests_per_second", 2.0)),
            timeout_seconds=float(limits.get("timeout_seconds", 10.0)),
            max_response_bytes=int(limits.get("max_response_bytes", 2_000_000)),
            user_agent=data.get(
                "user_agent", "AegisScope/0.1 authorized-security-assessment"
            ),
            headers=dict(data.get("headers", {})),
        )
        config.validate()
        return config


def load_config(path: str | Path) -> ScanConfig:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("configuration root must be a JSON object")
    return ScanConfig.from_dict(data)


def create_config(
    target: str,
    owner: str,
    authorization_reference: str,
    allow_subdomains: bool = False,
) -> ScanConfig:
    normalized = normalize_url(target)
    host = urlsplit(normalized).hostname
    if not host:
        raise ScopeError("target must include a hostname")
    scheme = urlsplit(normalized).scheme
    config = ScanConfig(
        target=normalized,
        allowed_hosts=[host],
        authorization_owner=owner,
        authorization_reference=authorization_reference,
        allow_subdomains=allow_subdomains,
        allowed_schemes=[scheme],
    )
    config.validate()
    return config
