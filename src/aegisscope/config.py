from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .nmap_runner import NMAP_PROFILES
from .scope import ScopeError, ScopePolicy, normalize_url


DEFAULT_COMMON_PORTS = [
    21,
    22,
    25,
    53,
    80,
    110,
    143,
    443,
    445,
    465,
    587,
    993,
    995,
    1433,
    1521,
    2049,
    2375,
    3000,
    3306,
    3389,
    5432,
    5601,
    6379,
    8000,
    8080,
    8443,
    9000,
    9200,
    27017,
]


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
    passive_subdomains: bool = True
    provider_lookup: bool = True
    resolve_subdomains: bool = True
    dns_wordlist_subdomains: bool = False
    web_scan: bool = True
    port_scan: bool = False
    port_scan_engine: str = "builtin"
    nmap_profile: str = "inventory"
    nmap_timeout_seconds: int = 180
    nmap_max_rate: int = 100
    common_ports: list[int] = field(default_factory=lambda: list(DEFAULT_COMMON_PORTS))
    port_timeout_seconds: float = 1.0
    max_subdomains: int = 100
    max_pages: int = 50
    max_requests: int = 150
    requests_per_second: float = 2.0
    timeout_seconds: float = 10.0
    max_response_bytes: int = 2_000_000
    user_agent: str = "AegisScope/0.3.1 authorized-security-assessment"
    headers: dict[str, str] = field(default_factory=dict)

    @property
    def scope(self) -> ScopePolicy:
        hosts = [
            host[4:] if self.allow_subdomains and host.lower().startswith("www.") else host
            for host in self.allowed_hosts
        ]
        return ScopePolicy(
            tuple(hosts),
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
        if not 0.1 <= self.port_timeout_seconds <= 5:
            raise ValueError("port_timeout_seconds must be between 0.1 and 5")
        if self.port_scan_engine not in {"builtin", "nmap"}:
            raise ValueError("port_scan_engine must be 'builtin' or 'nmap'")
        if self.nmap_profile not in NMAP_PROFILES:
            raise ValueError(f"nmap_profile must be one of: {', '.join(NMAP_PROFILES)}")
        if not 30 <= self.nmap_timeout_seconds <= 1_800:
            raise ValueError("nmap_timeout_seconds must be between 30 and 1800")
        if not 1 <= self.nmap_max_rate <= 1_000:
            raise ValueError("nmap_max_rate must be between 1 and 1000")
        if not 1 <= self.max_subdomains <= 500:
            raise ValueError("max_subdomains must be between 1 and 500")
        if not 1 <= len(self.common_ports) <= 100:
            raise ValueError("common_ports must contain between 1 and 100 ports")
        if any(not 1 <= port <= 65535 for port in self.common_ports):
            raise ValueError("common_ports contains an invalid TCP port")
        self.common_ports = sorted(set(self.common_ports))

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
            "passive_subdomains": self.passive_subdomains,
            "modules": {
                "provider_lookup": self.provider_lookup,
                "resolve_subdomains": self.resolve_subdomains,
                "dns_wordlist_subdomains": self.dns_wordlist_subdomains,
                "web_scan": self.web_scan,
                "port_scan": self.port_scan,
            },
            "network_scan": {
                "common_ports": self.common_ports,
                "port_timeout_seconds": self.port_timeout_seconds,
                "engine": self.port_scan_engine,
                "nmap_profile": self.nmap_profile,
                "nmap_timeout_seconds": self.nmap_timeout_seconds,
                "nmap_max_rate": self.nmap_max_rate,
                "max_subdomains": self.max_subdomains,
            },
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
        modules = data.get("modules", {})
        network_scan = data.get("network_scan", {})
        config = cls(
            target=data["target"],
            allowed_hosts=list(data.get("allowed_hosts", [])),
            authorization_owner=authorization.get("owner", ""),
            authorization_reference=authorization.get("reference", ""),
            allow_subdomains=bool(data.get("allow_subdomains", False)),
            allowed_schemes=list(data.get("allowed_schemes", ["https"])),
            active_probes=bool(data.get("active_probes", False)),
            reconnaissance=bool(data.get("reconnaissance", True)),
            passive_subdomains=bool(data.get("passive_subdomains", True)),
            provider_lookup=bool(modules.get("provider_lookup", True)),
            resolve_subdomains=bool(modules.get("resolve_subdomains", True)),
            dns_wordlist_subdomains=bool(
                modules.get("dns_wordlist_subdomains", False)
            ),
            web_scan=bool(modules.get("web_scan", True)),
            port_scan=bool(modules.get("port_scan", False)),
            port_scan_engine=str(network_scan.get("engine", "builtin")),
            nmap_profile=str(network_scan.get("nmap_profile", "inventory")),
            nmap_timeout_seconds=int(network_scan.get("nmap_timeout_seconds", 180)),
            nmap_max_rate=int(network_scan.get("nmap_max_rate", 100)),
            common_ports=[
                int(port)
                for port in network_scan.get("common_ports", DEFAULT_COMMON_PORTS)
            ],
            port_timeout_seconds=float(network_scan.get("port_timeout_seconds", 1.0)),
            max_subdomains=int(network_scan.get("max_subdomains", 100)),
            max_pages=int(limits.get("max_pages", 50)),
            max_requests=int(limits.get("max_requests", 150)),
            requests_per_second=float(limits.get("requests_per_second", 2.0)),
            timeout_seconds=float(limits.get("timeout_seconds", 10.0)),
            max_response_bytes=int(limits.get("max_response_bytes", 2_000_000)),
            user_agent=data.get(
                "user_agent", "AegisScope/0.3.1 authorized-security-assessment"
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
        allowed_hosts=[host[4:] if allow_subdomains and host.startswith("www.") else host],
        authorization_owner=owner,
        authorization_reference=authorization_reference,
        allow_subdomains=allow_subdomains,
        allowed_schemes=[scheme],
    )
    config.validate()
    return config
