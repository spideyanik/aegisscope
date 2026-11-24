from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit


class ScopeError(ValueError):
    """Raised when a URL or scope policy is unsafe or invalid."""


def normalize_url(url: str, base: str | None = None) -> str:
    candidate = urljoin(base, url) if base else url
    parts = urlsplit(candidate.strip())
    if parts.scheme.lower() not in {"http", "https"}:
        raise ScopeError("only http and https URLs are supported")
    if not parts.hostname:
        raise ScopeError("URL must include a hostname")
    if parts.username or parts.password:
        raise ScopeError("credentials in URLs are not allowed")

    host = parts.hostname.lower().rstrip(".")
    try:
        port = parts.port
    except ValueError as exc:
        raise ScopeError("URL contains an invalid port") from exc

    default_port = (parts.scheme.lower() == "http" and port == 80) or (
        parts.scheme.lower() == "https" and port == 443
    )
    netloc = host if port is None or default_port else f"{host}:{port}"
    path = parts.path or "/"
    query = urlencode(parse_qsl(parts.query, keep_blank_values=True), doseq=True)
    return urlunsplit((parts.scheme.lower(), netloc, path, query, ""))


@dataclass(frozen=True, slots=True)
class ScopePolicy:
    allowed_hosts: tuple[str, ...]
    allow_subdomains: bool = False
    allowed_schemes: tuple[str, ...] = ("https",)

    def __post_init__(self) -> None:
        normalized = tuple(host.lower().rstrip(".") for host in self.allowed_hosts)
        if not normalized or any(not host for host in normalized):
            raise ScopeError("at least one allowed host is required")
        object.__setattr__(self, "allowed_hosts", normalized)

    def is_allowed(self, url: str) -> bool:
        try:
            parts = urlsplit(normalize_url(url))
        except ScopeError:
            return False
        if parts.scheme not in self.allowed_schemes:
            return False
        host = parts.hostname or ""
        for allowed in self.allowed_hosts:
            if host == allowed:
                return True
            if self.allow_subdomains and host.endswith(f".{allowed}"):
                return True
        return False

    def require_allowed(self, url: str) -> str:
        normalized = normalize_url(url)
        if not self.is_allowed(normalized):
            raise ScopeError(f"out-of-scope URL blocked: {normalized}")
        return normalized
