from __future__ import annotations

import re
import socket
import ssl
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

import httpx


PRODUCT_VERSION = re.compile(
    r"(?P<product>[A-Za-z][A-Za-z0-9._+-]{1,40})[/ ](?P<version>\d+(?:\.\d+){1,4}(?:[-._A-Za-z0-9]+)?)"
)
GENERATOR_META = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)',
    re.IGNORECASE,
)
TECHNOLOGY_MARKERS = {
    "WordPress": ("wp-content/", "wp-includes/"),
    "Drupal": ("drupal-settings-json", "sites/default/files"),
    "Joomla": ("/media/system/js/", "option=com_"),
    "Next.js": ("__next_data__", "/_next/static/"),
    "React": ("data-reactroot", "__react"),
    "Angular": ("ng-version=", "_ngcontent-"),
}
OS_HINTS = {
    "ubuntu": "Ubuntu Linux",
    "debian": "Debian Linux",
    "centos": "CentOS Linux",
    "red hat": "Red Hat Enterprise Linux",
    "win32": "Microsoft Windows",
    "windows": "Microsoft Windows",
}


def _name_from_x509(parts: tuple[tuple[tuple[str, str], ...], ...]) -> str:
    values = [f"{key}={value}" for group in parts for key, value in group]
    return ", ".join(values)


def _subdomain_base(hostname: str) -> str:
    return hostname[4:] if hostname.startswith("www.") else hostname


def is_related_subdomain(candidate: str, hostname: str) -> bool:
    candidate = candidate.lower().strip().lstrip("*.").rstrip(".")
    base = _subdomain_base(hostname.lower().rstrip("."))
    return bool(candidate and candidate != base and candidate.endswith(f".{base}"))


def collect_dns(hostname: str, port: int) -> dict[str, Any]:
    result: dict[str, Any] = {"addresses": [], "aliases": [], "error": None}
    try:
        canonical, aliases, addresses = socket.gethostbyname_ex(hostname)
        result["canonical_name"] = canonical
        result["aliases"] = sorted(set(aliases))
        all_addresses = set(addresses)
        for entry in socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM):
            all_addresses.add(entry[4][0])
        result["addresses"] = sorted(all_addresses)
    except OSError as error:
        result["error"] = f"{type(error).__name__}: DNS resolution failed"
    return result


def collect_tls(hostname: str, port: int, timeout: float) -> dict[str, Any]:
    result: dict[str, Any] = {"enabled": True, "error": None}
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as connection:
            with context.wrap_socket(connection, server_hostname=hostname) as secure:
                certificate = secure.getpeercert()
                cipher = secure.cipher()
                result.update(
                    {
                        "protocol": secure.version(),
                        "cipher": cipher[0] if cipher else None,
                        "subject": _name_from_x509(certificate.get("subject", ())),
                        "issuer": _name_from_x509(certificate.get("issuer", ())),
                        "serial_number": certificate.get("serialNumber"),
                        "not_before": certificate.get("notBefore"),
                        "not_after": certificate.get("notAfter"),
                        "dns_names": sorted(
                            {
                                value
                                for kind, value in certificate.get("subjectAltName", ())
                                if kind == "DNS"
                            }
                        ),
                    }
                )
                if certificate.get("notAfter"):
                    expires = datetime.fromtimestamp(
                        ssl.cert_time_to_seconds(certificate["notAfter"]), UTC
                    )
                    result["expires_in_days"] = (expires - datetime.now(UTC)).days
    except (OSError, ssl.SSLError, ValueError) as error:
        result["error"] = f"{type(error).__name__}: TLS inspection failed"
    return result


def collect_host_recon(url: str, timeout: float) -> dict[str, Any]:
    parts = urlsplit(url)
    hostname = parts.hostname or ""
    port = parts.port or (443 if parts.scheme == "https" else 80)
    recon: dict[str, Any] = {
        "hostname": hostname,
        "port": port,
        "scheme": parts.scheme,
        "dns": collect_dns(hostname, port),
        "tls": {"enabled": False} if parts.scheme != "https" else collect_tls(hostname, port, timeout),
        "certificate_subdomains": [],
        "linked_hosts": [],
        "technologies": [],
        "possible_operating_systems": [],
        "limitations": [
            "Operating systems and patch levels cannot be reliably identified from HTTP/TLS alone.",
            "Exposed versions are inventory evidence, not proof that a CVE is exploitable.",
            "Certificate and linked host discovery is passive; discovered hosts are not scanned unless explicitly in scope.",
        ],
    }
    tls_names = recon.get("tls", {}).get("dns_names", [])
    recon["certificate_subdomains"] = sorted(
        {
            name.lower().lstrip("*.")
            for name in tls_names
            if is_related_subdomain(name, hostname)
        }
    )
    return recon


def fingerprint_http(headers: httpx.Headers, body: str) -> dict[str, list[dict[str, str]] | list[str]]:
    technologies: list[dict[str, str]] = []
    os_hints: list[str] = []
    observed: set[tuple[str, str, str, str]] = set()

    for header in ("server", "x-powered-by", "x-generator"):
        value = headers.get(header)
        if not value:
            continue
        matches = list(PRODUCT_VERSION.finditer(value))
        if matches:
            for match in matches:
                item = (
                    match.group("product"),
                    match.group("version"),
                    f"{header} header",
                    "medium",
                )
                observed.add(item)
        else:
            observed.add((value[:80], "unknown", f"{header} header", "medium"))
        lower_value = value.lower()
        for marker, operating_system in OS_HINTS.items():
            if marker in lower_value:
                os_hints.append(f"{operating_system} (low confidence, inferred from {header})")

    generator = GENERATOR_META.search(body[:500_000])
    if generator:
        value = generator.group(1).strip()[:120]
        match = PRODUCT_VERSION.search(value)
        observed.add(
            (
                match.group("product") if match else value,
                match.group("version") if match else "unknown",
                "HTML generator metadata",
                "medium",
            )
        )

    lower_body = body[:1_000_000].lower()
    for technology, markers in TECHNOLOGY_MARKERS.items():
        if any(marker.lower() in lower_body for marker in markers):
            observed.add((technology, "unknown", "HTML marker", "low"))

    for name, version, evidence, confidence in sorted(observed):
        technologies.append(
            {
                "name": name,
                "version": version,
                "evidence": evidence,
                "confidence": confidence,
            }
        )
    return {"technologies": technologies, "possible_operating_systems": sorted(set(os_hints))}
