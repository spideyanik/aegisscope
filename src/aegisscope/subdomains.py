from __future__ import annotations

import secrets
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable

import httpx


COMMON_SUBDOMAIN_LABELS = (
    "www",
    "mail",
    "webmail",
    "smtp",
    "imap",
    "pop",
    "ftp",
    "sftp",
    "api",
    "app",
    "admin",
    "portal",
    "auth",
    "sso",
    "login",
    "vpn",
    "remote",
    "dev",
    "test",
    "testing",
    "stage",
    "staging",
    "uat",
    "qa",
    "prod",
    "production",
    "beta",
    "demo",
    "dashboard",
    "support",
    "help",
    "docs",
    "status",
    "blog",
    "shop",
    "store",
    "mobile",
    "m",
    "static",
    "assets",
    "cdn",
    "media",
    "files",
    "download",
    "uploads",
    "images",
    "img",
    "ns1",
    "ns2",
    "dns",
    "mx",
    "git",
    "gitlab",
    "jenkins",
    "ci",
    "registry",
    "docker",
    "k8s",
    "grafana",
    "prometheus",
    "monitor",
    "internal",
    "intranet",
    "legacy",
    "old",
    "new",
    "db",
    "mysql",
    "postgres",
    "redis",
    "elastic",
    "search",
)


def normalize_subdomain(value: str, domain: str) -> str | None:
    hostname = value.strip().lower().lstrip("*.").rstrip(".")
    if not hostname or hostname == domain or not hostname.endswith(f".{domain}"):
        return None
    try:
        return hostname.encode("idna").decode("ascii")
    except UnicodeError:
        return None


def parse_certificate_entries(entries: object, domain: str) -> list[str]:
    if not isinstance(entries, list):
        return []
    discovered: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        dns_names = entry.get("dns_names")
        values = (
            [str(value) for value in dns_names]
            if isinstance(dns_names, list)
            else str(entry.get("name_value", "")).splitlines()
        )
        for value in values:
            hostname = normalize_subdomain(value, domain)
            if hostname:
                discovered.add(hostname)
    return sorted(discovered)


def parse_hackertarget(text: str, domain: str) -> list[str]:
    if text.lower().startswith(("error", "api count exceeded")):
        return []
    discovered: set[str] = set()
    for line in text.splitlines():
        hostname = normalize_subdomain(line.split(",", 1)[0], domain)
        if hostname:
            discovered.add(hostname)
    return sorted(discovered)


def parse_otx(entries: object, domain: str) -> list[str]:
    if not isinstance(entries, dict):
        return []
    discovered: set[str] = set()
    records = entries.get("passive_dns", [])
    if not isinstance(records, list):
        return []
    for record in records:
        if not isinstance(record, dict):
            continue
        hostname = normalize_subdomain(str(record.get("hostname", "")), domain)
        if hostname:
            discovered.add(hostname)
    return sorted(discovered)


def _fetch_json(
    name: str,
    url: str,
    domain: str,
    parser: Callable[[object, str], list[str]],
    timeout: float,
    params: dict[str, str] | None = None,
) -> dict[str, Any]:
    try:
        response = httpx.get(
            url,
            params=params,
            headers={"User-Agent": "AegisScope/0.3.1 authorized-subdomain-discovery"},
            timeout=timeout,
            follow_redirects=True,
        )
        response.raise_for_status()
        hostnames = parser(response.json(), domain)
        return {"name": name, "hostnames": hostnames, "error": None}
    except (httpx.HTTPError, ValueError) as error:
        return {
            "name": name,
            "hostnames": [],
            "error": f"{type(error).__name__}: source lookup failed",
        }


def _fetch_hackertarget(domain: str, timeout: float) -> dict[str, Any]:
    try:
        response = httpx.get(
            "https://api.hackertarget.com/hostsearch/",
            params={"q": domain},
            headers={"User-Agent": "AegisScope/0.3.1 authorized-subdomain-discovery"},
            timeout=timeout,
            follow_redirects=True,
        )
        response.raise_for_status()
        hostnames = parse_hackertarget(response.text, domain)
        error = None
        if not hostnames and response.text.lower().startswith(("error", "api count exceeded")):
            error = "provider returned an API error or rate limit"
        return {"name": "HackerTarget", "hostnames": hostnames, "error": error}
    except httpx.HTTPError as error:
        return {
            "name": "HackerTarget",
            "hostnames": [],
            "error": f"{type(error).__name__}: source lookup failed",
        }


def collect_passive_sources(domain: str, timeout: float) -> list[dict[str, Any]]:
    bounded_timeout = min(max(timeout, 5), 20)
    tasks: tuple[Callable[[], dict[str, Any]], ...] = (
        lambda: _fetch_json(
            "Cert Spotter",
            "https://api.certspotter.com/v1/issuances",
            domain,
            parse_certificate_entries,
            bounded_timeout,
            {
                "domain": domain,
                "include_subdomains": "true",
                "expand": "dns_names",
            },
        ),
        lambda: _fetch_json(
            "crt.sh",
            "https://crt.sh/",
            domain,
            parse_certificate_entries,
            bounded_timeout,
            {"q": f"%.{domain}", "output": "json"},
        ),
        lambda: _fetch_json(
            "AlienVault OTX",
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
            domain,
            parse_otx,
            bounded_timeout,
        ),
        lambda: _fetch_hackertarget(domain, bounded_timeout),
    )
    results: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=len(tasks)) as executor:
        futures = [executor.submit(task) for task in tasks]
        for future in as_completed(futures):
            results.append(future.result())
    return sorted(results, key=lambda item: item["name"])


def resolve_hostname(hostname: str) -> list[str]:
    try:
        return sorted(
            {
                entry[4][0]
                for entry in socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
            }
        )
    except OSError:
        return []


def discover_subdomains(
    domain: str,
    timeout: float,
    max_resolved: int,
    dns_wordlist: bool,
    certificate_names: list[str] | None = None,
    passive_sources: bool = True,
) -> dict[str, Any]:
    source_results = collect_passive_sources(domain, timeout) if passive_sources else []
    candidate_sources: dict[str, set[str]] = {}
    for hostname in certificate_names or []:
        normalized = normalize_subdomain(hostname, domain)
        if normalized:
            candidate_sources.setdefault(normalized, set()).add("Target certificate")
    for source in source_results:
        for hostname in source["hostnames"]:
            candidate_sources.setdefault(hostname, set()).add(source["name"])
    if dns_wordlist:
        for label in COMMON_SUBDOMAIN_LABELS:
            hostname = f"{label}.{domain}"
            candidate_sources.setdefault(hostname, set()).add("DNS wordlist")

    wildcard_hostnames = (
        [
            f"aegis-{secrets.token_hex(8)}-{index}.{domain}"
            for index in range(1, 3)
        ]
        if dns_wordlist
        else []
    )
    wildcard_results = [resolve_hostname(hostname) for hostname in wildcard_hostnames]
    wildcard_addresses = (
        sorted({address for result in wildcard_results for address in result})
        if wildcard_results and all(wildcard_results)
        else []
    )
    ordered_candidates = sorted(
        candidate_sources,
        key=lambda hostname: (
            candidate_sources[hostname] == {"DNS wordlist"},
            hostname,
        ),
    )[:max_resolved]

    resolved: list[dict[str, Any]] = []
    wildcard_filtered: list[str] = []
    with ThreadPoolExecutor(max_workers=min(16, max(1, len(ordered_candidates)))) as executor:
        futures = {
            executor.submit(resolve_hostname, hostname): hostname
            for hostname in ordered_candidates
        }
        for future in as_completed(futures):
            hostname = futures[future]
            addresses = future.result()
            if not addresses:
                continue
            sources = sorted(candidate_sources[hostname])
            wildcard_match = bool(
                wildcard_addresses
                and set(addresses).issubset(set(wildcard_addresses))
            )
            if wildcard_match and sources == ["DNS wordlist"]:
                wildcard_filtered.append(hostname)
                continue
            resolved.append(
                {
                    "hostname": hostname,
                    "addresses": addresses,
                    "sources": sources,
                    "wildcard_match": wildcard_match,
                }
            )

    candidates = [
        {"hostname": hostname, "sources": sorted(sources)}
        for hostname, sources in sorted(candidate_sources.items())
    ]
    resolved_names = {item["hostname"] for item in resolved}
    discovered_names = sorted(
        hostname
        for hostname, sources in candidate_sources.items()
        if sources != {"DNS wordlist"} or hostname in resolved_names
    )
    return {
        "domain": domain,
        "passive_sources": [
            {
                "name": source["name"],
                "count": len(source["hostnames"]),
                "error": source["error"],
            }
            for source in source_results
        ],
        "candidate_count": len(candidates),
        "candidates": candidates[:5_000],
        "discovered_names": discovered_names,
        "dns_wordlist_enabled": dns_wordlist,
        "dns_wordlist_size": len(COMMON_SUBDOMAIN_LABELS) if dns_wordlist else 0,
        "resolution_limit": max_resolved,
        "wildcard_test_hostnames": wildcard_hostnames,
        "wildcard_addresses": wildcard_addresses,
        "wildcard_filtered": sorted(wildcard_filtered),
        "resolved": sorted(resolved, key=lambda item: item["hostname"]),
    }
