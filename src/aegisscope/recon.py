from __future__ import annotations

import re
import ipaddress
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

import httpx
import tldextract

from .subdomains import discover_subdomains, parse_certificate_entries


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
SAFE_RESPONSE_HEADERS = (
    "server",
    "x-powered-by",
    "content-type",
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "access-control-allow-origin",
    "access-control-allow-credentials",
    "cache-control",
)
_TLD_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())
COMMON_SERVICE_NAMES = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP submission",
    993: "IMAPS",
    995: "POP3S",
    1433: "Microsoft SQL Server",
    1521: "Oracle Database",
    2049: "NFS",
    2375: "Docker API",
    3000: "Web application",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5601: "Kibana",
    6379: "Redis",
    8000: "Alternate HTTP",
    8080: "Alternate HTTP",
    8443: "Alternate HTTPS",
    9000: "Application service",
    9200: "Elasticsearch",
    27017: "MongoDB",
}


def _name_from_x509(parts: tuple[tuple[tuple[str, str], ...], ...]) -> str:
    values = [f"{key}={value}" for group in parts for key, value in group]
    return ", ".join(values)


def _subdomain_base(hostname: str) -> str:
    return hostname[4:] if hostname.startswith("www.") else hostname


def registrable_domain(hostname: str) -> str:
    extracted = _TLD_EXTRACT(hostname.lower().rstrip("."))
    return extracted.top_domain_under_public_suffix or hostname.lower().rstrip(".")


def is_related_subdomain(candidate: str, hostname: str) -> bool:
    candidate = candidate.lower().strip().lstrip("*.").rstrip(".")
    base = _subdomain_base(hostname.lower().rstrip("."))
    return bool(candidate and candidate != base and candidate.endswith(f".{base}"))


def parse_ct_entries(entries: object, domain: str) -> list[str]:
    return parse_certificate_entries(entries, domain)


def collect_certificate_transparency(domain: str, timeout: float) -> dict[str, Any]:
    result: dict[str, Any] = {
        "domain": domain,
        "subdomains": [],
        "source": None,
        "error": None,
    }
    errors: list[str] = []
    try:
        response = httpx.get(
            "https://api.certspotter.com/v1/issuances",
            params={
                "domain": domain,
                "include_subdomains": "true",
                "expand": "dns_names",
            },
            headers={"User-Agent": "AegisScope/0.3.1 passive-certificate-discovery"},
            timeout=timeout,
            follow_redirects=True,
        )
        response.raise_for_status()
        result["subdomains"] = parse_ct_entries(response.json(), domain)[:2_000]
        result["source"] = "Cert Spotter"
        return result
    except (httpx.HTTPError, ValueError) as error:
        errors.append(f"Cert Spotter: {type(error).__name__}")

    try:
        response = httpx.get(
            "https://crt.sh/",
            params={"q": f"%.{domain}", "output": "json"},
            headers={"User-Agent": "AegisScope/0.3.1 passive-certificate-discovery"},
            timeout=max(timeout, 30),
            follow_redirects=True,
        )
        response.raise_for_status()
        result["subdomains"] = parse_ct_entries(response.json(), domain)[:2_000]
        result["source"] = "crt.sh"
        return result
    except (httpx.HTTPError, ValueError) as error:
        errors.append(f"crt.sh: {type(error).__name__}")
    result["error"] = "; ".join(errors) or "certificate transparency lookup failed"
    return result


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


def parse_rdap_record(address: str, record: object) -> dict[str, Any]:
    if not isinstance(record, dict):
        return {"address": address, "error": "invalid RDAP response"}
    provider_names: list[str] = []
    for entity in record.get("entities", []):
        if not isinstance(entity, dict):
            continue
        vcard = entity.get("vcardArray")
        if not isinstance(vcard, list) or len(vcard) < 2 or not isinstance(vcard[1], list):
            continue
        for field in vcard[1]:
            if isinstance(field, list) and len(field) >= 4 and field[0] == "fn":
                provider_names.append(str(field[3]))
    return {
        "address": address,
        "network_name": record.get("name") or record.get("handle"),
        "handle": record.get("handle"),
        "country": record.get("country"),
        "start_address": record.get("startAddress"),
        "end_address": record.get("endAddress"),
        "entities": sorted(set(provider_names))[:10],
        "error": None,
    }


def collect_provider_records(addresses: list[str], timeout: float) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for address in addresses[:3]:
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            continue
        if not parsed.is_global:
            records.append(
                {
                    "address": address,
                    "network_name": "private or non-global address",
                    "error": None,
                }
            )
            continue
        try:
            response = httpx.get(
                f"https://rdap.org/ip/{address}",
                headers={"User-Agent": "AegisScope/0.3.1 passive-provider-lookup"},
                timeout=timeout,
                follow_redirects=True,
            )
            response.raise_for_status()
            records.append(parse_rdap_record(address, response.json()))
        except (httpx.HTTPError, ValueError) as error:
            records.append(
                {
                    "address": address,
                    "network_name": None,
                    "error": f"{type(error).__name__}: provider lookup failed",
                }
            )
    return records


def resolve_subdomain_hosts(hostnames: list[str], limit: int) -> list[dict[str, Any]]:
    def resolve(hostname: str) -> dict[str, Any] | None:
        try:
            addresses = sorted(
                {
                    entry[4][0]
                    for entry in socket.getaddrinfo(
                        hostname, None, type=socket.SOCK_STREAM
                    )
                }
            )
            return {"hostname": hostname, "addresses": addresses}
        except OSError:
            return None

    resolved: list[dict[str, Any]] = []
    selected = sorted(set(hostnames))[:limit]
    with ThreadPoolExecutor(max_workers=min(12, max(1, len(selected)))) as executor:
        futures = {executor.submit(resolve, hostname): hostname for hostname in selected}
        for future in as_completed(futures):
            result = future.result()
            if result:
                resolved.append(result)
    return sorted(resolved, key=lambda item: item["hostname"])


def scan_common_ports(
    hostname: str, ports: list[int], timeout: float
) -> dict[str, Any]:
    def connect(port: int) -> dict[str, Any] | None:
        try:
            connection = socket.create_connection((hostname, port), timeout=timeout)
            connection.close()
            return {
                "port": port,
                "service": COMMON_SERVICE_NAMES.get(port, "unknown"),
            }
        except OSError:
            return None

    open_ports: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=min(20, len(ports))) as executor:
        futures = {executor.submit(connect, port): port for port in ports}
        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)
    return {
        "hostname": hostname,
        "transport": "tcp",
        "scanned_ports": ports,
        "open_ports": sorted(open_ports, key=lambda item: item["port"]),
        "note": "A TCP connection confirms exposure, not a vulnerability or service version.",
    }


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


def collect_host_recon(
    url: str,
    timeout: float,
    passive_subdomains: bool = True,
    provider_lookup: bool = True,
    resolve_subdomains: bool = True,
    dns_wordlist_subdomains: bool = False,
    max_subdomains: int = 100,
) -> dict[str, Any]:
    parts = urlsplit(url)
    hostname = parts.hostname or ""
    port = parts.port or (443 if parts.scheme == "https" else 80)
    domain = registrable_domain(hostname)
    recon: dict[str, Any] = {
        "hostname": hostname,
        "port": port,
        "scheme": parts.scheme,
        "dns": collect_dns(hostname, port),
        "tls": {"enabled": False} if parts.scheme != "https" else collect_tls(hostname, port, timeout),
        "certificate_subdomains": [],
        "certificate_transparency": {
            "domain": domain,
            "subdomains": [],
            "error": "disabled by configuration",
        },
        "linked_hosts": [],
        "technologies": [],
        "possible_operating_systems": [],
        "observed_headers": {},
        "provider_records": [],
        "resolved_subdomains": [],
        "subdomain_discovery": {},
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
    if passive_subdomains or dns_wordlist_subdomains:
        discovery = discover_subdomains(
            domain,
            timeout,
            max_subdomains if resolve_subdomains else 0,
            dns_wordlist_subdomains,
            tls_names,
            passive_subdomains,
        )
        recon["subdomain_discovery"] = discovery
        recon["resolved_subdomains"] = discovery["resolved"]
        passive_candidates = [
            item["hostname"]
            for item in discovery["candidates"]
            if any(source != "DNS wordlist" for source in item["sources"])
        ]
        source_errors = [
            f"{item['name']}: {item['error']}"
            for item in discovery["passive_sources"]
            if item["error"]
        ]
        recon["certificate_transparency"] = {
            "domain": domain,
            "subdomains": passive_candidates,
            "source": "multi-source passive discovery",
            "error": "; ".join(source_errors) or None,
        }
    if provider_lookup:
        recon["provider_records"] = collect_provider_records(
            recon["dns"].get("addresses", []), timeout
        )
    return recon


def fingerprint_http(headers: httpx.Headers, body: str) -> dict[str, Any]:
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
    observed_headers = {
        name: headers[name]
        for name in SAFE_RESPONSE_HEADERS
        if name in headers
    }
    return {
        "technologies": technologies,
        "possible_operating_systems": sorted(set(os_hints)),
        "observed_headers": observed_headers,
    }
