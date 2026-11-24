from __future__ import annotations

import hashlib
import json
import time
from collections import deque
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx

from .checks import check_response, detect_new_sql_error, parse_page
from .config import ScanConfig
from .models import Finding, ScanResult
from .scope import ScopeError, normalize_url


SKIPPED_EXTENSIONS = {
    ".7z",
    ".avi",
    ".css",
    ".doc",
    ".docx",
    ".eot",
    ".gif",
    ".gz",
    ".ico",
    ".jpeg",
    ".jpg",
    ".mov",
    ".mp3",
    ".mp4",
    ".pdf",
    ".png",
    ".rar",
    ".svg",
    ".tar",
    ".tgz",
    ".ttf",
    ".wav",
    ".webm",
    ".webp",
    ".woff",
    ".woff2",
    ".xls",
    ".xlsx",
    ".zip",
}
REDIRECT_PARAMETERS = {
    "continue",
    "dest",
    "destination",
    "next",
    "redirect",
    "redirect_uri",
    "return",
    "return_to",
    "returnurl",
    "url",
}
ASSESSMENT_PROFILES: dict[str, frozenset[str]] = {
    "passive": frozenset(),
    "injection": frozenset({"reflection", "sql-error"}),
    "redirect": frozenset({"open-redirect"}),
    "full-safe": frozenset({"reflection", "sql-error", "open-redirect"}),
}


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def redacted_url(url: str) -> str:
    parts = urlsplit(url)
    query = urlencode([(key, "REDACTED") for key, _ in parse_qsl(parts.query, True)])
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))


def replace_query_value(url: str, index: int, value: str) -> str:
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    pairs[index] = (pairs[index][0], value)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(pairs), ""))


@dataclass(slots=True)
class FetchedResponse:
    url: str
    status_code: int
    headers: httpx.Headers
    body: str
    truncated: bool


class RequestBudgetExceeded(RuntimeError):
    pass


class AuditLog:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text("", encoding="utf-8")

    def write(self, event: str, **details: object) -> None:
        record = {"timestamp": utc_now(), "event": event, **details}
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")


class Scanner:
    def __init__(
        self,
        config: ScanConfig,
        audit_path: str | Path,
        profile: str = "passive",
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        config.validate()
        if profile not in ASSESSMENT_PROFILES:
            raise ValueError(f"unknown assessment profile: {profile}")
        self.probes = ASSESSMENT_PROFILES[profile]
        if self.probes and not config.active_probes:
            raise ValueError("active probes are disabled in the configuration")
        self.config = config
        self.scope = config.scope
        self.profile = profile
        self.active = bool(self.probes)
        self.audit = AuditLog(audit_path)
        self.result = ScanResult(
            target=config.target,
            started_at=utc_now(),
            profile=profile,
            active_probes_used=self.active,
        )
        headers = {"User-Agent": config.user_agent, **config.resolved_headers()}
        self.client = httpx.Client(
            headers=headers,
            timeout=config.timeout_seconds,
            follow_redirects=False,
            verify=True,
            transport=transport,
        )
        self._last_request_at = 0.0
        self._finding_keys: set[str] = set()

    def close(self) -> None:
        self.client.close()

    def __enter__(self) -> "Scanner":
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def _wait_for_rate_limit(self) -> None:
        interval = 1.0 / self.config.requests_per_second
        remaining = interval - (time.monotonic() - self._last_request_at)
        if remaining > 0:
            time.sleep(remaining)

    def _fetch(self, url: str, purpose: str) -> FetchedResponse:
        normalized = self.scope.require_allowed(url)
        if self.result.stats.requests_sent >= self.config.max_requests:
            raise RequestBudgetExceeded("maximum request budget reached")
        self._wait_for_rate_limit()
        query_keys = [key for key, _ in parse_qsl(urlsplit(normalized).query, True)]
        self.audit.write(
            "request",
            method="GET",
            host=urlsplit(normalized).hostname,
            path=urlsplit(normalized).path,
            query_keys=query_keys,
            purpose=purpose,
        )
        self.result.stats.requests_sent += 1
        self._last_request_at = time.monotonic()

        with self.client.stream("GET", normalized) as response:
            chunks = bytearray()
            truncated = False
            for chunk in response.iter_bytes():
                remaining = self.config.max_response_bytes - len(chunks)
                if remaining <= 0:
                    truncated = True
                    break
                chunks.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    truncated = True
                    break
            encoding = response.encoding or "utf-8"
            try:
                body = bytes(chunks).decode(encoding, errors="replace")
            except LookupError:
                body = bytes(chunks).decode("utf-8", errors="replace")
            fetched = FetchedResponse(
                url=normalized,
                status_code=response.status_code,
                headers=httpx.Headers(response.headers),
                body=body,
                truncated=truncated,
            )
        self.audit.write(
            "response",
            host=urlsplit(normalized).hostname,
            path=urlsplit(normalized).path,
            purpose=purpose,
            status=fetched.status_code,
            bytes=len(chunks),
            truncated=truncated,
        )
        return fetched

    def _add_finding(self, finding: Finding) -> None:
        finding.url = redacted_url(finding.url)
        digest_source = f"{finding.check_id}|{finding.url}|{finding.evidence}"
        key = hashlib.sha256(digest_source.encode()).hexdigest()
        if key not in self._finding_keys:
            self._finding_keys.add(key)
            self.result.findings.append(finding)

    def _add_error(self, url: str, error: Exception) -> None:
        self.result.stats.errors += 1
        self.audit.write(
            "request_error",
            host=urlsplit(url).hostname,
            path=urlsplit(url).path,
            error=type(error).__name__,
        )
        self._add_finding(
            Finding(
                check_id="request-error",
                title="Page could not be assessed",
                severity="info",
                confidence="high",
                url=url,
                description="A network or TLS error prevented this URL from being assessed.",
                evidence=f"{type(error).__name__}; request details are retained only in the redacted audit trail.",
                remediation="Confirm availability, DNS, TLS configuration, and the assessment scope.",
            )
        )

    def _active_probes(self, response: FetchedResponse) -> None:
        parameters = parse_qsl(urlsplit(response.url).query, keep_blank_values=True)
        for index, (name, original_value) in enumerate(parameters[:5]):
            try:
                if "reflection" in self.probes:
                    marker = f"aegisscope{self.result.stats.requests_sent:06d}"
                    reflected = self._fetch(
                        replace_query_value(response.url, index, marker), "reflection-canary"
                    )
                    if marker in reflected.body and marker not in response.body:
                        self._add_finding(
                            Finding(
                                check_id="input-reflection",
                                title="Query input is reflected in the response",
                                severity="info",
                                confidence="medium",
                                url=response.url,
                                description="A harmless alphanumeric canary was reflected. This is not XSS by itself and requires contextual review.",
                                evidence=f"Parameter {name!r} reflected a non-executable canary.",
                                remediation="Apply context-aware output encoding and validate untrusted input.",
                                cwe="CWE-79",
                            )
                        )

                if "sql-error" in self.probes:
                    sql_probe = self._fetch(
                        replace_query_value(response.url, index, original_value + "'"),
                        "sql-error-canary",
                    )
                    sql_error = detect_new_sql_error(response.body, sql_probe.body)
                    if sql_error:
                        self._add_finding(
                            Finding(
                                check_id="sql-error-indicator",
                                title="Database error appeared after input mutation",
                                severity="medium",
                                confidence="medium",
                                url=response.url,
                                description="A single-quote input mutation produced a database error signature not present in the baseline response.",
                                evidence=f"Parameter {name!r}; new signature: {sql_error}",
                                remediation="Use parameterized queries, avoid dynamic SQL, and return generic errors.",
                                cwe="CWE-89",
                            )
                        )

                if (
                    "open-redirect" in self.probes
                    and name.lower() in REDIRECT_PARAMETERS
                ):
                    redirect_probe = self._fetch(
                        replace_query_value(
                            response.url, index, "https://example.invalid/aegisscope"
                        ),
                        "redirect-canary",
                    )
                    location = redirect_probe.headers.get("location", "")
                    if (
                        redirect_probe.status_code in {301, 302, 303, 307, 308}
                        and urlsplit(location).hostname == "example.invalid"
                    ):
                        self._add_finding(
                            Finding(
                                check_id="open-redirect-indicator",
                                title="Unvalidated external redirect detected",
                                severity="medium",
                                confidence="high",
                                url=response.url,
                                description="The endpoint redirected to a reserved external hostname supplied through a query parameter.",
                                evidence=f"Parameter {name!r}; Location host: example.invalid",
                                remediation="Allowlist trusted redirect destinations or use server-side destination identifiers.",
                                cwe="CWE-601",
                            )
                        )
            except RequestBudgetExceeded:
                return
            except (httpx.HTTPError, ScopeError, UnicodeError) as error:
                self._add_error(response.url, error)

    def run(self) -> ScanResult:
        queue: deque[str] = deque([self.config.target])
        queued = {self.config.target}
        visited: set[str] = set()
        self.audit.write(
            "scan_started",
            target=redacted_url(self.config.target),
            authorization_owner=self.config.authorization_owner,
            authorization_reference=self.config.authorization_reference,
            active=self.active,
            profile=self.profile,
        )

        while queue and len(visited) < self.config.max_pages:
            url = queue.popleft()
            if url in visited:
                continue
            visited.add(url)
            try:
                response = self._fetch(url, "crawl")
            except RequestBudgetExceeded:
                break
            except (httpx.HTTPError, ScopeError, UnicodeError) as error:
                self._add_error(url, error)
                continue

            self.result.stats.pages_visited += 1
            for finding in check_response(
                response.url, response.status_code, response.headers, response.body
            ):
                self._add_finding(finding)

            content_type = response.headers.get("content-type", "").lower()
            if "text/html" in content_type and response.body:
                parser = parse_page(response.url, response.body)
                for link in sorted(parser.links):
                    try:
                        normalized = normalize_url(link)
                    except ScopeError:
                        continue
                    if not self.scope.is_allowed(normalized):
                        self.result.stats.blocked_urls += 1
                        continue
                    path = urlsplit(normalized).path.lower()
                    if any(path.endswith(extension) for extension in SKIPPED_EXTENSIONS):
                        continue
                    if normalized not in queued:
                        queued.add(normalized)
                        queue.append(normalized)

            location = response.headers.get("location")
            if location:
                try:
                    redirect = normalize_url(location, response.url)
                except ScopeError:
                    redirect = ""
                if redirect and self.scope.is_allowed(redirect) and redirect not in queued:
                    queued.add(redirect)
                    queue.append(redirect)
                elif redirect:
                    self.result.stats.blocked_urls += 1

            if self.active and urlsplit(response.url).query:
                self._active_probes(response)

        self.result.stats.urls_discovered = len(queued)
        self.result.completed_at = utc_now()
        self.audit.write(
            "scan_completed",
            requests=self.result.stats.requests_sent,
            pages=self.result.stats.pages_visited,
            findings=len(self.result.findings),
            blocked_urls=self.result.stats.blocked_urls,
        )
        return self.result
