from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

import httpx

from .models import Finding


class PageParser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.links: set[str] = set()
        self.get_forms: set[str] = set()
        self.insecure_resources: set[str] = set()
        self.password_forms: list[str] = []
        self._current_form_action: str | None = None
        self._current_form_method: str | None = None
        self._current_form_fields: list[str] = []
        self._current_form_has_password = False

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        values = {name.lower(): value for name, value in attrs if value is not None}
        candidate: str | None = None
        crawl_candidate = False
        if tag == "a":
            candidate = values.get("href")
            crawl_candidate = True
        elif tag == "link":
            candidate = values.get("href")
        elif tag in {"script", "img", "source", "video", "audio"}:
            candidate = values.get("src")
        elif tag == "iframe":
            candidate = values.get("src")
            crawl_candidate = True
        elif tag == "form":
            self._current_form_action = values.get("action", self.base_url)
            self._current_form_method = values.get("method", "get").lower()
            self._current_form_fields = []
            self._current_form_has_password = False
        elif tag in {"input", "select", "textarea"} and self._current_form_action:
            if values.get("name"):
                self._current_form_fields.append(values["name"])
            if tag == "input" and values.get("type", "").lower() == "password":
                self._current_form_has_password = True

        if candidate:
            absolute = urljoin(self.base_url, candidate)
            if urlsplit(absolute).scheme in {"http", "https"}:
                if crawl_candidate:
                    self.links.add(absolute)
                if self.base_url.startswith("https://") and absolute.startswith("http://"):
                    self.insecure_resources.add(absolute)

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            if self._current_form_has_password and self._current_form_action:
                self.password_forms.append(urljoin(self.base_url, self._current_form_action))
            elif (
                self._current_form_method == "get"
                and self._current_form_action
                and self._current_form_fields
            ):
                action = urljoin(self.base_url, self._current_form_action)
                parts = urlsplit(action)
                query = parse_qsl(parts.query, keep_blank_values=True)
                existing_names = {name for name, _ in query}
                query.extend(
                    (name, "")
                    for name in self._current_form_fields
                    if name not in existing_names
                )
                self.get_forms.add(
                    urlunsplit(
                        (parts.scheme, parts.netloc, parts.path, urlencode(query), "")
                    )
                )
            self._current_form_action = None
            self._current_form_method = None
            self._current_form_fields = []
            self._current_form_has_password = False


def parse_page(url: str, body: str) -> PageParser:
    parser = PageParser(url)
    parser.feed(body)
    return parser


def _finding(
    check_id: str,
    title: str,
    severity: str,
    url: str,
    description: str,
    evidence: str,
    remediation: str,
    confidence: str = "high",
    cwe: str | None = None,
    status: str = "confirmed",
) -> Finding:
    return Finding(
        check_id=check_id,
        title=title,
        severity=severity,
        confidence=confidence,
        url=url,
        description=description,
        evidence=evidence,
        remediation=remediation,
        cwe=cwe,
        status=status,
    )


def check_response(
    url: str, status_code: int, headers: httpx.Headers, body: str
) -> list[Finding]:
    findings: list[Finding] = []
    lower_headers = {name.lower(): value for name, value in headers.items()}

    recommended = {
        "content-security-policy": (
            "Content Security Policy is missing",
            "medium",
            "A Content-Security-Policy response header was not observed.",
            "Define a restrictive Content-Security-Policy and test it before enforcement.",
            "CWE-693",
        ),
        "x-content-type-options": (
            "MIME sniffing protection is missing",
            "low",
            "The X-Content-Type-Options response header was not observed.",
            "Set X-Content-Type-Options: nosniff.",
            "CWE-693",
        ),
        "referrer-policy": (
            "Referrer policy is missing",
            "low",
            "The Referrer-Policy response header was not observed.",
            "Set an appropriate Referrer-Policy such as strict-origin-when-cross-origin.",
            "CWE-200",
        ),
        "permissions-policy": (
            "Permissions policy is missing",
            "info",
            "The Permissions-Policy response header was not observed.",
            "Disable browser capabilities that the application does not require.",
            "CWE-693",
        ),
    }
    for header, details in recommended.items():
        if header not in lower_headers:
            title, severity, description, remediation, cwe = details
            findings.append(
                _finding(
                    f"header-{header}",
                    title,
                    severity,
                    url,
                    description,
                    f"HTTP {status_code}; missing header: {header}",
                    remediation,
                    cwe=cwe,
                )
            )

    if url.startswith("https://") and "strict-transport-security" not in lower_headers:
        findings.append(
            _finding(
                "header-hsts",
                "HTTP Strict Transport Security is missing",
                "medium",
                url,
                "HTTPS responses do not declare an HSTS policy.",
                "Missing Strict-Transport-Security header.",
                "Set Strict-Transport-Security with an appropriate max-age after confirming all subdomains support HTTPS.",
                cwe="CWE-319",
            )
        )

    csp = lower_headers.get("content-security-policy", "").lower()
    if "x-frame-options" not in lower_headers and "frame-ancestors" not in csp:
        findings.append(
            _finding(
                "header-clickjacking",
                "Clickjacking protection is missing",
                "low",
                url,
                "Neither X-Frame-Options nor a CSP frame-ancestors directive was observed.",
                "No frame embedding restriction found in response headers.",
                "Set CSP frame-ancestors to the origins permitted to frame this page.",
                cwe="CWE-1021",
            )
        )

    for cookie in headers.get_list("set-cookie"):
        cookie_name = cookie.split("=", 1)[0].strip() or "unnamed cookie"
        lower_cookie = cookie.lower()
        if url.startswith("https://") and "; secure" not in lower_cookie:
            findings.append(
                _finding(
                    "cookie-secure",
                    "Cookie is missing the Secure attribute",
                    "medium",
                    url,
                    "A cookie set over HTTPS can be sent without transport protection.",
                    f"Cookie {cookie_name!r} lacks Secure.",
                    "Add the Secure attribute to cookies used by HTTPS applications.",
                    cwe="CWE-614",
                )
            )
        if "; httponly" not in lower_cookie:
            findings.append(
                _finding(
                    "cookie-httponly",
                    "Cookie is missing the HttpOnly attribute",
                    "low",
                    url,
                    "Client-side scripts may be able to read this cookie.",
                    f"Cookie {cookie_name!r} lacks HttpOnly.",
                    "Add HttpOnly to cookies that do not require JavaScript access.",
                    cwe="CWE-1004",
                )
            )
        if "samesite=" not in lower_cookie:
            findings.append(
                _finding(
                    "cookie-samesite",
                    "Cookie is missing the SameSite attribute",
                    "low",
                    url,
                    "The cookie does not explicitly restrict cross-site requests.",
                    f"Cookie {cookie_name!r} lacks SameSite.",
                    "Set SameSite=Lax or Strict where application behavior permits it.",
                    cwe="CWE-1275",
                )
            )

    for disclosure_header in ("server", "x-powered-by"):
        if disclosure_header in lower_headers:
            findings.append(
                _finding(
                    f"disclosure-{disclosure_header}",
                    "Technology information is disclosed",
                    "info",
                    url,
                    "Response headers reveal implementation details that can aid reconnaissance.",
                    f"{disclosure_header}: {lower_headers[disclosure_header]}",
                    "Remove or generalize unnecessary technology-identifying headers.",
                    cwe="CWE-200",
                    status="informational",
                )
            )

    allow_origin = lower_headers.get("access-control-allow-origin", "").strip()
    allow_credentials = lower_headers.get(
        "access-control-allow-credentials", ""
    ).strip().lower()
    if allow_origin == "*" and allow_credentials == "true":
        findings.append(
            _finding(
                "cors-wildcard-credentials",
                "CORS policy combines wildcard origin with credentials",
                "low",
                url,
                "The response declares both a wildcard allowed origin and credential support. Browsers reject this combination, but it indicates an inconsistent CORS policy.",
                "Access-Control-Allow-Origin: *; Access-Control-Allow-Credentials: true",
                "Use explicit trusted origins when credentials are required, or disable credentialed CORS.",
                cwe="CWE-942",
            )
        )
    elif allow_origin == "null" and allow_credentials == "true":
        findings.append(
            _finding(
                "cors-null-credentials",
                "Credentialed CORS trusts the null origin",
                "medium",
                url,
                "The response permits credentialed requests from the null origin, which requires manual exploitability review.",
                "Access-Control-Allow-Origin: null; Access-Control-Allow-Credentials: true",
                "Remove null-origin trust and allowlist only required application origins.",
                confidence="medium",
                cwe="CWE-942",
                status="needs-review",
            )
        )

    content_type = lower_headers.get("content-type", "")
    path = urlsplit(url).path.lower().rstrip("/")
    if path == "/.git" and status_code == 200:
        git_indicators = ("directory listing", "objects/", "refs/", "head")
        if any(indicator in body.lower() for indicator in git_indicators):
            findings.append(
                _finding(
                    "exposed-git-metadata",
                    "Git repository metadata is publicly accessible",
                    "high",
                    url,
                    "A linked .git path returned content consistent with exposed repository metadata.",
                    "The .git path returned HTTP 200 with repository or directory-listing indicators.",
                    "Block access to version-control metadata and deploy from a clean build artifact.",
                    cwe="CWE-200",
                )
            )
    lower_body = body.lower()
    if status_code == 200 and path != "/.git":
        directory_indicators = ("<title>index of /", "<title>directory listing for ")
        if any(indicator in lower_body for indicator in directory_indicators):
            findings.append(
                _finding(
                    "directory-listing",
                    "Directory listing is enabled",
                    "medium",
                    url,
                    "The server returned a browsable directory index that may expose unintended files.",
                    "HTTP 200 response contains a directory-index title.",
                    "Disable directory indexing and publish only required application files.",
                    cwe="CWE-548",
                )
            )
    if status_code == 200 and path.endswith(".map"):
        if '"sources"' in body and '"mappings"' in body:
            findings.append(
                _finding(
                    "source-map-exposure",
                    "JavaScript source map is publicly accessible",
                    "low",
                    url,
                    "A linked source map may reveal original source paths and application logic.",
                    "HTTP 200 response contains source-map sources and mappings fields.",
                    "Exclude production source maps or restrict access when they contain sensitive implementation details.",
                    cwe="CWE-200",
                )
            )
    debug_indicators = (
        "traceback (most recent call last)",
        "werkzeug debugger",
        "django technical 500 response",
        "whoops, looks like something went wrong",
    )
    if status_code >= 500 and any(indicator in lower_body for indicator in debug_indicators):
        findings.append(
            _finding(
                "debug-error-disclosure",
                "Detailed application error is exposed",
                "medium",
                url,
                "A server error response contains a recognizable debug or stack-trace marker.",
                "HTTP 5xx response exposed a framework debugging signature.",
                "Disable production debug mode and return generic error pages while logging details server-side.",
                cwe="CWE-209",
            )
        )
    if "text/html" in content_type.lower() and body:
        parser = parse_page(url, body)
        if parser.insecure_resources:
            examples = ", ".join(sorted(parser.insecure_resources)[:3])
            findings.append(
                _finding(
                    "mixed-content",
                    "HTTPS page references insecure resources",
                    "medium",
                    url,
                    "An HTTPS page references resources over unencrypted HTTP.",
                    f"Insecure resource examples: {examples}",
                    "Serve every page resource over HTTPS and update absolute URLs.",
                    cwe="CWE-319",
                )
            )
        insecure_forms = [action for action in parser.password_forms if action.startswith("http://")]
        if insecure_forms:
            findings.append(
                _finding(
                    "password-form-http",
                    "Password form submits over HTTP",
                    "high",
                    url,
                    "A password form action uses an unencrypted HTTP URL.",
                    f"Form action: {insecure_forms[0]}",
                    "Submit credentials only to HTTPS endpoints.",
                    cwe="CWE-319",
                )
            )

    return findings


SQL_ERROR_PATTERNS = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"you have an error in your sql syntax",
        r"warning:\s*mysql",
        r"unclosed quotation mark after the character string",
        r"postgresql.*error",
        r"pg_query\(\).*failed",
        r"ora-\d{5}",
        r"sqlite(?:3)?\.operationalerror",
        r"sqlstate\[[0-9a-z]+\]",
    )
)


def detect_new_sql_error(baseline: str, probe_body: str) -> str | None:
    for pattern in SQL_ERROR_PATTERNS:
        match = pattern.search(probe_body)
        if match and not pattern.search(baseline):
            return match.group(0)[:160]
    return None
