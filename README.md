# AegisScope

AegisScope is a scope-enforced web security assessment CLI for websites you own or have explicit permission to test. It crawls authorized pages, performs passive security checks, optionally runs a small set of non-destructive GET-parameter canaries, and generates evidence-focused reports.

> Use AegisScope only under current written authorization. A successful scan does not prove an application is secure, and every finding requires human verification.

## Current capabilities

- Exact-host and optional subdomain allowlists
- HTTP/HTTPS scheme restrictions
- Redirect scope enforcement
- Request-rate, page, response-size, and total-request limits
- Same-scope HTML crawling without form submission
- Security header, cookie, mixed-content, and password-form checks
- Optional input-reflection, SQL-error, and open-redirect indicators
- Query-value redaction in reports and audit logs
- JSON and Markdown reports plus a JSONL request audit trail
- Environment-variable expansion for authentication headers

AegisScope does not perform denial of service, password attacks, data extraction, persistence, malware delivery, file writes, or automatic exploitation.

## Install

Python 3.11 or newer is required.

```bash
cd /home/anik/Projects/aegisscope
python -m venv .venv
. .venv/bin/activate
python -m pip install -e .
```

For a globally available command in an isolated environment:

```bash
pipx install /home/anik/Projects/aegisscope
```

## Configure

The easiest first run is the guided menu:

```bash
aegisscope
```

You will define or load an authorized target and choose one of these profiles:

- Passive audit: safe crawling, headers, cookies, and mixed-content checks
- Injection indicators: passive checks plus harmless reflection and database-error canaries
- Redirect validation: passive checks plus a reserved-domain open-redirect canary
- Full safe assessment: every currently implemented non-destructive check

You can also start the menu explicitly and choose other file locations:

```bash
aegisscope guided --config aegisscope.json --output-dir reports
```

Active profiles require the exact interactive authorization confirmation. They never submit forms, follow an external redirect, extract database data, or attempt code execution.

## Non-interactive use

Create a passive configuration:

```bash
aegisscope init https://staging.example.com \
  --owner "Example Company" \
  --authorization-reference "SEC-2026-001"
```

Review `aegisscope.json` carefully. Authentication values should come from environment variables rather than being committed:

```json
"headers": {
  "Authorization": "${AEGISSCOPE_AUTHORIZATION}"
}
```

Validate and run:

```bash
aegisscope validate --config aegisscope.json
aegisscope scan --config aegisscope.json --output-dir reports
```

The output directory contains `report.json`, `report.md`, and `audit.jsonl`.

## Active profiles

Active mode mutates only existing GET query parameters. It uses an alphanumeric reflection marker, one trailing single quote to identify newly exposed database errors, and `example.invalid` to identify unvalidated redirects. It does not submit forms or follow the external redirect.

Enable them only after reviewing the target and testing on staging:

1. Set `"active_probes": true` in `aegisscope.json`.
2. Run with both required command-line gates:

```bash
aegisscope scan --config aegisscope.json --output-dir reports \
  --profile injection --confirm-authorization
```

Available profile names are `passive`, `injection`, `redirect`, and `full-safe`.

## Safe testing

Run the unit tests before changing scanner behavior:

```bash
python -m unittest discover -s tests -v
```

Use intentionally vulnerable local applications such as OWASP Juice Shop or WebGoat for development. Start against staging with low request limits. Do not point development builds at third-party systems.

## Roadmap

- Authenticated browser crawling with Playwright
- OpenAPI import and API inventory
- Two-account authorization/IDOR comparison workflow
- TLS certificate analysis
- Plugin SDK with mandatory scope-gated HTTP transport
- HTML dashboard and finding review workflow
- SARIF output for CI systems

## License

MIT
