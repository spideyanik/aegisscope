# AegisScope

![AegisScope logo](assets/aegisscope-logo.svg)

**Made by SpideyAnon**

AegisScope is a Linux-only, scope-enforced web security assessment CLI for websites you own or have explicit permission to test. Arch Linux is the primary supported platform. It inventories DNS, TLS, certificate subdomains, linked hosts, and technology evidence; crawls authorized pages; performs passive security checks; optionally runs non-destructive GET-parameter canaries; and generates evidence-focused reports.

> Use AegisScope only under current written authorization. A successful scan does not prove an application is secure, and every finding requires human verification.

## Current capabilities

- Exact-host and optional subdomain allowlists
- HTTP/HTTPS scheme restrictions
- Redirect scope enforcement
- Request-rate, page, response-size, and total-request limits
- Same-scope HTML crawling with GET-form inventory and no POST submission
- DNS addresses and TLS certificate inventory
- Passive subdomain discovery from certificate names and page links
- Certificate Transparency discovery with Cert Spotter and crt.sh fallback
- Bounded DNS resolution for discovered subdomains
- Passive RDAP network and hosting-provider details
- Bounded common TCP-port exposure scanning without service exploitation
- Safe raw response-header inventory in JSON and Markdown reports
- Server, framework, version, and low-confidence OS evidence
- Security header, cookie, mixed-content, and password-form checks
- Optional input-reflection, SQL-error, and open-redirect indicators
- Query-value redaction in reports and audit logs
- JSON and Markdown reports plus a JSONL request audit trail
- Verification labels separating confirmed, likely, review-required, and informational results
- Environment-variable expansion for authentication headers

AegisScope does not perform denial of service, password attacks, data extraction, persistence, malware delivery, file writes, or automatic exploitation.

## Install

Linux and Python 3.11 or newer are required. Windows and macOS are intentionally unsupported.

On Arch Linux and Arch-based distributions:

```bash
sudo pacman -S --needed python python-pipx git
pipx ensurepath
pipx install git+https://github.com/OWNER/aegisscope.git
```

Start a URL-first assessment:

```bash
aegisscope owner-setup
aegisscope assess https://staging.example.com
```

The owner setup command stores only a salted PBKDF2 hash in `~/.config/aegisscope/owner-policy.json` with `0600` permissions. Every passive or active assessment requires the matching owner-issued code before any network request. After entering the URL, choose a scan type and, when web scanning is selected, a web profile.

The local access-code gate controls ordinary use of the installed CLI. It does not replace written permission from the website owner, and it cannot prevent someone with source-code or administrator access from modifying their own copy.

Every command launch displays the AegisScope terminal shield and project attribution. Package installation intentionally avoids post-install scripts; the logo appears when the installed command is started.

For local development:

```bash
git clone https://github.com/OWNER/aegisscope.git
cd aegisscope
python -m venv .venv
. .venv/bin/activate
python -m pip install -e .
```

For a globally available command in an isolated environment:

```bash
pipx install .
```

## Configure

The easiest first run is the guided menu:

```bash
aegisscope
```

After defining or loading an authorized target, choose a scan type:

- Host and provider scan: DNS, IP addresses, TLS, HTTP technology, and RDAP provider details
- Subdomain scan: Certificate Transparency names and bounded DNS resolution
- Web vulnerability scan: safe crawling and the selected web assessment profile
- Common-port exposure scan: bounded TCP connection checks without exploitation
- Full authorized scan: host, provider, subdomain, port, and web modules

Web and full scans then offer these profiles:

- Passive audit: safe crawling, headers, cookies, and mixed-content checks
- Injection indicators: passive checks plus harmless reflection and database-error canaries
- Redirect validation: passive checks plus a reserved-domain open-redirect canary
- Full safe assessment: every currently implemented non-destructive check

You can also start the menu explicitly and choose other file locations:

```bash
aegisscope guided --config aegisscope.json --output-dir reports
```

Every scan requires the configured owner authorization code. Active web profiles never submit POST forms, follow an external redirect, extract database data, or attempt code execution.

## Reconnaissance accuracy

AegisScope reports observed IP addresses, TLS protocol and certificate metadata, certificate subdomains, linked subdomains, HTTP technology headers, HTML framework markers, and exposed versions. It does not scan a discovered host unless the scope configuration permits it.

Certificate Transparency discovery sends the registrable domain, but no credentials or page content, to Cert Spotter or the crt.sh fallback. Set `"passive_subdomains": false` in the configuration to disable third-party lookups.

An HTTP banner cannot reliably identify the server operating system, patch level, or exploitable CVEs. OS values are therefore labeled as low-confidence hints. Exposed software versions are evidence for manual advisory review, not proof of vulnerability.

An open TCP port confirms network exposure only. It is not automatically a vulnerability. AegisScope flags selected administrative and database ports for review but does not authenticate, enumerate, brute-force, or exploit the service.

## Finding verification

- `confirmed`: the exact configuration weakness or behavior was directly reproduced, such as an open redirect or exposed Git metadata
- `likely`: strong evidence exists, but exploitability still depends on application context
- `needs-review`: a safe canary found an indicator such as reflected input, not a proven exploit
- `informational`: inventory or diagnostic evidence with no vulnerability claim

AegisScope does not claim to find every vulnerability. Authentication flaws, IDOR, business-logic abuse, stored XSS, and many authorization issues require controlled test accounts and human analysis.

## When no bugs are found

- `passive` reports reconnaissance and directly observed configuration weaknesses; it does not mutate inputs.
- `injection` requires query parameters or discovered non-password GET forms before it can send safe canaries.
- `redirect` tests only recognized redirect parameters such as `next`, `url`, and `return`.
- `full-safe` runs every implemented non-destructive check but still cannot prove the absence of vulnerabilities.
- Review `report.md` for DNS, TLS, Certificate Transparency, header, and request-error diagnostics.

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
aegisscope scan --config aegisscope.json --scan-type full --output-dir reports
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

Proprietary. Copyright 2026 SpideyAnon. Access and use require prior written authorization. See `LICENSE`.
