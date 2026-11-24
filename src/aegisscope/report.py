from __future__ import annotations

import json
from pathlib import Path

from .models import SEVERITY_ORDER, ScanResult


def write_reports(result: ScanResult, output_dir: str | Path) -> tuple[Path, Path]:
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    json_path = directory / "report.json"
    markdown_path = directory / "report.md"
    json_path.write_text(
        json.dumps(result.to_dict(), indent=2, sort_keys=False) + "\n", encoding="utf-8"
    )

    findings = sorted(
        result.findings,
        key=lambda finding: (SEVERITY_ORDER.get(finding.severity, 99), finding.title),
    )
    counts = {
        severity: sum(finding.severity == severity for finding in findings)
        for severity in ("high", "medium", "low", "info")
    }
    status_counts = {
        status: sum(finding.status == status for finding in findings)
        for status in ("confirmed", "likely", "needs-review", "informational")
    }
    lines = [
        "# AegisScope Security Assessment",
        "",
        f"- Target: `{result.target}`",
        f"- Started: `{result.started_at}`",
        f"- Completed: `{result.completed_at}`",
        f"- Modules: `{', '.join(result.modules) or 'none'}`",
        f"- Assessment profile: `{result.profile}`",
        f"- Active probes used: `{'yes' if result.active_probes_used else 'no'}`",
        f"- Requests sent: `{result.stats.requests_sent}`",
        f"- Pages visited: `{result.stats.pages_visited}`",
        "",
        "## Summary",
        "",
        "| High | Medium | Low | Info |",
        "|---:|---:|---:|---:|",
        f"| {counts['high']} | {counts['medium']} | {counts['low']} | {counts['info']} |",
        "",
        "| Confirmed | Likely | Needs review | Informational |",
        "|---:|---:|---:|---:|",
        f"| {status_counts['confirmed']} | {status_counts['likely']} | {status_counts['needs-review']} | {status_counts['informational']} |",
        "",
        "> Findings are indicators requiring human verification, not proof of compromise.",
        "",
    ]
    recon = result.reconnaissance
    if recon:
        dns = recon.get("dns", {})
        tls = recon.get("tls", {})
        certificate_transparency = recon.get("certificate_transparency", {})
        ct_subdomains = certificate_transparency.get("subdomains", [])
        certificate_subdomains = recon.get("certificate_subdomains", [])
        linked_hosts = sorted(recon.get("linked_hosts", []))
        resolved_subdomains = recon.get("resolved_subdomains", [])
        lines.extend(
            [
                "## Reconnaissance",
                "",
                f"- Hostname: `{recon.get('hostname', 'unknown')}`",
                f"- Port: `{recon.get('port', 'unknown')}`",
                f"- IP addresses: `{', '.join(dns.get('addresses', [])) or 'none observed'}`",
                f"- DNS error: `{dns.get('error') or 'none'}`",
                f"- TLS protocol: `{tls.get('protocol', 'not observed')}`",
                f"- TLS cipher: `{tls.get('cipher', 'not observed')}`",
                f"- Certificate issuer: `{tls.get('issuer', 'not observed')}`",
                f"- Certificate expiry: `{tls.get('not_after', 'not observed')}`",
                f"- TLS inspection error: `{tls.get('error') or 'none'}`",
                "",
                "### Discovered Hosts",
                "",
                f"- Certificate subdomains: `{', '.join(certificate_subdomains[:100]) or 'none observed'}`",
                f"- Certificate Transparency domain: `{certificate_transparency.get('domain', 'not queried')}`",
                f"- Certificate Transparency source: `{certificate_transparency.get('source') or 'none'}`",
                f"- Certificate Transparency subdomains: `{', '.join(ct_subdomains[:100]) or 'none observed'}`",
                f"- Certificate Transparency result count: `{len(ct_subdomains)}`",
                f"- Certificate Transparency error: `{certificate_transparency.get('error') or 'none'}`",
                f"- Linked subdomains: `{', '.join(linked_hosts[:100]) or 'none observed'}`",
                f"- DNS-resolved subdomains: `{len(resolved_subdomains)}`",
                f"- Discovered GET forms: `{len(recon.get('discovered_get_forms', []))}`",
                "",
                "### Resolved Subdomains",
                "",
            ]
        )
        if resolved_subdomains:
            lines.extend(["| Hostname | Addresses |", "|---|---|"])
            for item in resolved_subdomains[:100]:
                lines.append(
                    f"| `{item['hostname']}` | `{', '.join(item['addresses'])}` |"
                )
        else:
            lines.append("No discovered subdomain resolved within the configured limit.")

        lines.extend(["", "### Network Provider", ""])
        provider_records = recon.get("provider_records", [])
        if provider_records:
            lines.extend(
                [
                    "| Address | Network | Country | Entities | Error |",
                    "|---|---|---|---|---|",
                ]
            )
            for item in provider_records:
                lines.append(
                    f"| `{item.get('address', '')}` | `{item.get('network_name') or 'unknown'}` | "
                    f"`{item.get('country') or 'unknown'}` | `{', '.join(item.get('entities', [])) or 'none'}` | "
                    f"`{item.get('error') or 'none'}` |"
                )
        else:
            lines.append("Provider lookup was disabled or no address was available.")

        lines.extend(["", "### Common TCP Ports", ""])
        port_scan = recon.get("port_scan")
        if port_scan:
            lines.append(
                f"Scanned `{len(port_scan.get('scanned_ports', []))}` bounded TCP ports on `{port_scan.get('hostname', '')}`."
            )
            open_ports = port_scan.get("open_ports", [])
            if open_ports:
                lines.extend(["", "| Port | Service |", "|---:|---|"])
                for item in open_ports:
                    lines.append(f"| {item['port']} | {item['service']} |")
            else:
                lines.extend(["", "No configured TCP port accepted a connection."])
            lines.extend(["", port_scan.get("note", ""), ""])
        else:
            lines.extend(["Port scanning was not selected.", ""])

        lines.extend(["### Technology Evidence", ""])
        technologies = recon.get("technologies", [])
        if technologies:
            lines.extend(["| Technology | Version | Evidence | Confidence |", "|---|---|---|---|"])
            for item in technologies:
                lines.append(
                    f"| {item['name']} | {item['version']} | {item['evidence']} | {item['confidence']} |"
                )
        else:
            lines.append("No technology fingerprints were observed.")
        lines.extend(["", "### Observed Response Headers", ""])
        observed_headers = recon.get("observed_headers", {})
        if observed_headers:
            lines.extend(["| Header | Value |", "|---|---|"])
            for name, value in sorted(observed_headers.items()):
                safe_value = str(value).replace("|", "\\|").replace("\n", " ")
                lines.append(f"| `{name}` | `{safe_value}` |")
        else:
            lines.append("No allowlisted response headers were observed.")
        lines.extend(["", "### OS Assessment", ""])
        operating_systems = recon.get("possible_operating_systems", [])
        if operating_systems:
            lines.extend(f"- {item}" for item in operating_systems)
        else:
            lines.append("- No defensible operating-system hint was observed.")
        lines.extend(
            [
                "- HTTP/TLS fingerprinting cannot reliably determine the server OS or patch level.",
                "- Version evidence does not prove a CVE is exploitable; confirm deployment and patch status manually.",
                "",
            ]
        )
    if not findings:
        lines.extend(["## Findings", "", "No findings were produced.", ""])
    for index, finding in enumerate(findings, start=1):
        lines.extend(
            [
                f"## {index}. {finding.title}",
                "",
                f"- Severity: **{finding.severity.upper()}**",
                f"- Confidence: `{finding.confidence}`",
                f"- Verification status: **{finding.status.upper()}**",
                f"- Check: `{finding.check_id}`",
                f"- URL: `{finding.url}`",
                f"- CWE: `{finding.cwe or 'Not assigned'}`",
                "",
                finding.description,
                "",
                "**Evidence**",
                "",
                finding.evidence,
                "",
                "**Remediation**",
                "",
                finding.remediation,
                "",
            ]
        )
    markdown_path.write_text("\n".join(lines), encoding="utf-8")
    return json_path, markdown_path
