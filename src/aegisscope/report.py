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
    lines = [
        "# AegisScope Security Assessment",
        "",
        f"- Target: `{result.target}`",
        f"- Started: `{result.started_at}`",
        f"- Completed: `{result.completed_at}`",
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
        "> Findings are indicators requiring human verification, not proof of compromise.",
        "",
    ]
    if not findings:
        lines.extend(["## Findings", "", "No findings were produced.", ""])
    for index, finding in enumerate(findings, start=1):
        lines.extend(
            [
                f"## {index}. {finding.title}",
                "",
                f"- Severity: **{finding.severity.upper()}**",
                f"- Confidence: `{finding.confidence}`",
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
