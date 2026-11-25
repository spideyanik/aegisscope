import tempfile
import unittest
from pathlib import Path

from aegisscope.models import ScanResult
from aegisscope.report import write_reports


class ReportTests(unittest.TestCase):
    def test_markdown_contains_complete_discovered_subdomain_list(self) -> None:
        result = ScanResult(
            target="https://example.com/",
            started_at="2026-01-01T00:00:00+00:00",
            completed_at="2026-01-01T00:00:01+00:00",
            reconnaissance={
                "hostname": "example.com",
                "dns": {"addresses": [], "error": None},
                "tls": {},
                "certificate_transparency": {"subdomains": []},
                "subdomain_discovery": {
                    "candidate_count": 2,
                    "discovered_names": ["api.example.com", "portal.example.com"],
                },
                "resolved_subdomains": [],
            },
        )

        with tempfile.TemporaryDirectory() as directory:
            json_path, markdown_path = write_reports(result, Path(directory))
            markdown = markdown_path.read_text(encoding="utf-8")
            report_json = json_path.read_text(encoding="utf-8")

        self.assertIn("### Complete Discovered Subdomain List", markdown)
        self.assertIn("`api.example.com`", markdown)
        self.assertIn("`portal.example.com`", markdown)
        self.assertIn('"discovered_names"', report_json)
