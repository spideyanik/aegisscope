import tempfile
import unittest
from pathlib import Path
from urllib.parse import parse_qs

import httpx

from aegisscope.config import ScanConfig
from aegisscope.scanner import Scanner


class ScannerTests(unittest.TestCase):
    def test_active_canaries_and_scope_blocking(self) -> None:
        requested_hosts: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requested_hosts.append(request.url.host)
            value = parse_qs(request.url.query.decode()).get("next", [""])[0]
            headers = {
                "content-type": "text/html",
                "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
                "x-content-type-options": "nosniff",
                "referrer-policy": "same-origin",
                "permissions-policy": "camera=()",
            }
            if value == "https://example.invalid/aegisscope":
                return httpx.Response(302, headers={**headers, "location": value})
            if value.endswith("'"):
                return httpx.Response(
                    500, headers=headers, text="You have an error in your SQL syntax"
                )
            body = (
                f'<html>{value}<a href="/child">child</a>'
                '<a href="https://outside.test/">outside</a></html>'
            )
            return httpx.Response(200, headers=headers, text=body)

        config = ScanConfig(
            target="http://owned.test/?next=home",
            allowed_hosts=["owned.test"],
            allowed_schemes=["http"],
            authorization_owner="Test Owner",
            authorization_reference="unit-test",
            active_probes=True,
            max_pages=1,
            max_requests=10,
            requests_per_second=20,
        )
        with tempfile.TemporaryDirectory() as directory:
            with Scanner(
                config,
                Path(directory) / "audit.jsonl",
                profile="full-safe",
                transport=httpx.MockTransport(handler),
            ) as scanner:
                result = scanner.run()

        check_ids = {finding.check_id for finding in result.findings}
        self.assertIn("input-reflection", check_ids)
        self.assertIn("sql-error-indicator", check_ids)
        self.assertIn("open-redirect-indicator", check_ids)
        self.assertGreaterEqual(result.stats.blocked_urls, 1)
        self.assertEqual(set(requested_hosts), {"owned.test"})

        requested_hosts.clear()
        with tempfile.TemporaryDirectory() as directory:
            with Scanner(
                config,
                Path(directory) / "audit.jsonl",
                profile="injection",
                transport=httpx.MockTransport(handler),
            ) as scanner:
                injection_result = scanner.run()
        injection_ids = {finding.check_id for finding in injection_result.findings}
        self.assertIn("input-reflection", injection_ids)
        self.assertIn("sql-error-indicator", injection_ids)
        self.assertNotIn("open-redirect-indicator", injection_ids)
        self.assertEqual(injection_result.stats.requests_sent, 3)


if __name__ == "__main__":
    unittest.main()
