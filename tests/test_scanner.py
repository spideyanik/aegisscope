import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs

import httpx

from aegisscope.config import ScanConfig
from aegisscope.scanner import Scanner


class ScannerTests(unittest.TestCase):
    @patch("aegisscope.scanner.collect_host_recon")
    def test_exact_host_scope_disables_subdomain_discovery(self, collect_recon) -> None:
        collect_recon.return_value = {
            "hostname": "owned.test",
            "dns": {"addresses": []},
            "tls": {"enabled": False},
            "technologies": [],
            "possible_operating_systems": [],
            "observed_headers": {},
        }
        config = ScanConfig(
            target="http://owned.test/",
            allowed_hosts=["owned.test"],
            allowed_schemes=["http"],
            authorization_owner="Test Owner",
            authorization_reference="unit-test",
            allow_subdomains=False,
            passive_subdomains=True,
            resolve_subdomains=True,
            dns_wordlist_subdomains=True,
            web_scan=False,
        )

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, headers={"content-type": "text/html"})

        with tempfile.TemporaryDirectory() as directory:
            with Scanner(
                config,
                Path(directory) / "audit.jsonl",
                transport=httpx.MockTransport(handler),
            ) as scanner:
                result = scanner.run()

        arguments = collect_recon.call_args.args
        self.assertFalse(arguments[2])
        self.assertFalse(arguments[4])
        self.assertFalse(arguments[5])
        self.assertNotIn("subdomains", result.modules)

    @patch("aegisscope.scanner.run_nmap_scan")
    def test_nmap_engine_feeds_network_findings(self, run_nmap) -> None:
        run_nmap.return_value = {
            "engine": "nmap",
            "profile": "safe-services",
            "hostname": "owned.test",
            "scanned_ports": [2375],
            "open_ports": [
                {
                    "port": 2375,
                    "service": "docker",
                    "version": "Docker 26.0",
                    "scripts": [],
                }
            ],
            "error": None,
        }
        config = ScanConfig(
            target="http://owned.test/",
            allowed_hosts=["owned.test"],
            allowed_schemes=["http"],
            authorization_owner="Test Owner",
            authorization_reference="unit-test",
            reconnaissance=False,
            web_scan=False,
            port_scan=True,
            port_scan_engine="nmap",
            nmap_profile="safe-services",
            common_ports=[2375],
        )

        with tempfile.TemporaryDirectory() as directory:
            with Scanner(config, Path(directory) / "audit.jsonl") as scanner:
                result = scanner.run()

        run_nmap.assert_called_once_with("owned.test", [2375], "safe-services", 180, 100)
        finding = next(
            item for item in result.findings if item.check_id == "network-service-exposure"
        )
        self.assertEqual(finding.severity, "high")
        self.assertEqual(result.reconnaissance["port_scan"]["engine"], "nmap")

    @patch("aegisscope.scanner.collect_host_recon")
    def test_host_only_scan_fingerprints_without_crawling(self, collect_recon) -> None:
        collect_recon.return_value = {
            "hostname": "owned.test",
            "dns": {"addresses": ["192.0.2.10"], "error": None},
            "tls": {"enabled": False},
            "technologies": [],
            "possible_operating_systems": [],
            "observed_headers": {},
        }
        config = ScanConfig(
            target="http://owned.test/",
            allowed_hosts=["owned.test"],
            allowed_schemes=["http"],
            authorization_owner="Test Owner",
            authorization_reference="unit-test",
            passive_subdomains=False,
            provider_lookup=False,
            web_scan=False,
        )

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                headers={"content-type": "text/html", "server": "nginx/1.24.0"},
                text="<html><a href='/not-crawled'>link</a></html>",
            )

        with tempfile.TemporaryDirectory() as directory:
            with Scanner(
                config,
                Path(directory) / "audit.jsonl",
                transport=httpx.MockTransport(handler),
            ) as scanner:
                result = scanner.run()
        self.assertEqual(result.stats.requests_sent, 1)
        self.assertEqual(result.stats.pages_visited, 1)
        self.assertEqual(result.reconnaissance["technologies"][0]["name"], "nginx")
        self.assertIn("header-content-security-policy", {item.check_id for item in result.findings})

    def test_error_and_linked_host_records_are_independent(self) -> None:
        config = ScanConfig(
            target="http://example.com/",
            allowed_hosts=["example.com"],
            allowed_schemes=["http"],
            authorization_owner="Test Owner",
            authorization_reference="unit-test",
            reconnaissance=False,
        )
        with tempfile.TemporaryDirectory() as directory:
            with Scanner(config, Path(directory) / "audit.jsonl") as scanner:
                scanner.result.reconnaissance = {
                    "hostname": "example.com",
                    "linked_hosts": [],
                }
                scanner._record_linked_host("https://api.example.com/")
                scanner._add_error("http://example.com/", RuntimeError("test"))
                self.assertEqual(
                    scanner.result.reconnaissance["linked_hosts"], ["api.example.com"]
                )
                self.assertEqual(
                    [finding.check_id for finding in scanner.result.findings],
                    ["request-error"],
                )

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
            reconnaissance=False,
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
        redirect_finding = next(
            finding for finding in result.findings if finding.check_id == "open-redirect-indicator"
        )
        self.assertEqual(redirect_finding.status, "confirmed")
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

    def test_probeable_routes_take_priority_over_crawl_backlog(self) -> None:
        crawled: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            path = request.url.path
            query = request.url.query.decode()
            if not query:
                crawled.append(path)
            headers = {"content-type": "text/html"}
            if path == "/":
                links = "".join(
                    f'<a href="/page-{index}">page</a>' for index in range(10)
                )
                return httpx.Response(
                    200,
                    headers=headers,
                    text=f'<a href="/form-source">form source</a>{links}',
                )
            if path == "/form-source":
                return httpx.Response(
                    200,
                    headers=headers,
                    text='<form action="/search"><input name="q"></form>',
                )
            if path == "/search":
                value = parse_qs(query, keep_blank_values=True).get("q", [""])[0]
                if value.endswith("'"):
                    return httpx.Response(
                        500, headers=headers, text="PostgreSQL error"
                    )
                return httpx.Response(200, headers=headers, text=value)
            return httpx.Response(200, headers=headers, text="ordinary page")

        config = ScanConfig(
            target="http://owned.test/",
            allowed_hosts=["owned.test"],
            allowed_schemes=["http"],
            authorization_owner="Test Owner",
            authorization_reference="unit-test",
            active_probes=True,
            reconnaissance=False,
            max_pages=3,
            max_requests=10,
            requests_per_second=20,
        )
        with tempfile.TemporaryDirectory() as directory:
            with Scanner(
                config,
                Path(directory) / "audit.jsonl",
                profile="injection",
                transport=httpx.MockTransport(handler),
            ) as scanner:
                result = scanner.run()

        self.assertEqual(crawled[:2], ["/", "/form-source"])
        self.assertTrue(result.active_probes_used)
        self.assertIn(
            "sql-error-indicator", {finding.check_id for finding in result.findings}
        )

    def test_active_profile_without_probeable_input_reports_no_probe_use(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                headers={"content-type": "text/html"},
                text="<html>No query input</html>",
            )

        config = ScanConfig(
            target="http://owned.test/",
            allowed_hosts=["owned.test"],
            allowed_schemes=["http"],
            authorization_owner="Test Owner",
            authorization_reference="unit-test",
            active_probes=True,
            reconnaissance=False,
            max_pages=1,
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

        self.assertFalse(result.active_probes_used)
        self.assertEqual(result.stats.requests_sent, 1)

    def test_report_target_redacts_query_values(self) -> None:
        config = ScanConfig(
            target="http://owned.test/?token=private-value",
            allowed_hosts=["owned.test"],
            allowed_schemes=["http"],
            authorization_owner="Test Owner",
            authorization_reference="unit-test",
            reconnaissance=False,
            max_pages=1,
            requests_per_second=20,
        )

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, headers={"content-type": "text/html"})

        with tempfile.TemporaryDirectory() as directory:
            with Scanner(
                config,
                Path(directory) / "audit.jsonl",
                transport=httpx.MockTransport(handler),
            ) as scanner:
                result = scanner.run()

        self.assertEqual(result.target, "http://owned.test/?token=REDACTED")
        self.assertNotIn("private-value", str(result.to_dict()))


if __name__ == "__main__":
    unittest.main()
