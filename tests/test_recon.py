import unittest
from unittest.mock import Mock, patch

import httpx

from aegisscope.recon import (
    fingerprint_http,
    is_related_subdomain,
    parse_ct_entries,
    parse_rdap_record,
    registrable_domain,
    scan_common_ports,
)


class ReconTests(unittest.TestCase):
    def test_rdap_provider_record_extracts_network_owner(self) -> None:
        record = parse_rdap_record(
            "203.0.113.10",
            {
                "name": "EXAMPLE-NET",
                "country": "US",
                "entities": [
                    {
                        "vcardArray": [
                            "vcard",
                            [["fn", {}, "text", "Example Hosting Provider"]],
                        ]
                    }
                ],
            },
        )
        self.assertEqual(record["network_name"], "EXAMPLE-NET")
        self.assertEqual(record["entities"], ["Example Hosting Provider"])

    def test_common_port_scan_reports_only_open_ports(self) -> None:
        def connect(address: tuple[str, int], timeout: float) -> Mock:
            if address[1] != 22:
                raise ConnectionRefusedError
            connection = Mock()
            connection.close = Mock()
            return connection

        with patch("aegisscope.recon.socket.create_connection", side_effect=connect):
            result = scan_common_ports("example.com", [22, 80], 0.2)
        self.assertEqual(result["open_ports"], [{"port": 22, "service": "SSH"}])

    def test_registrable_domain_handles_multi_level_suffix(self) -> None:
        self.assertEqual(
            registrable_domain("www.example.ac.in"),
            "example.ac.in",
        )

    def test_certificate_transparency_entries_are_normalized(self) -> None:
        entries = [
            {"name_value": "*.example.com\napi.example.com"},
            {"dns_names": ["www.example.com", "cdn.example.com"]},
            {"name_value": "example.com.evil.test"},
            {"name_value": "API.example.com"},
        ]
        self.assertEqual(
            parse_ct_entries(entries, "example.com"),
            ["api.example.com", "cdn.example.com", "www.example.com"],
        )

    def test_related_subdomains_include_www_siblings(self) -> None:
        self.assertTrue(is_related_subdomain("api.example.com", "www.example.com"))
        self.assertFalse(is_related_subdomain("example.com.evil.test", "example.com"))
        self.assertFalse(is_related_subdomain("example.com", "example.com"))

    def test_http_fingerprint_preserves_evidence_and_confidence(self) -> None:
        fingerprint = fingerprint_http(
            httpx.Headers(
                {
                    "server": "nginx/1.24.0 (Ubuntu)",
                    "x-powered-by": "PHP/8.3.1",
                }
            ),
            '<html><meta name="generator" content="WordPress 6.5.2">'
            '<script src="/_next/static/app.js"></script></html>',
        )
        technologies = {
            (item["name"], item["version"])
            for item in fingerprint["technologies"]
        }
        self.assertIn(("nginx", "1.24.0"), technologies)
        self.assertIn(("PHP", "8.3.1"), technologies)
        self.assertIn(("WordPress", "6.5.2"), technologies)
        self.assertIn(("Next.js", "unknown"), technologies)
        next_item = next(
            item for item in fingerprint["technologies"] if item["name"] == "Next.js"
        )
        self.assertEqual(next_item["confidence"], "low")
        self.assertTrue(
            any("Ubuntu" in item for item in fingerprint["possible_operating_systems"])
        )
        self.assertEqual(fingerprint["observed_headers"]["server"], "nginx/1.24.0 (Ubuntu)")


if __name__ == "__main__":
    unittest.main()
