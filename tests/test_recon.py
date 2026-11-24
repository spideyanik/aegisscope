import unittest

import httpx

from aegisscope.recon import (
    fingerprint_http,
    is_related_subdomain,
    parse_ct_entries,
    registrable_domain,
)


class ReconTests(unittest.TestCase):
    def test_registrable_domain_handles_multi_level_suffix(self) -> None:
        self.assertEqual(
            registrable_domain("www.brainwareuniversity.ac.in"),
            "brainwareuniversity.ac.in",
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
