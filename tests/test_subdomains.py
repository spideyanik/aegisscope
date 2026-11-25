import unittest
from unittest.mock import patch

from aegisscope.subdomains import (
    discover_subdomains,
    normalize_subdomain,
    parse_hackertarget,
    parse_otx,
)


class SubdomainDiscoveryTests(unittest.TestCase):
    @patch("aegisscope.subdomains.resolve_hostname", return_value=[])
    @patch("aegisscope.subdomains.collect_passive_sources")
    def test_dns_only_discovery_skips_third_party_sources(
        self, passive_sources, _resolve_hostname
    ) -> None:
        result = discover_subdomains(
            "example.com",
            timeout=5,
            max_resolved=5,
            dns_wordlist=True,
            passive_sources=False,
        )

        passive_sources.assert_not_called()
        self.assertEqual(result["passive_sources"], [])
        self.assertTrue(result["dns_wordlist_enabled"])

    def test_source_parsers_normalize_and_reject_unrelated_hosts(self) -> None:
        self.assertEqual(
            parse_hackertarget(
                "api.example.com,192.0.2.1\nexample.com.evil.test,192.0.2.2",
                "example.com",
            ),
            ["api.example.com"],
        )
        self.assertEqual(
            parse_otx(
                {
                    "passive_dns": [
                        {"hostname": "MAIL.EXAMPLE.COM"},
                        {"hostname": "unrelated.test"},
                    ]
                },
                "example.com",
            ),
            ["mail.example.com"],
        )
        self.assertIsNone(normalize_subdomain("example.com.evil.test", "example.com"))

    @patch("aegisscope.subdomains.secrets.token_hex", return_value="fixed")
    @patch("aegisscope.subdomains.resolve_hostname")
    @patch("aegisscope.subdomains.collect_passive_sources")
    def test_discovery_attributes_sources_and_filters_wordlist_wildcards(
        self, passive_sources, resolve_hostname, _token
    ) -> None:
        passive_sources.return_value = [
            {
                "name": "AlienVault OTX",
                "hostnames": ["api.example.com"],
                "error": None,
            }
        ]

        def resolve(hostname: str) -> list[str]:
            if hostname.startswith("aegis-fixed-") or hostname in {
                "api.example.com",
                "www.example.com",
            }:
                return ["192.0.2.50"]
            return []

        resolve_hostname.side_effect = resolve
        result = discover_subdomains(
            "example.com",
            timeout=5,
            max_resolved=100,
            dns_wordlist=True,
        )
        resolved = {item["hostname"]: item for item in result["resolved"]}
        self.assertIn("api.example.com", resolved)
        self.assertEqual(
            resolved["api.example.com"]["sources"],
            ["AlienVault OTX", "DNS wordlist"],
        )
        self.assertTrue(resolved["api.example.com"]["wildcard_match"])
        self.assertIn("www.example.com", result["wildcard_filtered"])
        self.assertEqual(result["discovered_names"], ["api.example.com"])


if __name__ == "__main__":
    unittest.main()
