import json
import tempfile
import unittest
from pathlib import Path

from aegisscope.cli import choose_profile, choose_scan_type, configure_scan_type, run
from aegisscope.config import create_config


class CliTests(unittest.TestCase):
    def test_scan_type_choice_and_configuration(self) -> None:
        self.assertEqual(choose_scan_type("4"), "ports")
        config = create_config("https://example.com", "Example", "self-owned")
        configure_scan_type(config, "ports")
        self.assertTrue(config.reconnaissance)
        self.assertTrue(config.port_scan)
        self.assertFalse(config.web_scan)
        self.assertFalse(config.passive_subdomains)
        self.assertFalse(config.dns_wordlist_subdomains)
        configure_scan_type(config, "subdomains")
        self.assertFalse(config.passive_subdomains)
        subdomain_config = create_config(
            "https://example.com", "Example", "self-owned", allow_subdomains=True
        )
        configure_scan_type(subdomain_config, "subdomains")
        self.assertTrue(subdomain_config.passive_subdomains)
        self.assertTrue(subdomain_config.dns_wordlist_subdomains)

    def test_nmap_configuration_round_trip(self) -> None:
        config = create_config("https://example.com", "Example", "self-owned")
        config.port_scan = True
        config.port_scan_engine = "nmap"
        config.nmap_profile = "safe-services"

        loaded = type(config).from_dict(config.to_dict())

        self.assertEqual(loaded.port_scan_engine, "nmap")
        self.assertEqual(loaded.nmap_profile, "safe-services")

    def test_nmap_scan_requires_explicit_confirmation(self) -> None:
        config = create_config("https://example.com", "Example", "self-owned")
        config.port_scan = True
        config.web_scan = False
        config.port_scan_engine = "nmap"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps(config.to_dict()), encoding="utf-8")

            result = run(["scan", "--config", str(path)])

        self.assertEqual(result, 2)

    def test_www_subdomain_scope_uses_parent_domain(self) -> None:
        config = create_config(
            "https://www.example.com", "Example", "self-owned", allow_subdomains=True
        )
        self.assertEqual(config.allowed_hosts, ["example.com"])
        self.assertTrue(config.scope.is_allowed("https://api.example.com/"))

    def test_profile_choice_accepts_number_or_name(self) -> None:
        self.assertEqual(choose_profile("2"), "injection")
        self.assertEqual(choose_profile("redirect"), "redirect")
        with self.assertRaises(ValueError):
            choose_profile("99")

    def test_init_and_validate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            result = run(
                [
                    "init",
                    "https://example.com",
                    "--owner",
                    "Example",
                    "--authorization-reference",
                    "self-owned",
                    "--output",
                    str(path),
                ]
            )
            self.assertEqual(result, 0)
            data = json.loads(path.read_text(encoding="utf-8"))
            self.assertFalse(data["active_probes"])
            self.assertEqual(run(["validate", "--config", str(path)]), 0)
            self.assertEqual(
                run(
                    [
                        "scan",
                        "--config",
                        str(path),
                        "--profile",
                        "injection",
                        "--confirm-authorization",
                    ]
                ),
                2,
            )


if __name__ == "__main__":
    unittest.main()
