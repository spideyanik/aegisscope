import subprocess
import unittest
from unittest.mock import patch

from aegisscope.nmap_runner import (
    SAFE_SERVICE_SCRIPTS,
    build_nmap_command,
    parse_nmap_xml,
    run_nmap_scan,
)


NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up" reason="user-set"/>
    <address addr="192.0.2.10" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="closed" reason="conn-refused"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="https" product="nginx" version="1.24.0"/>
        <script id="ssl-cert" output="Subject: example.test"/>
      </port>
    </ports>
    <hostscript>
      <script id="dns-recursion" output="recursion enabled"/>
    </hostscript>
  </host>
</nmaprun>
"""


class NmapRunnerTests(unittest.TestCase):
    def test_safe_profile_builds_only_controlled_arguments(self) -> None:
        command = build_nmap_command(
            "/usr/bin/nmap",
            "owned.test",
            [443, 80, 443],
            "safe-services",
            120,
            50,
        )

        self.assertEqual(command[-2:], ["--", "owned.test"])
        self.assertIn("-sT", command)
        self.assertNotIn("-sS", command)
        self.assertEqual(command[command.index("-p") + 1], "80,443")
        scripts = command[command.index("--script") + 1].split(",")
        self.assertEqual(scripts, list(SAFE_SERVICE_SCRIPTS))
        self.assertFalse(
            {"brute", "dos", "exploit", "fuzzer", "intrusive"} & set(scripts)
        )

    def test_target_cannot_be_interpreted_as_an_option(self) -> None:
        with self.assertRaises(ValueError):
            build_nmap_command(
                "/usr/bin/nmap", "--script=exploit", [443], "inventory", 60, 20
            )

    def test_xml_parser_preserves_service_and_script_evidence(self) -> None:
        result = parse_nmap_xml(NMAP_XML, "owned.test", [22, 443])

        self.assertEqual(result["host_status"], "up")
        self.assertEqual(result["addresses"], ["192.0.2.10"])
        self.assertEqual(len(result["open_ports"]), 1)
        self.assertEqual(result["open_ports"][0]["port"], 443)
        self.assertEqual(result["open_ports"][0]["version"], "nginx 1.24.0")
        self.assertEqual(result["open_ports"][0]["scripts"][0]["id"], "ssl-cert")
        self.assertEqual(result["host_scripts"][0]["id"], "dns-recursion")

    @patch("aegisscope.nmap_runner.subprocess.run")
    @patch("aegisscope.nmap_runner.shutil.which", return_value="/usr/bin/nmap")
    def test_runner_uses_argument_list_and_imports_xml(self, which, run) -> None:
        run.return_value = subprocess.CompletedProcess([], 0, NMAP_XML, "")

        result = run_nmap_scan("owned.test", [443], "web-tls", 60, 25)

        self.assertIsNone(result["error"])
        self.assertEqual(result["engine"], "nmap")
        self.assertEqual(result["profile"], "web-tls")
        self.assertEqual(result["open_ports"][0]["port"], 443)
        command = run.call_args.args[0]
        self.assertIsInstance(command, list)
        self.assertEqual(command[-1], "owned.test")
        self.assertNotIn("shell", run.call_args.kwargs)
        which.assert_called_once_with("nmap")

    @patch("aegisscope.nmap_runner.shutil.which", return_value=None)
    def test_missing_nmap_is_reported_without_failing_scan(self, which) -> None:
        result = run_nmap_scan("owned.test", [443], "inventory", 60, 25)

        self.assertEqual(result["open_ports"], [])
        self.assertIn("not found", result["error"])
        which.assert_called_once_with("nmap")


if __name__ == "__main__":
    unittest.main()
