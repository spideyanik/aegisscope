import json
import tempfile
import unittest
from pathlib import Path

from aegisscope.cli import choose_profile, run


class CliTests(unittest.TestCase):
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
