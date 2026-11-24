import os
import stat
import tempfile
import unittest
from pathlib import Path

from aegisscope.authorization import create_policy, verify_code


class AuthorizationTests(unittest.TestCase):
    def test_policy_accepts_only_matching_code(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "owner-policy.json"
            create_policy("bwu", path=path, iterations=10_000)
            self.assertTrue(verify_code("bwu", path))
            self.assertFalse(verify_code("wrong", path))
            mode = stat.S_IMODE(os.stat(path).st_mode)
            self.assertEqual(mode, 0o600)

    def test_policy_cannot_be_silently_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "owner-policy.json"
            create_policy("bwu", path=path, iterations=10_000)
            with self.assertRaises(ValueError):
                create_policy("different", path=path, iterations=10_000)


if __name__ == "__main__":
    unittest.main()
