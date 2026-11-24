import unittest

from aegisscope.scope import ScopeError, ScopePolicy, normalize_url


class ScopePolicyTests(unittest.TestCase):
    def test_normalizes_default_port_and_fragment(self) -> None:
        self.assertEqual(
            normalize_url("HTTPS://Example.COM:443/path?b=2&a=1#section"),
            "https://example.com/path?b=2&a=1",
        )

    def test_exact_host_does_not_allow_suffix_attack(self) -> None:
        policy = ScopePolicy(("example.com",))
        self.assertTrue(policy.is_allowed("https://example.com/"))
        self.assertFalse(policy.is_allowed("https://example.com.evil.test/"))
        self.assertFalse(policy.is_allowed("https://sub.example.com/"))

    def test_subdomain_mode_requires_dot_boundary(self) -> None:
        policy = ScopePolicy(("example.com",), allow_subdomains=True)
        self.assertTrue(policy.is_allowed("https://api.example.com/"))
        self.assertFalse(policy.is_allowed("https://notexample.com/"))

    def test_rejects_credentials_and_unsupported_schemes(self) -> None:
        with self.assertRaises(ScopeError):
            normalize_url("https://user:password@example.com/")
        with self.assertRaises(ScopeError):
            normalize_url("file:///etc/passwd")


if __name__ == "__main__":
    unittest.main()
