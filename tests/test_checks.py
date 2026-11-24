import unittest

import httpx

from aegisscope.checks import check_response, detect_new_sql_error, parse_page


class PassiveCheckTests(unittest.TestCase):
    def test_secure_headers_produce_no_header_findings(self) -> None:
        headers = httpx.Headers(
            {
                "content-type": "text/html",
                "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
                "x-content-type-options": "nosniff",
                "referrer-policy": "strict-origin-when-cross-origin",
                "permissions-policy": "camera=()",
                "strict-transport-security": "max-age=31536000",
            }
        )
        findings = check_response("https://example.com/", 200, headers, "<html></html>")
        self.assertEqual(findings, [])

    def test_cookie_attributes_are_checked_without_disclosing_value(self) -> None:
        headers = httpx.Headers(
            [
                ("content-type", "text/plain"),
                ("set-cookie", "session=secret-value; Path=/"),
            ]
        )
        findings = check_response("https://example.com/", 200, headers, "ok")
        cookie_findings = [item for item in findings if item.check_id.startswith("cookie-")]
        self.assertEqual(len(cookie_findings), 3)
        self.assertNotIn("secret-value", " ".join(item.evidence for item in findings))

    def test_sql_signature_must_be_new(self) -> None:
        signature = "You have an error in your SQL syntax"
        self.assertIsNotNone(detect_new_sql_error("normal", signature))
        self.assertIsNone(detect_new_sql_error(signature, signature))

    def test_parser_does_not_crawl_assets_or_form_actions(self) -> None:
        parser = parse_page(
            "https://example.com/",
            '<script src="/app.js"></script><form action="/change-password">'
            '<input name="password" type="password"></form>'
            '<form action="/search" method="get"><input name="q">'
            '<select name="category"></select></form>'
            '<form action="/update" method="post"><input name="value"></form>'
            '<a href="/account">account</a>',
        )
        self.assertEqual(parser.links, {"https://example.com/account"})
        self.assertEqual(parser.password_forms, ["https://example.com/change-password"])
        self.assertEqual(
            parser.get_forms,
            {"https://example.com/search?q=&category="},
        )

    def test_linked_git_directory_is_reported(self) -> None:
        findings = check_response(
            "https://example.com/.git/",
            200,
            httpx.Headers({"content-type": "text/html"}),
            "<title>Directory listing for /.git/</title><a href='objects/'>objects/</a>",
        )
        self.assertIn("exposed-git-metadata", {item.check_id for item in findings})

    def test_inconsistent_credentialed_cors_is_reported(self) -> None:
        findings = check_response(
            "https://example.com/",
            200,
            httpx.Headers(
                {
                    "content-type": "text/plain",
                    "access-control-allow-origin": "*",
                    "access-control-allow-credentials": "true",
                }
            ),
            "ok",
        )
        self.assertIn("cors-wildcard-credentials", {item.check_id for item in findings})


if __name__ == "__main__":
    unittest.main()
