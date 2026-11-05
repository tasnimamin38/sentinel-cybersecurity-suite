import unittest

from app.services.security_headers import evaluate_security_headers


class SecurityHeaderTests(unittest.TestCase):
    def test_missing_required_headers_create_findings(self):
        findings = evaluate_security_headers({})
        codes = {finding["code"] for finding in findings}
        self.assertIn("MISSING_HSTS", codes)
        self.assertIn("MISSING_CSP", codes)
        self.assertIn("MISSING_FRAME_PROTECTION", codes)

    def test_existing_headers_reduce_findings(self):
        findings = evaluate_security_headers(
            {
                "strict-transport-security": "max-age=31536000; includeSubDomains",
                "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
                "x-content-type-options": "nosniff",
                "referrer-policy": "strict-origin-when-cross-origin",
                "x-frame-options": "DENY",
                "permissions-policy": "camera=(), microphone=(), geolocation=()",
            }
        )
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
