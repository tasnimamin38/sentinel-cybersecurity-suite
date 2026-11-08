import unittest

from app.services.security_headers import evaluate_security_headers


class SecurityHeaderTests(unittest.TestCase):
    def test_missing_required_headers_create_findings(self):
        findings = evaluate_security_headers({})
        codes = {finding["code"] for finding in findings}
        self.assertIn("MISSING_HSTS", codes)
        self.assertIn("MISSING_CSP", codes)
        self.assertIn("MISSING_FRAME_PROTECTION", codes)

    def test_weak_hsts_csp_referrer_and_permissions_policies_are_flagged(self):
        findings = evaluate_security_headers(
            {
                "strict-transport-security": "max-age=86400",
                "content-security-policy": "default-src 'self'; script-src 'self' 'unsafe-eval' 'unsafe-inline' *",
                "referrer-policy": "unsafe-url",
                "permissions-policy": "camera=*, microphone=()",
            }
        )
        codes = {finding["code"] for finding in findings}
        self.assertIn("HSTS_MAX_AGE_SHORT", codes)
        self.assertIn("HSTS_SUBDOMAINS_NOT_COVERED", codes)
        self.assertIn("CSP_UNSAFE_EVAL", codes)
        self.assertIn("CSP_UNSAFE_INLINE_SCRIPT", codes)
        self.assertIn("CSP_WILDCARD_SCRIPT_SOURCE", codes)
        self.assertIn("REFERRER_POLICY_WEAK", codes)
        self.assertIn("PERMISSIONS_POLICY_WILDCARD", codes)

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


    def test_csp_without_script_or_default_policy_is_reported_as_unrestricted(self):
        findings = evaluate_security_headers(
            {"content-security-policy": "frame-ancestors 'none'"}
        )
        codes = {finding["code"] for finding in findings}
        self.assertIn("CSP_SCRIPT_POLICY_UNRESTRICTED", codes)

    def test_frame_ancestors_text_inside_another_directive_is_not_protection(self):
        findings = evaluate_security_headers(
            {
                "content-security-policy": (
                    "default-src 'self'; report-uri https://reports.example.com/frame-ancestors"
                )
            }
        )
        codes = {finding["code"] for finding in findings}
        self.assertIn("MISSING_FRAME_PROTECTION", codes)
