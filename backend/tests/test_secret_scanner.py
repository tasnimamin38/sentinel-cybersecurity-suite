import unittest

from app.services.secrets import scan_text


class SecretScannerTests(unittest.TestCase):
    def test_detects_and_redacts_github_token(self):
        token = "ghp_" + ("A" * 36)
        findings = scan_text("TOKEN=" + token)
        self.assertTrue(findings)
        self.assertNotIn(token, findings[0]["evidence"])
        self.assertIn("[REDACTED]", findings[0]["evidence"])

    def test_does_not_return_plain_secret(self):
        private_key = "-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n-----END PRIVATE KEY-----"
        findings = scan_text(private_key)
        self.assertTrue(findings)
        self.assertNotIn("not-a-real-key", findings[0]["evidence"])


if __name__ == "__main__":
    unittest.main()