import unittest

from app.services.scope import ScopeViolation, authorize_domain


class ScopeAuthorizationTests(unittest.TestCase):
    def test_exact_allowed_domain_is_authorized(self):
        self.assertEqual(
            authorize_domain("example.com", ["example.com"]),
            "example.com",
        )

    def test_subdomain_is_authorized_when_parent_is_allowlisted(self):
        self.assertEqual(
            authorize_domain("api.example.com", ["example.com"]),
            "api.example.com",
        )

    def test_suffix_confusion_is_rejected(self):
        with self.assertRaises(ScopeViolation):
            authorize_domain("example.com.attacker.test", ["example.com"])

    def test_unlisted_domain_is_rejected(self):
        with self.assertRaises(ScopeViolation):
            authorize_domain("other.test", ["example.com"])

    def test_ip_literal_is_rejected(self):
        with self.assertRaises(ScopeViolation):
            authorize_domain("127.0.0.1", ["127.0.0.1"])

    def test_invalid_host_is_rejected(self):
        with self.assertRaises(ScopeViolation):
            authorize_domain("https://example.com/path", ["example.com"])


if __name__ == "__main__":
    unittest.main()
