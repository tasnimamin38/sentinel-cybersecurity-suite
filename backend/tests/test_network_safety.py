import unittest
from unittest.mock import patch

from app.services.network_safety import UnsafeResolution, assert_public_dns_resolution


class NetworkSafetyTests(unittest.TestCase):
    @patch("app.services.network_safety.socket.getaddrinfo")
    def test_public_resolution_is_accepted(self, resolver):
        resolver.return_value = [(None, None, None, None, ("8.8.8.8", 443))]
        self.assertEqual(assert_public_dns_resolution("example.com"), ["8.8.8.8"])

    @patch("app.services.network_safety.socket.getaddrinfo")
    def test_private_resolution_is_rejected(self, resolver):
        resolver.return_value = [(None, None, None, None, ("10.0.0.2", 443))]
        with self.assertRaises(UnsafeResolution):
            assert_public_dns_resolution("example.com")

    @patch("app.services.network_safety.socket.getaddrinfo")
    def test_mixed_public_and_private_resolution_is_rejected(self, resolver):
        resolver.return_value = [
            (None, None, None, None, ("8.8.8.8", 443)),
            (None, None, None, None, ("127.0.0.1", 443)),
        ]
        with self.assertRaises(UnsafeResolution):
            assert_public_dns_resolution("example.com")


if __name__ == "__main__":
    unittest.main()
