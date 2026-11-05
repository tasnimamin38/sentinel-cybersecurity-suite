import unittest
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import HTTPException

from app.auth import require_api_key


class ApiKeyAuthTests(unittest.TestCase):
    @patch("app.auth.get_settings", return_value=SimpleNamespace(configured_api_keys=["A" * 40]))
    def test_valid_key_is_accepted(self, _settings):
        self.assertIsNone(require_api_key("A" * 40))

    @patch("app.auth.get_settings", return_value=SimpleNamespace(configured_api_keys=["A" * 40]))
    def test_invalid_key_is_rejected(self, _settings):
        with self.assertRaises(HTTPException) as raised:
            require_api_key("wrong")
        self.assertEqual(raised.exception.status_code, 401)

    @patch("app.auth.get_settings", return_value=SimpleNamespace(configured_api_keys=[]))
    def test_missing_server_key_fails_closed(self, _settings):
        with self.assertRaises(HTTPException) as raised:
            require_api_key("A" * 40)
        self.assertEqual(raised.exception.status_code, 503)

    @patch(
        "app.auth.get_settings",
        return_value=SimpleNamespace(configured_api_keys=["A" * 40, "B" * 40]),
    )
    def test_rotation_accepts_old_and_new_keys_during_overlap(self, _settings):
        self.assertIsNone(require_api_key("A" * 40))
        self.assertIsNone(require_api_key("B" * 40))

    @patch("app.auth.get_settings", return_value=SimpleNamespace(configured_api_keys=["short"]))
    def test_weak_server_key_fails_closed(self, _settings):
        with self.assertRaises(HTTPException) as raised:
            require_api_key("short")
        self.assertEqual(raised.exception.status_code, 503)


if __name__ == "__main__":
    unittest.main()
