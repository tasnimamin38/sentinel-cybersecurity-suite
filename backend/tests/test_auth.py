import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from fastapi import HTTPException
from starlette.requests import Request

from app.auth import require_api_key


def make_request(path="/api/v1/overview", method="GET"):
    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("ascii"),
        "query_string": b"",
        "headers": [],
        "client": ("testclient", 50000),
        "server": ("testserver", 80),
        "route": SimpleNamespace(path=path),
    }
    return Request(scope)


class ApiKeyAuthTests(unittest.TestCase):
    def settings(self, keys=None, roles=None):
        return SimpleNamespace(
            configured_api_keys=keys or [],
            configured_role_credentials=roles or [],
        )

    def setUp(self):
        self.db = MagicMock()
        self.db.scalar.return_value = None

    def test_valid_legacy_admin_key_is_accepted(self):
        with patch("app.auth.get_settings", return_value=self.settings(["A" * 40])):
            principal = require_api_key(make_request(), "A" * 40, self.db)
        self.assertEqual(principal.role, "admin")
        self.assertEqual(principal.credential_source, "environment")

    def test_invalid_key_is_rejected(self):
        with patch("app.auth.get_settings", return_value=self.settings(["A" * 40])):
            with self.assertRaises(HTTPException) as raised:
                require_api_key(make_request(), "wrong", self.db)
        self.assertEqual(raised.exception.status_code, 401)

    def test_missing_server_credentials_fail_closed(self):
        with patch("app.auth.get_settings", return_value=self.settings()):
            with self.assertRaises(HTTPException) as raised:
                require_api_key(make_request(), "A" * 40, self.db)
        self.assertEqual(raised.exception.status_code, 401)

    def test_rotation_accepts_old_and_new_keys_during_overlap(self):
        with patch("app.auth.get_settings", return_value=self.settings(["A" * 40, "B" * 40])):
            first = require_api_key(make_request(), "A" * 40, self.db)
            second = require_api_key(make_request(), "B" * 40, self.db)
        self.assertEqual(first.role, "admin")
        self.assertEqual(second.role, "admin")

    def test_weak_static_server_key_fails_closed(self):
        with patch("app.auth.get_settings", return_value=self.settings(["short"])):
            with self.assertRaises(HTTPException) as raised:
                require_api_key(make_request(), "short", self.db)
        self.assertEqual(raised.exception.status_code, 503)

    def test_role_scoped_analyst_can_read_assets_but_cannot_write_assets(self):
        analyst = [{"id": "nightly-analyst", "key": "N" * 40, "role": "analyst"}]
        with patch("app.auth.get_settings", return_value=self.settings(roles=analyst)):
            principal = require_api_key(make_request("/api/v1/assets"), "N" * 40, self.db)
            with self.assertRaises(HTTPException) as raised:
                require_api_key(make_request("/api/v1/assets", "POST"), "N" * 40, self.db)
        self.assertEqual(principal.role, "analyst")
        self.assertEqual(raised.exception.status_code, 403)

    def test_static_role_credential_preserves_selected_asset_scope(self):
        asset_id = "00000000-0000-0000-0000-000000000001"
        analyst = [
            {
                "id": "scoped-analyst",
                "key": "S" * 40,
                "role": "analyst",
                "asset_scope_mode": "selected",
                "asset_scope_ids": [asset_id],
            }
        ]
        with (
            patch("app.auth.get_settings", return_value=self.settings(roles=analyst)),
            patch("app.services.credential_quota.consume_credential_quota", return_value=None),
        ):
            principal = require_api_key(make_request("/api/v1/assets"), "S" * 40, self.db)

        self.assertEqual(principal.asset_scope_mode, "selected")
        self.assertTrue(principal.can_access_asset(asset_id))
        self.assertFalse(principal.can_access_asset("00000000-0000-0000-0000-000000000002"))
        self.assertFalse(principal.can_access_asset(None))

    def test_unmapped_route_fails_closed_for_non_admin(self):
        auditor = [{"id": "audit-reader", "key": "R" * 40, "role": "auditor"}]
        with patch("app.auth.get_settings", return_value=self.settings(roles=auditor)):
            with self.assertRaises(HTTPException) as raised:
                require_api_key(make_request("/api/v1/unmapped"), "R" * 40, self.db)
        self.assertEqual(raised.exception.status_code, 403)


if __name__ == "__main__":
    unittest.main()
