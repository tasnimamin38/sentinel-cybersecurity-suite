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

    def test_valid_legacy_admin_key_is_bound_to_the_legacy_tenant(self):
        with patch("app.auth.get_settings", return_value=self.settings(["A" * 40])):
            principal = require_api_key(make_request(), "A" * 40, self.db)
        self.assertEqual(principal.tenant_id, "00000000-0000-4000-8000-000000000001")
        self.assertEqual(self.db.info["tenant_id"], principal.tenant_id)

    def test_managed_api_key_selects_its_own_tenant_context(self):
        import hashlib

        tenant_id = "00000000-0000-4000-8000-00000000000b"
        secret = "B" * 48
        self.db.scalar.return_value = SimpleNamespace(
            id="managed-company-b",
            role="analyst",
            key_hash=hashlib.sha256(secret.encode()).hexdigest(),
            tenant_id=tenant_id,
            revoked_at=None,
            expires_at=None,
            last_used_at=None,
        )
        with patch("app.auth.get_settings", return_value=self.settings()):
            principal = require_api_key(make_request(), secret, self.db)
        self.assertEqual(principal.tenant_id, tenant_id)
        self.assertEqual(self.db.info["tenant_id"], tenant_id)

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

    def test_unmapped_route_fails_closed_for_non_admin(self):
        auditor = [{"id": "audit-reader", "key": "R" * 40, "role": "auditor"}]
        with patch("app.auth.get_settings", return_value=self.settings(roles=auditor)):
            with self.assertRaises(HTTPException) as raised:
                require_api_key(make_request("/api/v1/unmapped"), "R" * 40, self.db)
        self.assertEqual(raised.exception.status_code, 403)


if __name__ == "__main__":
    unittest.main()
