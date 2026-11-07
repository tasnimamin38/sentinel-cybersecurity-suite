import os
import unittest
from unittest.mock import patch

from pydantic import ValidationError

from app.config import Settings


class ProductionConfigTests(unittest.TestCase):
    def test_production_rejects_short_api_key_and_missing_scope(self):
        with self.assertRaises(ValidationError):
            Settings(
                environment="production",
                api_key="short",
                allowed_domains="",
                database_url="postgresql+psycopg://user:pass@db/sentinel",
            )

    def test_production_rejects_sqlite_database(self):
        with self.assertRaises(ValidationError):
            Settings(
                environment="production",
                api_key="S" * 40,
                allowed_domains="example.com",
                database_url="sqlite:///./sentinel.db",
            )

    def test_production_accepts_strong_baseline_configuration(self):
        settings = Settings(
            environment="production",
            api_key="S" * 40,
            allowed_domains="example.com",
            database_url="postgresql+psycopg://user:pass@db/sentinel",
            cors_origins="https://console.example.com",
        )
        self.assertEqual(settings.allowed_domain_list, ["example.com"])
        self.assertEqual(settings.process_role, "api")

    def test_production_rejects_placeholder_key_even_when_long(self):
        with self.assertRaises(ValidationError):
            Settings(
                environment="production",
                api_key="replace-with-a-long-but-not-a-real-secret-value",
                allowed_domains="example.com",
                database_url="postgresql+psycopg://user:pass@db/sentinel",
            )

    def test_api_key_overlap_configuration_accepts_two_strong_keys(self):
        settings = Settings(api_keys="A" * 40 + "," + "B" * 40)
        self.assertEqual(settings.configured_api_keys, ["A" * 40, "B" * 40])

    def test_api_key_overlap_rejects_any_weak_key_in_production(self):
        with self.assertRaises(ValidationError):
            Settings(
                environment="production",
                api_keys="A" * 40 + ",short",
                allowed_domains="example.com",
                database_url="postgresql+psycopg://user:pass@db/sentinel",
            )

    def test_timeout_is_bounded(self):
        with self.assertRaises(ValidationError):
            Settings(request_timeout_seconds=99)

    def test_production_worker_role_does_not_require_an_api_key(self):
        with patch.dict(os.environ, {}, clear=True):
            settings = Settings(
                _env_file=None,
                environment="production",
                process_role="worker",
                allowed_domains="example.com",
                database_url="postgresql+psycopg://user:pass@db/sentinel",
                cors_origins="https://console.example.com",
            )
        self.assertEqual(settings.process_role, "worker")
        self.assertEqual(settings.configured_api_keys, [])

    def test_production_api_role_still_requires_a_strong_api_key(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ValidationError):
                Settings(
                    _env_file=None,
                    environment="production",
                    process_role="api",
                    api_key="",
                    allowed_domains="example.com",
                    database_url="postgresql+psycopg://user:pass@db/sentinel",
                    cors_origins="https://console.example.com",
                )

    def test_production_worker_rejects_api_credentials(self):
        with self.assertRaises(ValidationError):
            Settings(
                environment="production",
                process_role="worker",
                api_key="W" * 40,
                allowed_domains="example.com",
                database_url="postgresql+psycopg://user:pass@db/sentinel",
                cors_origins="https://console.example.com",
            )

    def test_process_role_rejects_unknown_values(self):
        with self.assertRaises(ValidationError):
            Settings(process_role="scheduler")


if __name__ == "__main__":
    unittest.main()
