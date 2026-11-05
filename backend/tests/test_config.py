import unittest

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

    def test_timeout_is_bounded(self):
        with self.assertRaises(ValidationError):
            Settings(request_timeout_seconds=99)


if __name__ == "__main__":
    unittest.main()
