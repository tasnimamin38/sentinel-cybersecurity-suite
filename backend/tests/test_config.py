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
            redis_url="redis://:R" + "R" * 63 + "@redis:6379/0",
            cors_origins="https://console.example.com",
        )
        self.assertEqual(settings.allowed_domain_list, ["example.com"])

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

    def test_production_requires_authenticated_shared_redis(self):
        with self.assertRaises(ValidationError):
            Settings(
                environment="production",
                api_key="P" * 64,
                allowed_domains="example.com",
                database_url="postgresql+psycopg://user:pass@db/sentinel",
            )

    def test_production_rejects_redis_without_a_strong_password(self):
        with self.assertRaises(ValidationError):
            Settings(
                environment="production",
                api_key="P" * 64,
                allowed_domains="example.com",
                database_url="postgresql+psycopg://user:pass@db/sentinel",
                redis_url="redis://redis:6379/0",
            )

    def test_rate_limit_policy_is_bounded(self):
        with self.assertRaises(ValidationError):
            Settings(api_rate_limit_per_minute=0)
        with self.assertRaises(ValidationError):
            Settings(rate_limit_window_seconds=90_000)

    def test_production_rejects_weak_redis_password(self):
        with self.assertRaises(ValidationError):
            Settings(
                environment="production",
                api_key="P" * 64,
                allowed_domains="example.com",
                database_url="postgresql+psycopg://user:pass@db/sentinel",
                redis_url="redis://:short@redis:6379/0",
            )


if __name__ == "__main__":
    unittest.main()
