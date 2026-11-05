from functools import lru_cache
from urllib.parse import urlsplit

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SENTINEL_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    api_key: str = ""
    api_keys: str = ""
    allowed_domains: str = ""
    database_url: str = "sqlite:///./sentinel.db"
    cors_origins: str = "http://localhost:5173"
    request_timeout_seconds: float = 8.0
    max_request_body_bytes: int = 524_288
    max_assessment_records: int = 250
    redis_url: str = ""
    rate_limit_window_seconds: int = 60
    api_rate_limit_per_minute: int = 120
    ip_rate_limit_per_minute: int = 300
    assessment_rate_limit_per_minute: int = 10
    secret_scan_rate_limit_per_minute: int = 20
    environment: str = "development"

    @property
    def configured_api_keys(self) -> list[str]:
        # Keep API_KEY for backward compatibility. API_KEYS supports overlap
        # during rotation: deploy [old,new], switch clients, then remove old.
        values = [item.strip() for item in self.api_keys.split(",") if item.strip()]
        if not values and self.api_key.strip():
            values = [self.api_key.strip()]
        return list(dict.fromkeys(values))

    @property
    def allowed_domain_list(self) -> list[str]:
        return [item.strip() for item in self.allowed_domains.split(",") if item.strip()]

    @property
    def cors_origin_list(self) -> list[str]:
        return [item.strip() for item in self.cors_origins.split(",") if item.strip()]

    @model_validator(mode="after")
    def validate_runtime_policy(self):
        if self.environment not in {"development", "test", "staging", "production"}:
            raise ValueError(
                "SENTINEL_ENVIRONMENT must be development, test, staging or production."
            )
        if not 0.5 <= self.request_timeout_seconds <= 20:
            raise ValueError("SENTINEL_REQUEST_TIMEOUT_SECONDS must be between 0.5 and 20.")
        if not 1_024 <= self.max_request_body_bytes <= 10_485_760:
            raise ValueError("SENTINEL_MAX_REQUEST_BODY_BYTES must be between 1024 and 10485760.")
        if not 1 <= self.max_assessment_records <= 100_000:
            raise ValueError("SENTINEL_MAX_ASSESSMENT_RECORDS must be between 1 and 100000.")
        if not 1 <= self.rate_limit_window_seconds <= 86_400:
            raise ValueError("SENTINEL_RATE_LIMIT_WINDOW_SECONDS must be between 1 and 86400.")
        for name, value in (
            ("SENTINEL_API_RATE_LIMIT_PER_MINUTE", self.api_rate_limit_per_minute),
            ("SENTINEL_IP_RATE_LIMIT_PER_MINUTE", self.ip_rate_limit_per_minute),
            ("SENTINEL_ASSESSMENT_RATE_LIMIT_PER_MINUTE", self.assessment_rate_limit_per_minute),
            ("SENTINEL_SECRET_SCAN_RATE_LIMIT_PER_MINUTE", self.secret_scan_rate_limit_per_minute),
        ):
            if not 1 <= value <= 100_000:
                raise ValueError(f"{name} must be between 1 and 100000.")
        if self.environment == "production":
            errors = []
            keys = self.configured_api_keys
            if not keys or any(len(key) < 32 for key in keys):
                errors.append("Every configured API key must contain at least 32 characters")
            for key in keys:
                normalized_key = key.lower()
                if any(
                    marker in normalized_key
                    for marker in (
                        "replace-with",
                        "change-me",
                        "your-api-key",
                        "placeholder",
                        "example",
                    )
                ):
                    errors.append("API keys must not contain sample or placeholder values")
                    break
            if not self.allowed_domain_list:
                errors.append(
                    "SENTINEL_ALLOWED_DOMAINS must contain at least one authorized domain"
                )
            if "*" in self.cors_origin_list:
                errors.append("SENTINEL_CORS_ORIGINS must not contain a wildcard")
            if self.database_url.startswith("sqlite"):
                errors.append("SENTINEL_DATABASE_URL must use PostgreSQL outside development")
            redis_parts = urlsplit(self.redis_url)
            if (
                redis_parts.scheme not in {"redis", "rediss"}
                or not redis_parts.hostname
                or not redis_parts.password
                or len(redis_parts.password) < 32
            ):
                errors.append(
                    "SENTINEL_REDIS_URL must configure authenticated shared Redis rate-limit storage"
                )
            if errors:
                raise ValueError("Production configuration rejected: " + "; ".join(errors))
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
