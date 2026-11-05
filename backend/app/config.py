from functools import lru_cache

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
    allowed_domains: str = ""
    database_url: str = "sqlite:///./sentinel.db"
    cors_origins: str = "http://localhost:5173"
    request_timeout_seconds: float = 8.0
    max_assessment_records: int = 250
    environment: str = "development"

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
        if not 1 <= self.max_assessment_records <= 100_000:
            raise ValueError("SENTINEL_MAX_ASSESSMENT_RECORDS must be between 1 and 100000.")
        if self.environment == "production":
            errors = []
            if len(self.api_key) < 32:
                errors.append("SENTINEL_API_KEY must contain at least 32 characters")
            if not self.allowed_domain_list:
                errors.append(
                    "SENTINEL_ALLOWED_DOMAINS must contain at least one authorized domain"
                )
            if "*" in self.cors_origin_list:
                errors.append("SENTINEL_CORS_ORIGINS must not contain a wildcard")
            if self.database_url.startswith("sqlite"):
                errors.append("SENTINEL_DATABASE_URL must use PostgreSQL outside development")
            if errors:
                raise ValueError("Production configuration rejected: " + "; ".join(errors))
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()