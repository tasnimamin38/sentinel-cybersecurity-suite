from functools import lru_cache

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


@lru_cache
def get_settings() -> Settings:
    return Settings()