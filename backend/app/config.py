import json
import re
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
    api_keys: str = ""
    api_credentials_json: str = ""
    allowed_domains: str = ""
    database_url: str = "sqlite:///./sentinel.db"
    cors_origins: str = "http://localhost:5173"
    request_timeout_seconds: float = 8.0
    max_assessment_records: int = 250
    process_role: str = "api"
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
    def configured_role_credentials(self) -> list[dict[str, str]]:
        if not self.api_credentials_json.strip():
            return []
        return json.loads(self.api_credentials_json)

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
        if self.process_role not in {"api", "worker"}:
            raise ValueError("SENTINEL_PROCESS_ROLE must be api or worker.")
        if not 0.5 <= self.request_timeout_seconds <= 20:
            raise ValueError("SENTINEL_REQUEST_TIMEOUT_SECONDS must be between 0.5 and 20.")
        if not 1 <= self.max_assessment_records <= 100_000:
            raise ValueError("SENTINEL_MAX_ASSESSMENT_RECORDS must be between 1 and 100000.")
        role_credentials = self.configured_role_credentials
        if not isinstance(role_credentials, list):
            raise ValueError("SENTINEL_API_CREDENTIALS_JSON must be a JSON array.")
        seen_ids: set[str] = set()
        seen_keys: set[str] = set()
        for item in role_credentials:
            if not isinstance(item, dict) or set(item) != {"id", "key", "role"}:
                raise ValueError("Each role credential must contain exactly id, key and role.")
            credential_id, key, role = item["id"], item["key"], item["role"]
            if not isinstance(credential_id, str) or not re.fullmatch(
                r"[a-zA-Z0-9_-]{1,64}", credential_id
            ):
                raise ValueError(
                    "Static credential IDs must be 1–64 alphanumeric, underscore or hyphen characters."
                )
            if not isinstance(key, str) or len(key) < 32:
                raise ValueError(
                    "Every static role credential must contain at least 32 characters."
                )
            if not isinstance(role, str) or role not in {
                "admin",
                "analyst",
                "asset_manager",
                "auditor",
                "read_only",
            }:
                raise ValueError("Static credential role is not supported.")
            if credential_id in seen_ids or key in seen_keys:
                raise ValueError("Static credential IDs and key material must be unique.")
            seen_ids.add(credential_id)
            seen_keys.add(key)

        legacy_keys = self.configured_api_keys
        if len(legacy_keys) != len(set(legacy_keys)):
            raise ValueError("Legacy API key material must be unique.")
        if seen_keys.intersection(legacy_keys):
            raise ValueError("Static role credentials must not reuse legacy API key material.")
        legacy_ids = {f"legacy-admin-{index + 1}" for index in range(len(legacy_keys))}
        if seen_ids.intersection(legacy_ids):
            raise ValueError(
                "Static role credential IDs must not collide with legacy credential IDs."
            )

        if self.environment == "production":
            errors = []
            keys = self.configured_api_keys
            if self.process_role == "api":
                if (
                    not keys and not any(item["role"] == "admin" for item in role_credentials)
                ) or any(len(key) < 32 for key in keys):
                    errors.append("Configure a strong bootstrap admin API key")
                if any(len(key) < 32 for key in keys):
                    errors.append(
                        "Every configured legacy API key must contain at least 32 characters"
                    )
                for key in keys + [item["key"] for item in role_credentials]:
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
            elif keys or role_credentials:
                errors.append("Worker processes must not be configured with API credentials")
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
