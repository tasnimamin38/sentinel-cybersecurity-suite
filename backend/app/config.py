import json
import re
from functools import lru_cache
from ipaddress import ip_network
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
    api_credentials_json: str = ""
    allowed_domains: str = ""
    database_url: str = "sqlite:///./sentinel.db"
    cors_origins: str = "http://localhost:5173"
    request_timeout_seconds: float = 8.0
    max_assessment_records: int = 250
    max_request_body_bytes: int = 524_288
    process_role: str = "api"
    redis_url: str = ""
    trusted_proxy_cidrs: str = ""
    rate_limit_window_seconds: int = 60
    api_rate_limit_per_minute: int = 120
    ip_rate_limit_per_minute: int = 300
    honeypot_event_limit_per_minute: int = 10
    security_event_audit_limit_per_minute: int = 10
    assessment_rate_limit_per_minute: int = 10
    secret_scan_rate_limit_per_minute: int = 20
    auth_failure_threshold: int = 5
    auth_failure_window_seconds: int = 300
    security_alert_webhook_url: str = ""
    security_alert_webhook_secret: str = ""
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

    @property
    def trusted_proxy_cidr_list(self) -> list[str]:
        return [item.strip() for item in self.trusted_proxy_cidrs.split(",") if item.strip()]

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
        if not 1_024 <= self.max_request_body_bytes <= 10_485_760:
            raise ValueError("SENTINEL_MAX_REQUEST_BODY_BYTES must be between 1024 and 10485760.")
        if not 1 <= self.rate_limit_window_seconds <= 86_400:
            raise ValueError("SENTINEL_RATE_LIMIT_WINDOW_SECONDS must be between 1 and 86400.")
        for name, value in (
            ("SENTINEL_API_RATE_LIMIT_PER_MINUTE", self.api_rate_limit_per_minute),
            ("SENTINEL_IP_RATE_LIMIT_PER_MINUTE", self.ip_rate_limit_per_minute),
            ("SENTINEL_HONEYPOT_EVENT_LIMIT_PER_MINUTE", self.honeypot_event_limit_per_minute),
            (
                "SENTINEL_SECURITY_EVENT_AUDIT_LIMIT_PER_MINUTE",
                self.security_event_audit_limit_per_minute,
            ),
            ("SENTINEL_ASSESSMENT_RATE_LIMIT_PER_MINUTE", self.assessment_rate_limit_per_minute),
            ("SENTINEL_SECRET_SCAN_RATE_LIMIT_PER_MINUTE", self.secret_scan_rate_limit_per_minute),
        ):
            if not 1 <= value <= 100_000:
                raise ValueError(f"{name} must be between 1 and 100000.")
        if not 1 <= self.auth_failure_threshold <= 100:
            raise ValueError("SENTINEL_AUTH_FAILURE_THRESHOLD must be between 1 and 100.")
        if not 1 <= self.auth_failure_window_seconds <= 86_400:
            raise ValueError("SENTINEL_AUTH_FAILURE_WINDOW_SECONDS must be between 1 and 86400.")

        for cidr in self.trusted_proxy_cidr_list:
            try:
                ip_network(cidr, strict=False)
            except ValueError as exc:
                raise ValueError(
                    "SENTINEL_TRUSTED_PROXY_CIDRS must contain valid IP networks."
                ) from exc

        if self.security_alert_webhook_secret and not self.security_alert_webhook_url:
            raise ValueError("A webhook secret requires SENTINEL_SECURITY_ALERT_WEBHOOK_URL.")
        if self.security_alert_webhook_url:
            webhook = urlsplit(self.security_alert_webhook_url)
            if (
                webhook.scheme != "https"
                or not webhook.hostname
                or webhook.username
                or webhook.password
                or webhook.fragment
                or len(self.security_alert_webhook_secret) < 32
            ):
                raise ValueError(
                    "Security alert webhooks require an HTTPS URL without userinfo or fragments "
                    "and a secret of at least 32 characters."
                )

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
            for origin in self.cors_origin_list:
                parsed_origin = urlsplit(origin)
                invalid_origin = (
                    "*" in origin
                    or parsed_origin.scheme != "https"
                    or not parsed_origin.hostname
                    or parsed_origin.username is not None
                    or parsed_origin.password is not None
                    or parsed_origin.path not in ("", "/")
                    or bool(parsed_origin.query)
                    or bool(parsed_origin.fragment)
                    or any(character.isspace() for character in origin)
                )
                try:
                    if parsed_origin.port is not None and not 1 <= parsed_origin.port <= 65535:
                        invalid_origin = True
                except ValueError:
                    invalid_origin = True
                if invalid_origin:
                    errors.append(
                        "SENTINEL_CORS_ORIGINS must contain HTTPS origins only, without "
                        "wildcards, credentials, paths, query strings or fragments"
                    )
                    break
            if self.database_url.startswith("sqlite"):
                errors.append("SENTINEL_DATABASE_URL must use PostgreSQL outside development")
            if self.process_role == "api":
                redis = urlsplit(self.redis_url)
                if (
                    redis.scheme not in {"redis", "rediss"}
                    or not redis.hostname
                    or not redis.password
                    or len(redis.password) < 32
                    or any(
                        marker in redis.password.lower()
                        for marker in ("replace-with", "change-me", "placeholder", "example")
                    )
                ):
                    errors.append(
                        "SENTINEL_REDIS_URL must configure authenticated shared Redis rate-limit storage"
                    )
                if not self.trusted_proxy_cidr_list:
                    errors.append(
                        "SENTINEL_TRUSTED_PROXY_CIDRS must identify the reverse-proxy network"
                    )
            if errors:
                raise ValueError("Production configuration rejected: " + "; ".join(errors))
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
