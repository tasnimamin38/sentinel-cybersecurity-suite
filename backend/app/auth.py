import hashlib
import hmac
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import get_db
from app.models import ApiCredential


@dataclass(frozen=True)
class ApiPrincipal:
    credential_id: str
    role: str
    credential_source: str
    rate_limit_per_minute: int
    daily_request_limit: int
    asset_scope_mode: str = "all"
    asset_scope_ids: frozenset[str] = frozenset()

    def can_access_asset(self, asset_id: str | None) -> bool:
        return self.asset_scope_mode == "all" or (
            asset_id is not None and asset_id in self.asset_scope_ids
        )


ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "admin": frozenset({"*"}),
    "analyst": frozenset(
        {
            "identity.read",
            "system.read",
            "dashboard.read",
            "asset.read",
            "assessment.read",
            "assessment.run",
            "job.read",
            "job.enqueue",
            "incident.read",
            "incident.write",
            "remediation.read",
            "controls.read",
            "secrets.scan",
            "audit.read",
            "export.read",
        }
    ),
    "asset_manager": frozenset(
        {
            "identity.read",
            "system.read",
            "dashboard.read",
            "asset.read",
            "asset.write",
            "assessment.read",
            "assessment.run",
            "job.read",
            "job.enqueue",
            "job.manage",
            "incident.read",
            "incident.write",
            "remediation.read",
            "remediation.write",
            "controls.read",
            "audit.read",
            "export.read",
        }
    ),
    "auditor": frozenset(
        {
            "identity.read",
            "system.read",
            "dashboard.read",
            "asset.read",
            "assessment.read",
            "job.read",
            "incident.read",
            "remediation.read",
            "controls.read",
            "audit.read",
            "export.read",
        }
    ),
    "read_only": frozenset(
        {
            "identity.read",
            "dashboard.read",
            "asset.read",
            "assessment.read",
            "job.read",
            "incident.read",
            "remediation.read",
            "controls.read",
        }
    ),
}

ROUTE_PERMISSIONS: dict[tuple[str, str], str] = {
    ("GET", "/api/v1/me"): "identity.read",
    ("GET", "/api/v1/config"): "system.read",
    ("GET", "/api/v1/overview"): "dashboard.read",
    ("GET", "/api/v1/assets"): "asset.read",
    ("POST", "/api/v1/assets"): "asset.write",
    ("PATCH", "/api/v1/assets/{asset_id}"): "asset.write",
    ("POST", "/api/v1/assets/{asset_id}/assessments"): "assessment.run",
    ("GET", "/api/v1/assessments"): "assessment.read",
    ("GET", "/api/v1/assessments/{assessment_id}"): "assessment.read",
    ("GET", "/api/v1/assessments/{assessment_id}/evidence-integrity"): "assessment.read",
    ("POST", "/api/v1/assessments"): "assessment.run",
    ("GET", "/api/v1/remediations"): "remediation.read",
    ("POST", "/api/v1/remediations"): "remediation.write",
    ("PATCH", "/api/v1/remediations/{task_id}"): "remediation.write",
    ("GET", "/api/v1/incidents"): "incident.read",
    ("POST", "/api/v1/incidents"): "incident.write",
    ("PATCH", "/api/v1/incidents/{incident_id}"): "incident.write",
    ("GET", "/api/v1/controls"): "controls.read",
    ("POST", "/api/v1/secrets/scan"): "secrets.scan",
    ("GET", "/api/v1/audit/integrity"): "audit.read",
    ("GET", "/api/v1/audit"): "audit.read",
    ("GET", "/api/v1/exports/{dataset}.csv"): "export.read",
    ("POST", "/api/v1/assessment-jobs"): "job.enqueue",
    ("GET", "/api/v1/assessment-jobs"): "job.read",
    ("GET", "/api/v1/assessment-jobs/{job_id}"): "job.read",
    ("POST", "/api/v1/assessment-jobs/{job_id}/cancel"): "job.manage",
    ("POST", "/api/v1/assessment-jobs/{job_id}/retry"): "job.manage",
    ("GET", "/api/v1/credentials"): "credential.manage",
    ("POST", "/api/v1/credentials"): "credential.manage",
    ("POST", "/api/v1/credentials/{credential_id}/revoke"): "credential.manage",
    ("POST", "/api/v1/credentials/{credential_id}/rotate"): "credential.manage",
}


def _configured_static_principals() -> list[tuple[str, str, str, int, int, str, frozenset[str]]]:
    settings = get_settings()
    principals: list[tuple[str, str, str, int, int, str, frozenset[str]]] = []
    for index, key in enumerate(settings.configured_api_keys):
        principals.append((f"legacy-admin-{index + 1}", key, "admin", 600, 1_000_000, "all", frozenset()))
    for item in getattr(settings, "configured_role_credentials", []):
        principals.append(
            (
                item["id"],
                item["key"],
                item["role"],
                item.get("rate_limit_per_minute", 120),
                item.get("daily_request_limit", 10000),
                item.get("asset_scope_mode", "all"),
                frozenset(item.get("asset_scope_ids", [])),
            )
        )
    return principals


def apply_asset_scope(query, principal: ApiPrincipal, asset_id_column):
    """Filter an asset-bearing query to the credential's explicit asset IDs."""
    if principal.asset_scope_mode == "selected":
        return query.where(asset_id_column.in_(sorted(principal.asset_scope_ids)))
    return query


def ensure_asset_access(principal: ApiPrincipal, asset_id: str | None) -> None:
    """Return 404 for out-of-scope records so their existence is not disclosed."""
    if not principal.can_access_asset(asset_id):
        raise HTTPException(status_code=404, detail="Record not found.")


def require_global_asset_scope(principal: ApiPrincipal) -> None:
    """Some global assurance surfaces cannot be safely partitioned by asset."""
    if principal.asset_scope_mode != "all":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This operation requires an all-assets credential scope.",
        )


def _route_permission(request: Request) -> str:
    route: Any = request.scope.get("route")
    route_path = getattr(route, "path", None)
    if not isinstance(route_path, str):
        return "admin.only"
    return ROUTE_PERMISSIONS.get((request.method.upper(), route_path), "admin.only")


def _authorize_role(role: str, request: Request, asset_scope_mode: str = "all") -> None:
    permission = _route_permission(request)
    granted = ROLE_PERMISSIONS.get(role, frozenset())
    if asset_scope_mode != "all" and permission == "credential.manage":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Credential administration requires an all-assets API credential.",
        )
    if "*" not in granted and permission not in granted:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This API credential does not have permission to access this operation.",
        )


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def require_api_key(
    request: Request,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    db: Session = Depends(get_db),
) -> ApiPrincipal:
    supplied = x_api_key or ""
    static_credentials = _configured_static_principals()
    if any(len(candidate) < 32 for _, candidate, _, _, _, _, _ in static_credentials):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="API authentication is not securely configured. Static API keys must contain at least 32 characters.",
        )
    matches: list[tuple[str, str, str, int, int, str, frozenset[str]]] = []
    for credential_id, candidate, role, rpm_limit, daily_limit, scope_mode, scope_ids in static_credentials:
        if hmac.compare_digest(supplied, candidate):
            matches.append(
                (credential_id, role, "environment", rpm_limit, daily_limit, scope_mode, scope_ids)
            )

    principal: ApiPrincipal | None = None
    if matches:
        # Configuration validation prevents duplicate key material and IDs.
        credential_id, role, source, rpm_limit, daily_limit, scope_mode, scope_ids = matches[0]
        principal = ApiPrincipal(
            credential_id=credential_id,
            role=role,
            credential_source=source,
            rate_limit_per_minute=rpm_limit,
            daily_request_limit=daily_limit,
            asset_scope_mode=scope_mode,
            asset_scope_ids=scope_ids,
        )
    elif supplied:
        digest = hashlib.sha256(supplied.encode("utf-8")).hexdigest()
        managed = db.scalar(
            select(ApiCredential).where(ApiCredential.key_hash == digest).with_for_update()
        )
        if managed is not None and hmac.compare_digest(managed.key_hash, digest):
            now = datetime.now(UTC)
            expires = _as_utc(managed.expires_at) if managed.expires_at is not None else None
            rotation_deadline = (
                _as_utc(managed.rotation_grace_expires_at)
                if managed.rotation_grace_expires_at is not None
                else None
            )
            rotation_valid = managed.rotated_to_id is None or (
                rotation_deadline is not None and rotation_deadline > now
            )
            if managed.revoked_at is None and (expires is None or expires > now) and rotation_valid:
                scope_mode = getattr(managed, "asset_scope_mode", "all")
                raw_scope_ids = getattr(managed, "asset_scope_ids", []) or []
                if (
                    not isinstance(scope_mode, str)
                    or scope_mode not in {"all", "selected"}
                    or not isinstance(raw_scope_ids, list)
                    or any(not isinstance(asset_id, str) or len(asset_id) != 36 for asset_id in raw_scope_ids)
                    or len(raw_scope_ids) != len(set(raw_scope_ids))
                    or (scope_mode == "selected" and not raw_scope_ids)
                    or (scope_mode == "all" and raw_scope_ids)
                ):
                    raise HTTPException(
                        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                        detail="API credential asset scope is invalid. Contact an administrator.",
                    )
                managed.last_used_at = now
                principal = ApiPrincipal(
                    credential_id=managed.id,
                    role=managed.role,
                    credential_source="database",
                    rate_limit_per_minute=managed.rate_limit_per_minute,
                    daily_request_limit=managed.daily_request_limit,
                    asset_scope_mode=scope_mode,
                    asset_scope_ids=frozenset(raw_scope_ids),
                )

    if principal is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid, expired, revoked or missing API key.",
        )

    _authorize_role(principal.role, request, principal.asset_scope_mode)
    from app.services.credential_quota import consume_credential_quota

    retry_after = consume_credential_quota(
        db,
        principal.credential_id,
        principal.rate_limit_per_minute,
        principal.daily_request_limit,
    )
    if retry_after is not None:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="API credential request quota exceeded. Retry after the quota window resets.",
            headers={"Retry-After": str(retry_after)},
        )
    db.commit()
    request.state.api_principal = principal
    return principal
