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
    ("POST", "/api/v1/assessments"): "assessment.run",
    ("GET", "/api/v1/remediations"): "remediation.read",
    ("POST", "/api/v1/remediations"): "remediation.write",
    ("PATCH", "/api/v1/remediations/{task_id}"): "remediation.write",
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
}


def _configured_static_principals() -> list[tuple[str, str, str]]:
    settings = get_settings()
    principals: list[tuple[str, str, str]] = []
    for index, key in enumerate(settings.configured_api_keys):
        principals.append((f"legacy-admin-{index + 1}", key, "admin"))
    for item in getattr(settings, "configured_role_credentials", []):
        principals.append((item["id"], item["key"], item["role"]))
    return principals


def _route_permission(request: Request) -> str:
    route: Any = request.scope.get("route")
    route_path = getattr(route, "path", None)
    if not isinstance(route_path, str):
        return "admin.only"
    return ROUTE_PERMISSIONS.get((request.method.upper(), route_path), "admin.only")


def _authorize_role(role: str, request: Request) -> None:
    permission = _route_permission(request)
    granted = ROLE_PERMISSIONS.get(role, frozenset())
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
    if any(len(candidate) < 32 for _, candidate, _ in static_credentials):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="API authentication is not securely configured. Static API keys must contain at least 32 characters.",
        )
    matches: list[tuple[str, str, str]] = []
    for credential_id, candidate, role in static_credentials:
        if hmac.compare_digest(supplied, candidate):
            matches.append((credential_id, role, "environment"))

    principal: ApiPrincipal | None = None
    if matches:
        # Configuration validation prevents duplicate key material and IDs.
        credential_id, role, source = matches[0]
        principal = ApiPrincipal(credential_id=credential_id, role=role, credential_source=source)
    elif supplied:
        digest = hashlib.sha256(supplied.encode("utf-8")).hexdigest()
        managed = db.scalar(
            select(ApiCredential).where(ApiCredential.key_hash == digest).with_for_update()
        )
        if managed is not None and hmac.compare_digest(managed.key_hash, digest):
            now = datetime.now(UTC)
            expires = _as_utc(managed.expires_at) if managed.expires_at is not None else None
            if managed.revoked_at is None and (expires is None or expires > now):
                managed.last_used_at = now
                db.commit()
                principal = ApiPrincipal(
                    credential_id=managed.id,
                    role=managed.role,
                    credential_source="database",
                )

    if principal is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid, expired, revoked or missing API key.",
        )

    _authorize_role(principal.role, request)
    request.state.api_principal = principal
    return principal
