import hashlib
import secrets
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from time import perf_counter
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException, Query, Response, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import desc, func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.auth import ROLE_PERMISSIONS, ApiPrincipal, require_api_key
from app.config import get_settings
from app.database import Base, engine, get_db
from app.models import ApiCredential, Assessment, Asset, AuditEvent, RemediationTask
from app.observability import HTTP_METRICS
from app.routes.jobs import router as assessment_jobs_router
from app.schemas import (
    AssessmentRequest,
    AssessmentResponse,
    AssetCreate,
    AssetResponse,
    AssetUpdate,
    CredentialCreate,
    CredentialCreatedResponse,
    CredentialResponse,
    CredentialRevokeResponse,
    CredentialRotateRequest,
    CredentialRotationResponse,
    OverviewResponse,
    RemediationCreate,
    RemediationResponse,
    RemediationUpdate,
    SecretScanRequest,
)
from app.services.assessment_store import add_assessment_result
from app.services.audit import record_audit_event, verify_audit_chain
from app.services.controls import CONTROL_CATALOG, controls_for_findings
from app.services.posture import assess_domain
from app.services.scope import ScopeViolation, authorize_domain
from app.services.secrets import scan_text


@asynccontextmanager
async def lifespan(_: FastAPI):
    # Development/test bootstrap only. Production containers run Alembic before
    # Uvicorn; schema changes must never be hidden behind create_all.
    if settings.environment != "production":
        Base.metadata.create_all(bind=engine)
    yield


settings = get_settings()
is_production = settings.environment == "production"
app = FastAPI(
    title="SENTINEL Defensive Security Platform",
    version="0.10.0-pre",
    description="Authorized asset governance, posture assessment, remediation and tamper-evident audit.",
    docs_url=None if is_production else "/docs",
    redoc_url=None if is_production else "/redoc",
    openapi_url=None if is_production else "/openapi.json",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Content-Type", "X-API-Key", "Idempotency-Key"],
)


@app.middleware("http")
async def security_response_headers(request, call_next):
    request_id = uuid4().hex
    started_at = perf_counter()
    response = await call_next(request)
    if settings.metrics_enabled:
        route = getattr(request.scope.get("route"), "path", "unmatched")
        HTTP_METRICS.observe(
            request.method,
            route,
            response.status_code,
            perf_counter() - started_at,
        )
    response.headers.setdefault("X-Request-ID", request_id)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault("X-Permitted-Cross-Domain-Policies", "none")
    response.headers.setdefault("Cache-Control", "no-store")
    response.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
    return response


app.include_router(assessment_jobs_router)


@app.get("/api/v1/me", dependencies=[Depends(require_api_key)])
def read_api_identity(principal: ApiPrincipal = Depends(require_api_key)):
    permissions = ROLE_PERMISSIONS.get(principal.role, frozenset())
    return {
        "credential_id": principal.credential_id,
        "role": principal.role,
        "credential_source": principal.credential_source,
        "permissions": sorted(permissions),
    }


@app.get(
    "/api/v1/credentials",
    response_model=list[CredentialResponse],
    dependencies=[Depends(require_api_key)],
)
def list_api_credentials(db: Session = Depends(get_db)):
    return db.scalars(select(ApiCredential).order_by(desc(ApiCredential.created_at))).all()


@app.post(
    "/api/v1/credentials",
    response_model=CredentialCreatedResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_api_key)],
)
def create_api_credential(
    payload: CredentialCreate,
    response: Response,
    principal: ApiPrincipal = Depends(require_api_key),
    db: Session = Depends(get_db),
):
    now = datetime.now(UTC)
    if db.bind is not None and db.bind.dialect.name == "postgresql":
        db.execute(
            text("SELECT pg_advisory_xact_lock(:lock_key)"),
            {"lock_key": 7812340912346},
        )
    active_count = (
        db.scalar(
            select(func.count())
            .select_from(ApiCredential)
            .where(
                ApiCredential.revoked_at.is_(None),
                (ApiCredential.expires_at.is_(None)) | (ApiCredential.expires_at > now),
                (ApiCredential.rotated_to_id.is_(None))
                | (ApiCredential.rotation_grace_expires_at > now),
            )
        )
        or 0
    )
    if active_count >= 250:
        raise HTTPException(
            status_code=409, detail="The active API credential limit has been reached."
        )

    secret = secrets.token_urlsafe(48)
    item = ApiCredential(
        label=payload.label,
        role=payload.role,
        key_hash=hashlib.sha256(secret.encode("utf-8")).hexdigest(),
        key_prefix=secret[:12],
        expires_at=payload.expires_at or (now + timedelta(days=90)),
        created_by=principal.credential_id,
        created_at=now,
        rate_limit_per_minute=payload.rate_limit_per_minute,
        daily_request_limit=payload.daily_request_limit,
    )
    db.add(item)
    db.flush()
    db.add(
        record_audit_event(
            db,
            event_type="api_credential.created",
            subject=item.label,
            details=f"credential_id={item.id}; role={item.role}; key_prefix={item.key_prefix}; actor={principal.credential_id}",
        )
    )
    db.commit()
    db.refresh(item)
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return {"credential": item, "secret": secret}


@app.post(
    "/api/v1/credentials/{credential_id}/revoke",
    response_model=CredentialRevokeResponse,
    dependencies=[Depends(require_api_key)],
)
def revoke_api_credential(
    credential_id: str,
    principal: ApiPrincipal = Depends(require_api_key),
    db: Session = Depends(get_db),
):
    item = db.scalar(
        select(ApiCredential).where(ApiCredential.id == credential_id).with_for_update()
    )
    if item is None:
        raise HTTPException(status_code=404, detail="API credential not found.")
    if principal.credential_source == "database" and principal.credential_id == item.id:
        raise HTTPException(
            status_code=409,
            detail="A managed credential cannot revoke itself; use a different admin credential.",
        )
    if item.revoked_at is None:
        item.revoked_at = datetime.now(UTC)
        db.add(
            record_audit_event(
                db,
                event_type="api_credential.revoked",
                subject=item.label,
                details=f"credential_id={item.id}; role={item.role}; actor={principal.credential_id}",
            )
        )
        db.commit()
        db.refresh(item)
    return {"id": item.id, "status": "revoked", "revoked_at": item.revoked_at}


@app.post(
    "/api/v1/credentials/{credential_id}/rotate",
    response_model=CredentialRotationResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_api_key)],
)
def rotate_api_credential(
    credential_id: str,
    payload: CredentialRotateRequest,
    response: Response,
    principal: ApiPrincipal = Depends(require_api_key),
    db: Session = Depends(get_db),
):
    now = datetime.now(UTC)
    item = db.scalar(
        select(ApiCredential).where(ApiCredential.id == credential_id).with_for_update()
    )
    if item is None:
        raise HTTPException(status_code=404, detail="API credential not found.")
    if item.revoked_at is not None or item.rotated_to_id is not None:
        raise HTTPException(
            status_code=409, detail="Only an active, unrotated credential can be rotated."
        )
    current_expiry = (
        _aware_utc(item.expires_at) if item.expires_at is not None else now + timedelta(days=90)
    )
    if current_expiry <= now:
        raise HTTPException(status_code=409, detail="An expired credential cannot be rotated.")

    if db.bind is not None and db.bind.dialect.name == "postgresql":
        db.execute(
            text("SELECT pg_advisory_xact_lock(:lock_key)"),
            {"lock_key": 7812340912346},
        )
    active_count = (
        db.scalar(
            select(func.count())
            .select_from(ApiCredential)
            .where(
                ApiCredential.id != item.id,
                ApiCredential.revoked_at.is_(None),
                (ApiCredential.expires_at.is_(None)) | (ApiCredential.expires_at > now),
                (ApiCredential.rotated_to_id.is_(None))
                | (ApiCredential.rotation_grace_expires_at > now),
            )
        )
        or 0
    )
    grace_expires_at = now + timedelta(seconds=payload.grace_period_seconds)
    temporary_previous_key = payload.grace_period_seconds > 0
    projected_active_count = active_count + 1 + int(temporary_previous_key)
    if projected_active_count > 250:
        raise HTTPException(
            status_code=409,
            detail="The active API credential limit would be exceeded during the rotation grace period.",
        )

    secret = secrets.token_urlsafe(48)
    replacement = ApiCredential(
        label=item.label,
        role=item.role,
        key_hash=hashlib.sha256(secret.encode("utf-8")).hexdigest(),
        key_prefix=secret[:12],
        expires_at=current_expiry,
        created_by=principal.credential_id,
        created_at=now,
        rate_limit_per_minute=item.rate_limit_per_minute,
        daily_request_limit=item.daily_request_limit,
    )
    db.add(replacement)
    db.flush()

    item.rotated_to_id = replacement.id
    item.rotation_grace_expires_at = grace_expires_at
    db.add(
        record_audit_event(
            db,
            event_type="api_credential.rotated",
            subject=item.label,
            details=(
                f"previous_credential_id={item.id}; replacement_credential_id={replacement.id}; "
                f"grace_period_seconds={payload.grace_period_seconds}; actor={principal.credential_id}"
            ),
        )
    )
    db.commit()
    db.refresh(replacement)
    db.refresh(item)
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return {
        "previous_credential_id": item.id,
        "grace_expires_at": grace_expires_at,
        "credential": replacement,
        "secret": secret,
    }


def _aware_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _ensure_asset_authorization(asset: Asset) -> None:
    expires = _aware_utc(asset.authorization_expires_at)
    if asset.status != "active":
        raise HTTPException(status_code=409, detail="Asset is not active.")
    if expires <= datetime.now(UTC):
        raise HTTPException(
            status_code=403,
            detail="Asset authorization has expired. Renew its authorization record before assessment.",
        )


def _persist_assessment(
    db: Session,
    result: dict,
    asset: Asset | None = None,
) -> Assessment:
    item = add_assessment_result(
        db,
        result,
        asset,
        max_records=settings.max_assessment_records,
    )
    db.commit()
    db.refresh(item)
    return item


@app.get("/metrics", include_in_schema=False)
def metrics():
    if not settings.metrics_enabled:
        raise HTTPException(status_code=404, detail="Not found.")
    return Response(
        content=HTTP_METRICS.render(),
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )


@app.get("/healthz")
def healthz():
    return {
        "status": "ok",
        "service": "sentinel-api",
        "version": "0.10.0-pre",
        "timestamp": datetime.now(UTC).isoformat(),
    }


@app.get("/readyz")
def readyz(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
        if settings.environment == "production":
            from alembic.config import Config
            from alembic.runtime.migration import MigrationContext
            from alembic.script import ScriptDirectory

            migration_config = Config(str(Path(__file__).resolve().parents[1] / "alembic.ini"))
            expected_revision = ScriptDirectory.from_config(migration_config).get_current_head()
            migration_context = MigrationContext.configure(db.connection())
            current_revision = migration_context.get_current_revision()
            if current_revision != expected_revision:
                raise HTTPException(
                    status_code=503,
                    detail="Database migrations are not at the current application revision.",
                )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Database readiness check failed.") from exc
    return {"status": "ready", "database": "reachable"}


@app.get("/api/v1/config", dependencies=[Depends(require_api_key)])
def read_config():
    return {
        "version": "0.10.0-pre",
        "authorized_domains": settings.allowed_domain_list,
        "features": [
            "dns-pinned-https-headers",
            "tls-certificate",
            "dns-email-posture",
            "explainable-risk-v2",
            "asset-inventory",
            "time-bounded-authorization",
            "remediation-workflow",
            "tamper-evident-audit",
            "control-catalog",
            "alembic-migrations",
            "overlapping-api-key-rotation",
            "audited-csv-exports",
            "extended-dns-posture",
            "security-header-policy-analysis",
            "durable-assessment-jobs",
            "scheduled-assessment-jobs",
            "idempotent-job-requests",
            "postgresql-row-locked-worker-claims",
            "lease-based-worker-recovery",
            "bounded-job-retries-and-dead-letter",
            "cooperative-job-cancellation",
            "resource-bounded-assessment-worker-service",
            "route-level-rbac",
            "role-scoped-static-api-credentials",
            "database-managed-api-credentials",
            "credential-expiry-and-revocation",
            "per-service-fixed-window-api-quotas",
            "postgresql-atomic-credential-rate-limits",
            "credential-rotation-with-bounded-grace-period",
            "offline-ed25519-audit-checkpoints",
        ],
        "network_policy": "HTTPS-only, validated public DNS answers, pinned IP connection, no redirects, headers-only response read",
    }


@app.get(
    "/api/v1/overview", response_model=OverviewResponse, dependencies=[Depends(require_api_key)]
)
def overview(db: Session = Depends(get_db)):
    assessment_count = db.scalar(select(func.count()).select_from(Assessment)) or 0
    findings_count = sum(len(item.findings or []) for item in db.scalars(select(Assessment)).all())
    high_risk_count = (
        db.scalar(
            select(func.count())
            .select_from(Assessment)
            .where(Assessment.risk_level.in_(["high", "critical"]))
        )
        or 0
    )
    asset_count = db.scalar(select(func.count()).select_from(Asset)) or 0
    active_asset_count = (
        db.scalar(select(func.count()).select_from(Asset).where(Asset.status == "active")) or 0
    )
    open_remediation_count = (
        db.scalar(
            select(func.count())
            .select_from(RemediationTask)
            .where(RemediationTask.status.in_(["open", "in_progress"]))
        )
        or 0
    )
    return OverviewResponse(
        assessment_count=assessment_count,
        findings_count=findings_count,
        high_risk_count=high_risk_count,
        authorized_domains=settings.allowed_domain_list,
        asset_count=asset_count,
        active_asset_count=active_asset_count,
        open_remediation_count=open_remediation_count,
    )


@app.get(
    "/api/v1/assets",
    response_model=list[AssetResponse],
    dependencies=[Depends(require_api_key)],
)
def list_assets(
    active_only: bool = Query(default=False),
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
):
    query = select(Asset).order_by(desc(Asset.updated_at)).limit(limit)
    if active_only:
        query = query.where(Asset.status == "active")
    return db.scalars(query).all()


@app.post(
    "/api/v1/assets",
    response_model=AssetResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_api_key)],
)
def create_asset(payload: AssetCreate, db: Session = Depends(get_db)):
    try:
        hostname = authorize_domain(payload.hostname, settings.allowed_domain_list)
    except ScopeViolation as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    item = Asset(
        hostname=hostname,
        name=payload.name.strip(),
        owner=payload.owner.strip(),
        environment=payload.environment,
        criticality=payload.criticality,
        authorization_expires_at=payload.authorization_expires_at,
        authorization_reference=payload.authorization_reference.strip(),
        tags=payload.tags,
        status="active",
    )
    existing = db.scalar(select(Asset.id).where(Asset.hostname == hostname))
    if existing:
        raise HTTPException(
            status_code=409, detail="An asset with this hostname is already registered."
        )

    db.add(item)
    try:
        db.flush()
        db.add(
            record_audit_event(
                db,
                event_type="asset.registered",
                subject=hostname,
                details=f"asset_id={item.id}; owner={item.owner}; authorization_ref={item.authorization_reference}",
            )
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=409, detail="An asset with this hostname is already registered."
        ) from exc
    db.refresh(item)
    return item


@app.patch(
    "/api/v1/assets/{asset_id}",
    response_model=AssetResponse,
    dependencies=[Depends(require_api_key)],
)
def update_asset(asset_id: str, payload: AssetUpdate, db: Session = Depends(get_db)):
    item = db.get(Asset, asset_id)
    if not item:
        raise HTTPException(status_code=404, detail="Asset not found.")
    changes = payload.model_dump(exclude_unset=True)
    for key, value in changes.items():
        if key == "owner" and value is not None:
            value = value.strip()
        elif key == "name" and value is not None:
            value = value.strip()
        elif key == "authorization_reference" and value is not None:
            value = value.strip()
        setattr(item, key, value)
    item.updated_at = datetime.now(UTC)
    db.add(
        record_audit_event(
            db,
            event_type="asset.updated",
            subject=item.hostname,
            details=f"asset_id={item.id}; changed_fields={','.join(sorted(changes))}",
        )
    )
    db.commit()
    db.refresh(item)
    return item


@app.post(
    "/api/v1/assets/{asset_id}/assessments",
    response_model=AssessmentResponse,
    dependencies=[Depends(require_api_key)],
)
async def assess_registered_asset(asset_id: str, db: Session = Depends(get_db)):
    asset = db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found.")
    _ensure_asset_authorization(asset)
    try:
        result = await assess_domain(
            asset.hostname,
            settings.allowed_domain_list,
            timeout=settings.request_timeout_seconds,
            context={
                "asset_criticality": asset.criticality,
                "asset_id": asset.id,
                "asset_environment": asset.environment,
            },
        )
    except ScopeViolation as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _persist_assessment(db, result, asset=asset)


@app.get(
    "/api/v1/assessments",
    response_model=list[AssessmentResponse],
    dependencies=[Depends(require_api_key)],
)
def list_assessments(
    limit: int = Query(default=25, ge=1, le=100),
    asset_id: str | None = Query(default=None),
    db: Session = Depends(get_db),
):
    query = select(Assessment).order_by(desc(Assessment.created_at)).limit(limit)
    if asset_id:
        query = query.where(Assessment.asset_id == asset_id)
    return db.scalars(query).all()


@app.get(
    "/api/v1/assessments/{assessment_id}",
    response_model=AssessmentResponse,
    dependencies=[Depends(require_api_key)],
)
def get_assessment(assessment_id: str, db: Session = Depends(get_db)):
    item = db.get(Assessment, assessment_id)
    if not item:
        raise HTTPException(status_code=404, detail="Assessment not found.")
    return item


@app.post(
    "/api/v1/assessments",
    response_model=AssessmentResponse,
    dependencies=[Depends(require_api_key)],
)
async def create_assessment(payload: AssessmentRequest, db: Session = Depends(get_db)):
    try:
        result = await assess_domain(
            payload.domain,
            settings.allowed_domain_list,
            timeout=settings.request_timeout_seconds,
        )
    except ScopeViolation as exc:
        db.add(
            record_audit_event(
                db,
                event_type="assessment.denied",
                subject=payload.domain[:253],
                result="denied",
                details=str(exc)[:500],
            )
        )
        db.commit()
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _persist_assessment(db, result)


@app.get(
    "/api/v1/remediations",
    response_model=list[RemediationResponse],
    dependencies=[Depends(require_api_key)],
)
def list_remediations(
    state: str | None = Query(
        default=None, alias="status", pattern="^(open|in_progress|resolved|accepted)$"
    ),
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
):
    query = select(RemediationTask).order_by(desc(RemediationTask.updated_at)).limit(limit)
    if state:
        query = query.where(RemediationTask.status == state)
    return db.scalars(query).all()


@app.post(
    "/api/v1/remediations",
    response_model=RemediationResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_api_key)],
)
def create_remediation(payload: RemediationCreate, db: Session = Depends(get_db)):
    assessment = db.get(Assessment, payload.assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found.")
    finding = next(
        (item for item in (assessment.findings or []) if item.get("code") == payload.finding_code),
        None,
    )
    if not finding:
        raise HTTPException(
            status_code=404, detail="Finding code does not exist in the selected assessment."
        )
    item = RemediationTask(
        assessment_id=assessment.id,
        asset_id=assessment.asset_id,
        finding_code=payload.finding_code,
        title=finding.get("title", payload.finding_code),
        severity=finding.get("severity", "medium"),
        assignee=payload.assignee.strip(),
        due_at=payload.due_at,
        notes=payload.notes,
    )
    db.add(item)
    db.flush()
    db.add(
        record_audit_event(
            db,
            event_type="remediation.created",
            subject=assessment.target,
            details=f"task_id={item.id}; finding={item.finding_code}",
        )
    )
    db.commit()
    db.refresh(item)
    return item


@app.patch(
    "/api/v1/remediations/{task_id}",
    response_model=RemediationResponse,
    dependencies=[Depends(require_api_key)],
)
def update_remediation(task_id: str, payload: RemediationUpdate, db: Session = Depends(get_db)):
    item = db.get(RemediationTask, task_id)
    if not item:
        raise HTTPException(status_code=404, detail="Remediation task not found.")
    changes = payload.model_dump(exclude_unset=True)
    for key, value in changes.items():
        if key == "assignee" and value is not None:
            value = value.strip()
        setattr(item, key, value)
    item.updated_at = datetime.now(UTC)
    db.add(
        record_audit_event(
            db,
            event_type="remediation.updated",
            subject=item.finding_code,
            details=f"task_id={item.id}; changed_fields={','.join(sorted(changes))}; status={item.status}",
        )
    )
    db.commit()
    db.refresh(item)
    return item


@app.get("/api/v1/controls", dependencies=[Depends(require_api_key)])
def read_control_catalog(db: Session = Depends(get_db)):
    assessments = db.scalars(
        select(Assessment).order_by(desc(Assessment.created_at)).limit(100)
    ).all()
    findings = [finding for assessment in assessments for finding in (assessment.findings or [])]
    return {
        "catalog": CONTROL_CATALOG,
        "assessment_count": len(assessments),
        "controls": controls_for_findings(findings),
        "note": "Operational control mapping only; this is not a regulatory certification or audit opinion.",
    }


@app.post("/api/v1/secrets/scan", dependencies=[Depends(require_api_key)])
def scan_submitted_text(payload: SecretScanRequest, db: Session = Depends(get_db)):
    """Scan a bounded text payload; never persist or echo the submitted source."""
    findings = scan_text(payload.content)
    byte_count = len(payload.content.encode("utf-8"))
    db.add(
        record_audit_event(
            db,
            event_type="secrets.scan",
            subject="inline-text",
            details=f"input_bytes={byte_count}; findings={len(findings)}; source_persisted=false",
        )
    )
    db.commit()
    return {
        "findings": findings,
        "finding_count": len(findings),
        "input_bytes": byte_count,
        "source_persisted": False,
        "redaction_policy": "Matched values are never returned; only a short SHA-256 fingerprint is disclosed.",
    }


@app.get("/api/v1/audit/integrity", dependencies=[Depends(require_api_key)])
def audit_integrity(
    through_sequence: int | None = Query(default=None, ge=1),
    db: Session = Depends(get_db),
):
    """Verify the full journal or a historical prefix for offline checkpoint comparison."""
    return verify_audit_chain(db, through_sequence=through_sequence)


@app.get("/api/v1/audit", dependencies=[Depends(require_api_key)])
def list_audit_events(limit: int = Query(default=50, ge=1, le=200), db: Session = Depends(get_db)):
    events = db.scalars(
        select(AuditEvent)
        .order_by(desc(AuditEvent.sequence_no), desc(AuditEvent.created_at))
        .limit(limit)
    ).all()
    return [
        {
            "id": event.id,
            "event_type": event.event_type,
            "subject": event.subject,
            "result": event.result,
            "details": event.details,
            "sequence_no": event.sequence_no,
            "previous_hash": event.previous_hash,
            "event_hash": event.event_hash,
            "created_at": event.created_at,
        }
        for event in events
    ]


@app.get("/api/v1/exports/{dataset}.csv", dependencies=[Depends(require_api_key)])
def export_dataset(dataset: str, db: Session = Depends(get_db)):
    """Export a bounded operational dataset; spreadsheet formula payloads are neutralized."""
    from fastapi.responses import Response

    from app.services.exports import render_csv

    if dataset not in {"assets", "assessments", "findings", "remediations", "audit"}:
        raise HTTPException(status_code=404, detail="Unknown export dataset.")

    if dataset == "assets":
        items = db.scalars(select(Asset).order_by(Asset.hostname).limit(5000)).all()
        headers = [
            "id",
            "hostname",
            "name",
            "owner",
            "environment",
            "criticality",
            "status",
            "authorization_expires_at",
            "authorization_reference",
            "tags",
            "created_at",
        ]
        rows = [
            [
                item.id,
                item.hostname,
                item.name,
                item.owner,
                item.environment,
                item.criticality,
                item.status,
                item.authorization_expires_at.isoformat(),
                item.authorization_reference,
                ", ".join(item.tags or []),
                item.created_at.isoformat(),
            ]
            for item in items
        ]
    elif dataset == "assessments":
        items = db.scalars(
            select(Assessment).order_by(desc(Assessment.created_at)).limit(5000)
        ).all()
        headers = [
            "id",
            "asset_id",
            "target",
            "status",
            "score",
            "risk_level",
            "finding_count",
            "created_at",
        ]
        rows = [
            [
                item.id,
                item.asset_id,
                item.target,
                item.status,
                item.score,
                item.risk_level,
                len(item.findings or []),
                item.created_at.isoformat(),
            ]
            for item in items
        ]
    elif dataset == "findings":
        items = db.scalars(
            select(Assessment).order_by(desc(Assessment.created_at)).limit(1000)
        ).all()
        headers = [
            "assessment_id",
            "asset_id",
            "target",
            "finding_code",
            "title",
            "severity",
            "category",
            "confidence",
            "description",
            "recommendation",
            "observed_at",
        ]
        rows = [
            [
                item.id,
                item.asset_id,
                item.target,
                finding.get("code", ""),
                finding.get("title", ""),
                finding.get("severity", ""),
                finding.get("category", ""),
                finding.get("confidence", ""),
                finding.get("description", ""),
                finding.get("recommendation", ""),
                item.created_at.isoformat(),
            ]
            for item in items
            for finding in (item.findings or [])
        ][:10000]
    elif dataset == "remediations":
        items = db.scalars(
            select(RemediationTask).order_by(desc(RemediationTask.updated_at)).limit(5000)
        ).all()
        headers = [
            "id",
            "assessment_id",
            "asset_id",
            "finding_code",
            "title",
            "severity",
            "assignee",
            "status",
            "due_at",
            "notes",
            "created_at",
            "updated_at",
        ]
        rows = [
            [
                item.id,
                item.assessment_id,
                item.asset_id,
                item.finding_code,
                item.title,
                item.severity,
                item.assignee,
                item.status,
                item.due_at.isoformat() if item.due_at else "",
                item.notes,
                item.created_at.isoformat(),
                item.updated_at.isoformat(),
            ]
            for item in items
        ]
    else:
        items = db.scalars(select(AuditEvent).order_by(AuditEvent.sequence_no).limit(5000)).all()
        headers = [
            "sequence_no",
            "id",
            "event_type",
            "subject",
            "result",
            "details",
            "previous_hash",
            "event_hash",
            "created_at",
        ]
        rows = [
            [
                item.sequence_no,
                item.id,
                item.event_type,
                item.subject,
                item.result,
                item.details,
                item.previous_hash,
                item.event_hash,
                item.created_at.isoformat(),
            ]
            for item in items
        ]

    csv_content = render_csv(headers, rows)
    db.add(
        record_audit_event(
            db,
            event_type="data.exported",
            subject=dataset,
            details=f"dataset={dataset}; rows={len(rows)}; format=csv",
        )
    )
    db.commit()
    return Response(
        content=csv_content,
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="sentinel-{dataset}.csv"',
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )
