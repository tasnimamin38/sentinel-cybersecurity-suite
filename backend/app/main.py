import hashlib
import logging
import secrets
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException, Query, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.background import BackgroundTask
from redis.asyncio import Redis
import httpx
from sqlalchemy import desc, func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.auth import ROLE_PERMISSIONS, ApiPrincipal, require_api_key
from app.config import get_settings
from app.database import Base, SessionLocal, engine, get_db
from app.models import ApiCredential, Assessment, Asset, AuditEvent, RemediationTask
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
from app.services.rate_limit import RateLimiterUnavailable, RedisSlidingWindowLimiter
from app.services.security_monitor import (
    classify_security_response,
    persist_security_evidence,
    resolve_client_ip,
    sign_alert_payload,
)

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(application: FastAPI):
    # Development/test bootstrap only. Production containers run Alembic before
    # Uvicorn; schema changes must never be hidden behind create_all.
    if settings.environment != "production":
        Base.metadata.create_all(bind=engine)

    redis_client: Redis | None = None
    application.state.redis = None
    application.state.rate_limiter = None
    if settings.redis_url:
        redis_client = Redis.from_url(
            settings.redis_url,
            decode_responses=False,
            socket_connect_timeout=1.5,
            socket_timeout=1.5,
            health_check_interval=30,
            max_connections=64,
        )
        try:
            await redis_client.ping()
        except Exception as exc:
            await redis_client.aclose()
            raise RuntimeError(
                "Shared Redis protection is unavailable; API startup refused."
            ) from exc
        application.state.redis = redis_client
        application.state.rate_limiter = RedisSlidingWindowLimiter(redis_client)

    try:
        yield
    finally:
        if redis_client is not None:
            await redis_client.aclose()


settings = get_settings()
is_production = settings.environment == "production"
app = FastAPI(
    title="SENTINEL Defensive Security Platform",
    version="0.7.0-pre",
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


async def _send_security_webhook(url: str, secret: str, payload: dict) -> None:
    body, signature = sign_alert_payload(payload, secret)
    try:
        async with httpx.AsyncClient(
            timeout=4.0,
            follow_redirects=False,
            trust_env=False,
        ) as client:
            response = await client.post(
                url,
                content=body,
                headers={
                    "Content-Type": "application/json",
                    "X-SENTINEL-Signature": signature,
                    "X-SENTINEL-Event": str(payload.get("rule_id", "security-event")),
                },
            )
            response.raise_for_status()
    except (httpx.HTTPError, ValueError):
        # Do not log the URL, secret, body or any attacker-supplied values.
        logger.warning("Security webhook delivery failed.")


@app.middleware("http")
async def security_response_headers(request, call_next):
    request_id = uuid4().hex
    request.state.request_id = request_id
    response = None
    source_ip = resolve_client_ip(
        peer_ip=request.client.host if request.client else None,
        x_real_ip=request.headers.get("X-Real-IP"),
        trusted_proxy_cidrs=settings.trusted_proxy_cidr_list,
    )

    if request.url.path.startswith("/api/v1/") and request.method.upper() != "OPTIONS":
        limiter = getattr(request.app.state, "rate_limiter", None)
        if limiter is None and settings.environment == "production":
            response = JSONResponse(
                status_code=503,
                content={"detail": "Request protection is temporarily unavailable."},
            )
        elif limiter is not None:
            supplied_key = request.headers.get("X-API-Key", "")
            key_identity = hashlib.sha256(
                (supplied_key if supplied_key else "anonymous:" + source_ip).encode("utf-8")
            ).hexdigest()
            ip_identity = hashlib.sha256(source_ip.encode("utf-8")).hexdigest()
            policies = [
                ("ip", ip_identity, settings.ip_rate_limit_per_minute),
                ("key", key_identity, settings.api_rate_limit_per_minute),
            ]
            if request.method.upper() == "POST" and request.url.path.endswith("/assessments"):
                policies.append(
                    ("assessment", key_identity, settings.assessment_rate_limit_per_minute)
                )
            if request.method.upper() == "POST" and request.url.path.endswith("/secrets/scan"):
                policies.append(
                    ("secret-scan", key_identity, settings.secret_scan_rate_limit_per_minute)
                )
            try:
                for bucket, identity, limit in policies:
                    decision = await limiter.check(
                        f"sentinel:rate:{bucket}:{identity}",
                        limit,
                        settings.rate_limit_window_seconds,
                    )
                    if not decision.allowed:
                        response = JSONResponse(
                            status_code=429,
                            content={"detail": "Request rate limit exceeded. Retry later."},
                            headers={"Retry-After": str(decision.retry_after_seconds)},
                        )
                        break
            except RateLimiterUnavailable:
                response = JSONResponse(
                    status_code=503,
                    content={"detail": "Request protection is temporarily unavailable."},
                )

    if response is None:
        response = await call_next(request)

    response.headers.setdefault("X-Request-ID", request_id)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault("X-Permitted-Cross-Domain-Policies", "none")
    response.headers.setdefault("Cache-Control", "no-store")
    response.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")

    signal = classify_security_response(request.url.path, response.status_code)
    if signal:
        try:
            with SessionLocal() as db:
                alerts = persist_security_evidence(
                    db,
                    signal=signal,
                    source_ip=source_ip,
                    path=request.url.path,
                    method=request.method,
                    user_agent=request.headers.get("User-Agent", ""),
                    request_id=request_id,
                    auth_failure_threshold=settings.auth_failure_threshold,
                    auth_failure_window_seconds=settings.auth_failure_window_seconds,
                )
                db.commit()
            if settings.security_alert_webhook_url and settings.security_alert_webhook_secret:
                for alert in alerts:
                    response.background = BackgroundTask(
                        _send_security_webhook,
                        settings.security_alert_webhook_url,
                        settings.security_alert_webhook_secret,
                        alert,
                    )
        except Exception:
            # Evidence persistence must not turn an otherwise handled request
            # into an application error; the server log carries only the class.
            logger.exception("Unable to persist SENTINEL security evidence.")

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


@app.get("/healthz")
def healthz():
    return {
        "status": "ok",
        "service": "sentinel-api",
        "version": "0.7.0-pre",
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
        "version": "0.7.0-pre",
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
def audit_integrity(db: Session = Depends(get_db)):
    return verify_audit_chain(db)


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


@app.get("/api/v1/security/events", dependencies=[Depends(require_api_key)])
def list_security_events(
    limit: int = Query(default=50, ge=1, le=200),
    severity: str | None = Query(default=None, pattern="^(low|medium|high|critical)$"),
    db: Session = Depends(get_db),
):
    """List sanitized runtime intrusion signals from the hash-linked audit journal."""
    statement = (
        select(AuditEvent)
        .where(AuditEvent.event_type.like("security.%"))
        .order_by(desc(AuditEvent.created_at), desc(AuditEvent.sequence_no))
        .limit(limit)
    )
    events = db.scalars(statement).all()
    results = []
    for event in events:
        try:
            details = json.loads(event.details)
        except (TypeError, ValueError):
            details = {}
        if severity and details.get("severity") != severity:
            continue
        results.append(
            {
                "id": event.id,
                "event_type": event.event_type,
                "severity": details.get("severity", event.result),
                "source_ip": event.subject,
                "details": details,
                "sequence_no": event.sequence_no,
                "event_hash": event.event_hash,
                "created_at": event.created_at,
            }
        )
    return results


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
