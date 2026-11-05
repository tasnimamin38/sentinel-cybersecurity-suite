import hashlib
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from redis.asyncio import Redis
from sqlalchemy import delete, desc, exists, func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.auth import require_api_key
from app.config import get_settings
from app.database import Base, engine, get_db
from app.models import Assessment, Asset, AuditEvent, RemediationTask
from app.schemas import (
    AssessmentRequest,
    AssessmentResponse,
    AssetCreate,
    AssetResponse,
    AssetUpdate,
    OverviewResponse,
    RemediationCreate,
    RemediationResponse,
    RemediationUpdate,
    SecretScanRequest,
)
from app.services.audit import record_audit_event, verify_audit_chain
from app.services.controls import CONTROL_CATALOG, controls_for_findings
from app.services.posture import assess_domain
from app.services.rate_limit import RateLimiterUnavailable, RedisSlidingWindowLimiter
from app.services.request_limits import RequestBodySizeLimitMiddleware
from app.services.scope import ScopeViolation, authorize_domain
from app.services.secrets import scan_text


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
                "Shared rate-limit storage is unavailable; API startup refused."
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
    version="0.3.4",
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
    allow_headers=["Content-Type", "X-API-Key"],
)
app.add_middleware(RequestBodySizeLimitMiddleware, max_bytes=settings.max_request_body_bytes)


@app.middleware("http")
async def security_response_headers(request: Request, call_next):
    request_id = uuid4().hex
    rate_headers: dict[str, str] = {}

    if request.url.path.startswith("/api/v1/"):
        limiter = getattr(request.app.state, "rate_limiter", None)
        if limiter is None and settings.environment == "production":
            response = JSONResponse(
                status_code=503,
                content={"detail": "Request protection is temporarily unavailable."},
            )
        elif limiter is None:
            response = await call_next(request)
        else:
            peer = request.client.host if request.client else "unknown"
            supplied_key = request.headers.get("X-API-Key", "")
            api_identity = hashlib.sha256(
                (supplied_key if supplied_key else "anonymous:" + peer).encode("utf-8")
            ).hexdigest()
            ip_identity = hashlib.sha256(peer.encode("utf-8")).hexdigest()
            window = settings.rate_limit_window_seconds
            policies = [
                ("ip", ip_identity, settings.ip_rate_limit_per_minute),
                ("client", api_identity, settings.api_rate_limit_per_minute),
            ]
            if request.method == "POST" and request.url.path.endswith("/assessments"):
                policies.append(
                    ("assessment", api_identity, settings.assessment_rate_limit_per_minute)
                )
            if request.method == "POST" and request.url.path.endswith("/secrets/scan"):
                policies.append(
                    ("secret-scan", api_identity, settings.secret_scan_rate_limit_per_minute)
                )

            try:
                for bucket, identity, limit in policies:
                    decision = await limiter.check(
                        f"sentinel:rate:{bucket}:{identity}", limit, window
                    )
                    if not decision.allowed:
                        response = JSONResponse(
                            status_code=429,
                            content={
                                "detail": "Request rate limit exceeded. Retry after the indicated delay."
                            },
                            headers={
                                "Retry-After": str(decision.retry_after_seconds),
                                "X-RateLimit-Limit": str(limit),
                                "X-RateLimit-Remaining": "0",
                                "RateLimit-Policy": f"{limit};w={window}",
                            },
                        )
                        break
                    if bucket in ("client", "assessment", "secret-scan"):
                        rate_headers = {
                            "X-RateLimit-Limit": str(limit),
                            "X-RateLimit-Remaining": str(decision.remaining),
                            "RateLimit-Policy": f"{limit};w={window}",
                        }
                else:
                    response = await call_next(request)
            except RateLimiterUnavailable:
                response = JSONResponse(
                    status_code=503,
                    content={"detail": "Request protection is temporarily unavailable."},
                )
    else:
        response = await call_next(request)

    response.headers.setdefault("X-Request-ID", request_id)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault("X-Permitted-Cross-Domain-Policies", "none")
    response.headers.setdefault("Cache-Control", "no-store")
    response.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
    for header, value in rate_headers.items():
        response.headers.setdefault(header, value)
    return response


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
    item = Assessment(
        asset_id=asset.id if asset else None,
        target=result["target"],
        status=result["status"],
        score=result["score"],
        risk_level=result["risk_level"],
        findings=result["findings"],
        evidence={
            **result["evidence"],
            "risk_explanation": result["risk_explanation"],
        },
    )
    db.add(item)
    db.flush()
    db.add(
        record_audit_event(
            db,
            event_type="assessment.completed",
            subject=result["target"],
            details=f"assessment_id={item.id}; asset_id={item.asset_id or 'unregistered'}; score={result['score']}; findings={len(result['findings'])}",
        )
    )
    excess_ids = db.scalars(
        select(Assessment.id)
        .where(
            Assessment.id != item.id,
            ~exists().where(RemediationTask.assessment_id == Assessment.id),
        )
        .order_by(desc(Assessment.created_at), desc(Assessment.id))
        .offset(settings.max_assessment_records - 1)
    ).all()
    if excess_ids:
        db.execute(delete(Assessment).where(Assessment.id.in_(excess_ids)))
    db.commit()
    db.refresh(item)
    return item


@app.get("/healthz")
def healthz():
    return {
        "status": "ok",
        "service": "sentinel-api",
        "version": "0.3.4",
        "timestamp": datetime.now(UTC).isoformat(),
    }


@app.get("/readyz")
async def readyz(db: Session = Depends(get_db)):
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
    readiness = {"status": "ready", "database": "reachable"}
    if settings.redis_url:
        redis_client = getattr(app.state, "redis", None)
        try:
            if redis_client is None:
                raise RuntimeError("Redis client is not initialized")
            await redis_client.ping()
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail="Shared rate-limit storage readiness check failed.",
            ) from exc
        readiness["rate_limiter"] = "reachable"
    return readiness


@app.get("/api/v1/config", dependencies=[Depends(require_api_key)])
def read_config():
    return {
        "version": "0.3.4",
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
            "redis-sliding-window-rate-limits",
            "ip-and-api-key-rate-limit-buckets",
            "strict-assessment-and-secret-scan-rate-limits",
            "bounded-api-request-body-size",
        ],
        "request_limits": {
            "max_body_bytes": settings.max_request_body_bytes,
        },
        "rate_limits": {
            "window_seconds": settings.rate_limit_window_seconds,
            "api_requests_per_window": settings.api_rate_limit_per_minute,
            "ip_requests_per_window": settings.ip_rate_limit_per_minute,
            "assessment_requests_per_window": settings.assessment_rate_limit_per_minute,
            "secret_scans_per_window": settings.secret_scan_rate_limit_per_minute,
            "algorithm": "redis-atomic-sliding-window-log",
        },
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
