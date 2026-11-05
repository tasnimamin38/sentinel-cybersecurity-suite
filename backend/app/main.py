from contextlib import asynccontextmanager
from datetime import UTC, datetime

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.auth import require_api_key
from app.config import get_settings
from app.database import Base, engine, get_db
from app.models import Assessment, AuditEvent
from app.schemas import AssessmentRequest, AssessmentResponse, OverviewResponse
from app.services.posture import assess_domain
from app.services.scope import ScopeViolation


@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield


settings = get_settings()
app = FastAPI(
    title="SENTINEL Defensive Security Platform",
    version="0.1.0",
    description="Authorized asset posture assessment and auditable security hygiene.",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-API-Key"],
)


@app.middleware("http")
async def security_response_headers(request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Cache-Control", "no-store")
    return response


@app.get("/healthz")
def healthz():
    return {"status": "ok", "service": "sentinel-api", "timestamp": datetime.now(UTC).isoformat()}


@app.get("/api/v1/config", dependencies=[Depends(require_api_key)])
def read_config():
    return {
        "authorized_domains": settings.allowed_domain_list,
        "features": [
            "web-security-headers",
            "tls-certificate",
            "dns-email-posture",
            "risk-scoring",
            "audit-log",
        ],
        "network_policy": "HTTPS-only, allowlisted DNS hostnames, public DNS resolution, no redirects",
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
    return OverviewResponse(
        assessment_count=assessment_count,
        findings_count=findings_count,
        high_risk_count=high_risk_count,
        authorized_domains=settings.allowed_domain_list,
    )


@app.get(
    "/api/v1/assessments",
    response_model=list[AssessmentResponse],
    dependencies=[Depends(require_api_key)],
)
def list_assessments(limit: int = Query(default=25, ge=1, le=100), db: Session = Depends(get_db)):
    return db.scalars(select(Assessment).order_by(desc(Assessment.created_at)).limit(limit)).all()


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
            AuditEvent(
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

    item = Assessment(
        target=result["target"],
        status=result["status"],
        score=result["score"],
        risk_level=result["risk_level"],
        findings=result["findings"],
        evidence=result["evidence"],
    )
    db.add(item)
    db.add(
        AuditEvent(
            event_type="assessment.completed",
            subject=result["target"],
            result="success",
            details=f"score={result['score']}; findings={len(result['findings'])}",
        )
    )
    db.commit()
    db.refresh(item)
    return item


@app.get("/api/v1/audit", dependencies=[Depends(require_api_key)])
def list_audit_events(limit: int = Query(default=50, ge=1, le=200), db: Session = Depends(get_db)):
    events = db.scalars(select(AuditEvent).order_by(desc(AuditEvent.created_at)).limit(limit)).all()
    return [
        {
            "id": event.id,
            "event_type": event.event_type,
            "subject": event.subject,
            "result": event.result,
            "details": event.details,
            "created_at": event.created_at,
        }
        for event in events
    ]