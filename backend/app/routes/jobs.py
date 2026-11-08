import hashlib
import re
from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Response, status
from sqlalchemy import desc, func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.auth import require_api_key
from app.config import get_settings
from app.database import get_db
from app.models import AssessmentJob, Asset
from app.schemas import AssessmentJobCreate, AssessmentJobResponse
from app.services.audit import record_audit_event
from app.services.jobs import enqueue_assessment_job, request_job_cancel, retry_job
from app.services.scope import ScopeViolation, authorize_domain

router = APIRouter(prefix="/api/v1")
settings = get_settings()
_IDEMPOTENCY_PATTERN = re.compile(r"^[\x21-\x7e]{8,128}$")


def _aware_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _ensure_asset_authorization(asset: Asset) -> None:
    if asset.status != "active":
        raise HTTPException(status_code=409, detail="Asset is not active.")
    if _aware_utc(asset.authorization_expires_at) <= datetime.now(UTC):
        raise HTTPException(
            status_code=403,
            detail="Asset authorization has expired. Renew its authorization record before queueing.",
        )
    try:
        authorize_domain(asset.hostname, settings.allowed_domain_list)
    except ScopeViolation as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def _get_job_for_update(db: Session, job_id: str) -> AssessmentJob:
    item = db.scalar(select(AssessmentJob).where(AssessmentJob.id == job_id).with_for_update())
    if item is None:
        raise HTTPException(status_code=404, detail="Assessment job not found.")
    return item


def _record_job_event(db: Session, event_type: str, job: AssessmentJob, result: str = "success"):
    db.add(
        record_audit_event(
            db,
            event_type=event_type,
            subject=job.target,
            result=result,
            details=f"job_id={job.id}; asset_id={job.asset_id or 'unavailable'}; attempts={job.attempts}",
        )
    )


@router.post(
    "/assessment-jobs",
    response_model=AssessmentJobResponse,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(require_api_key)],
)
def create_assessment_job(
    payload: AssessmentJobCreate,
    response: Response,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    db: Session = Depends(get_db),
):
    asset = db.get(Asset, payload.asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found.")
    _ensure_asset_authorization(asset)

    digest = None
    if idempotency_key is not None:
        if not _IDEMPOTENCY_PATTERN.fullmatch(idempotency_key):
            raise HTTPException(
                status_code=422,
                detail="Idempotency-Key must contain 8–128 visible ASCII characters.",
            )
        digest = hashlib.sha256(idempotency_key.encode("ascii")).hexdigest()

    try:
        # Serialize admission checks across API instances so concurrent requests
        # cannot all observe the same free queue slot and exceed the global cap.
        if db.get_bind().dialect.name == "postgresql":
            db.execute(
                text("SELECT pg_advisory_xact_lock(:lock_id)"),
                {"lock_id": 0x53454E54494E454C},
            )

        # Check idempotency only after acquiring the admission lock. A retry of an
        # existing request must remain successful even when the queue is full.
        if digest:
            existing = db.scalar(
                select(AssessmentJob).where(AssessmentJob.idempotency_key_hash == digest)
            )
            if existing is not None:
                if existing.asset_id != asset.id:
                    raise HTTPException(
                        status_code=409,
                        detail="Idempotency-Key was already used for a different asset.",
                    )
                response.status_code = status.HTTP_200_OK
                return existing

        pending_jobs = db.scalar(
            select(func.count())
            .select_from(AssessmentJob)
            .where(AssessmentJob.status.in_(("queued", "running", "cancel_requested")))
        ) or 0
        if pending_jobs >= settings.max_pending_assessment_jobs:
            raise HTTPException(
                status_code=429,
                detail="Assessment queue is at capacity. Retry later.",
                headers={"Retry-After": str(settings.rate_limit_window_seconds)},
            )

        item = enqueue_assessment_job(
            db,
            asset,
            scheduled_for=payload.scheduled_for,
            idempotency_digest=digest,
        )
        if item.asset_id != asset.id:
            raise HTTPException(
                status_code=409,
                detail="Idempotency-Key was already used for a different asset.",
            )
        _record_job_event(db, "assessment.job.queued", item)
        db.commit()
        db.refresh(item)
        return item
    except IntegrityError as exc:
        db.rollback()
        if digest:
            existing = db.scalar(
                select(AssessmentJob).where(AssessmentJob.idempotency_key_hash == digest)
            )
            if existing is not None:
                if existing.asset_id != asset.id:
                    raise HTTPException(
                        status_code=409,
                        detail="Idempotency-Key was already used for a different asset.",
                    ) from exc
                response.status_code = status.HTTP_200_OK
                return existing
        raise HTTPException(
            status_code=409, detail="Assessment job could not be enqueued."
        ) from exc


@router.get(
    "/assessment-jobs",
    response_model=list[AssessmentJobResponse],
    dependencies=[Depends(require_api_key)],
)
def list_assessment_jobs(
    state: Literal[
        "queued", "running", "cancel_requested", "succeeded", "failed", "cancelled", "dead_letter"
    ]
    | None = Query(default=None, alias="status"),
    limit: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
):
    query = select(AssessmentJob).order_by(desc(AssessmentJob.created_at)).limit(limit)
    if state:
        query = query.where(AssessmentJob.status == state)
    return db.scalars(query).all()


@router.get(
    "/assessment-jobs/{job_id}",
    response_model=AssessmentJobResponse,
    dependencies=[Depends(require_api_key)],
)
def get_assessment_job(job_id: str, db: Session = Depends(get_db)):
    item = db.get(AssessmentJob, job_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Assessment job not found.")
    return item


@router.post(
    "/assessment-jobs/{job_id}/cancel",
    response_model=AssessmentJobResponse,
    dependencies=[Depends(require_api_key)],
)
def cancel_assessment_job(job_id: str, db: Session = Depends(get_db)):
    item = _get_job_for_update(db, job_id)
    if item.status in ("succeeded", "failed", "dead_letter"):
        raise HTTPException(
            status_code=409, detail="A terminal assessment job cannot be cancelled."
        )
    previous = item.status
    request_job_cancel(db, item)
    if item.status != previous:
        event_type = (
            "assessment.job.cancelled"
            if item.status == "cancelled"
            else "assessment.job.cancel_requested"
        )
        _record_job_event(db, event_type, item)
    db.commit()
    db.refresh(item)
    return item


@router.post(
    "/assessment-jobs/{job_id}/retry",
    response_model=AssessmentJobResponse,
    dependencies=[Depends(require_api_key)],
)
def retry_assessment_job(job_id: str, db: Session = Depends(get_db)):
    item = _get_job_for_update(db, job_id)
    if item.asset_id is None:
        raise HTTPException(status_code=409, detail="The original asset is no longer available.")
    asset = db.get(Asset, item.asset_id)
    if asset is None:
        raise HTTPException(status_code=409, detail="The original asset is no longer available.")
    _ensure_asset_authorization(asset)
    try:
        retry_job(db, item)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    _record_job_event(db, "assessment.job.retry_scheduled", item)
    db.commit()
    db.refresh(item)
    return item
