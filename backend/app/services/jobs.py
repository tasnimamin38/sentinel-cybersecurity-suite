from datetime import UTC, datetime, timedelta
import re

from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from app.models import AssessmentJob, Asset


DEFAULT_MAX_ATTEMPTS = 3
DEFAULT_LEASE_SECONDS = 60
MAX_MANUAL_RETRIES = 3
_RETRY_BACKOFF_SECONDS = {1: 5, 2: 30}
_ERROR_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]+")


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _now(value: datetime | None = None) -> datetime:
    return _as_utc(value or datetime.now(UTC))


def _safe_error_summary(value: str) -> str:
    clean = _ERROR_CONTROL_CHARS.sub(" ", value).strip()
    return clean[:500] or "Assessment attempt failed."


def enqueue_assessment_job(
    db: Session,
    asset: Asset,
    scheduled_for: datetime | None = None,
    idempotency_digest: str | None = None,
) -> AssessmentJob:
    if idempotency_digest is not None and (
        len(idempotency_digest) != 64
        or any(character not in "0123456789abcdef" for character in idempotency_digest)
    ):
        raise ValueError("The idempotency digest must be a lowercase SHA-256 hex value.")

    if idempotency_digest:
        existing = db.scalar(
            select(AssessmentJob).where(
                AssessmentJob.idempotency_key_hash == idempotency_digest
            )
        )
        if existing is not None:
            return existing

    available_at = _now(scheduled_for)
    item = AssessmentJob(
        asset_id=asset.id,
        target=asset.hostname,
        status="queued",
        available_at=available_at,
        attempts=0,
        max_attempts=DEFAULT_MAX_ATTEMPTS,
        manual_retries=0,
        idempotency_key_hash=idempotency_digest,
    )
    db.add(item)
    db.flush()
    return item


def claim_next_job(
    db: Session,
    worker_id: str,
    now: datetime | None = None,
    lease_seconds: int = DEFAULT_LEASE_SECONDS,
) -> AssessmentJob | None:
    worker = worker_id.strip()
    if not worker or len(worker) > 64:
        raise ValueError("Worker id must contain 1 to 64 characters.")
    if lease_seconds < 5 or lease_seconds > 300:
        raise ValueError("Lease duration must be between 5 and 300 seconds.")

    current = _now(now)
    eligible = or_(
        and_(AssessmentJob.status == "queued", AssessmentJob.available_at <= current),
        and_(
            AssessmentJob.status.in_(("running", "cancel_requested")),
            AssessmentJob.lease_expires_at.is_not(None),
            AssessmentJob.lease_expires_at <= current,
        ),
    )
    job = db.scalar(
        select(AssessmentJob)
        .where(eligible)
        .order_by(AssessmentJob.available_at.asc(), AssessmentJob.created_at.asc())
        .with_for_update(skip_locked=True)
        .limit(1)
    )
    if job is None:
        return None

    if job.status == "cancel_requested":
        job.status = "cancelled"
        job.completed_at = current
        job.worker_id = None
        job.lease_expires_at = None
        job.heartbeat_at = None
        job.updated_at = current
        db.flush()
        return None

    if job.attempts >= job.max_attempts:
        job.status = "dead_letter"
        job.completed_at = current
        job.worker_id = None
        job.lease_expires_at = None
        job.heartbeat_at = None
        job.updated_at = current
        db.flush()
        return None

    job.status = "running"
    job.attempts += 1
    job.worker_id = worker
    job.lease_expires_at = current + timedelta(seconds=lease_seconds)
    job.heartbeat_at = current
    if job.started_at is None:
        job.started_at = current
    job.updated_at = current
    db.flush()
    return job


def heartbeat_job(
    db: Session,
    job_id: str,
    worker_id: str,
    now: datetime | None = None,
    lease_seconds: int = DEFAULT_LEASE_SECONDS,
) -> bool:
    current = _now(now)
    job = db.scalar(
        select(AssessmentJob)
        .where(AssessmentJob.id == job_id)
        .with_for_update()
    )
    if (
        job is None
        or job.worker_id != worker_id
        or job.status not in ("running", "cancel_requested")
        or job.lease_expires_at is None
        or _as_utc(job.lease_expires_at) <= current
    ):
        return False
    job.heartbeat_at = current
    job.lease_expires_at = current + timedelta(seconds=lease_seconds)
    job.updated_at = current
    db.flush()
    return True


def request_job_cancel(
    db: Session,
    job: AssessmentJob,
    now: datetime | None = None,
) -> AssessmentJob:
    current = _now(now)
    if job.status == "queued":
        job.status = "cancelled"
        job.completed_at = current
        job.updated_at = current
    elif job.status == "running":
        job.status = "cancel_requested"
        job.cancel_requested_at = current
        job.updated_at = current
    db.flush()
    return job


def complete_job(
    db: Session,
    job_id: str,
    worker_id: str,
    assessment_id: str,
    now: datetime | None = None,
) -> bool:
    current = _now(now)
    job = db.scalar(
        select(AssessmentJob)
        .where(AssessmentJob.id == job_id)
        .with_for_update()
    )
    if (
        job is None
        or job.worker_id != worker_id
        or job.lease_expires_at is None
        or _as_utc(job.lease_expires_at) <= current
    ):
        return False
    if job.status == "cancel_requested":
        job.status = "cancelled"
        job.completed_at = current
        job.worker_id = None
        job.lease_expires_at = None
        job.heartbeat_at = None
        job.updated_at = current
        db.flush()
        return False
    if job.status != "running":
        return False

    job.status = "succeeded"
    job.assessment_id = assessment_id
    job.completed_at = current
    job.worker_id = None
    job.lease_expires_at = None
    job.heartbeat_at = None
    job.updated_at = current
    job.last_error = None
    db.flush()
    return True


def fail_job_attempt(
    db: Session,
    job_id: str,
    worker_id: str,
    error_summary: str,
    now: datetime | None = None,
) -> AssessmentJob | None:
    current = _now(now)
    job = db.scalar(
        select(AssessmentJob)
        .where(AssessmentJob.id == job_id)
        .with_for_update()
    )
    if (
        job is None
        or job.worker_id != worker_id
        or job.lease_expires_at is None
        or _as_utc(job.lease_expires_at) <= current
    ):
        return None

    if job.status == "cancel_requested":
        job.status = "cancelled"
        job.completed_at = current
    elif job.status != "running":
        return None
    elif job.attempts >= job.max_attempts:
        job.status = "dead_letter"
        job.completed_at = current
        job.last_error = _safe_error_summary(error_summary)
    else:
        job.status = "queued"
        delay = _RETRY_BACKOFF_SECONDS.get(job.attempts, 30)
        job.available_at = current + timedelta(seconds=delay)
        job.last_error = _safe_error_summary(error_summary)

    job.worker_id = None
    job.lease_expires_at = None
    job.heartbeat_at = None
    job.updated_at = current
    db.flush()
    return job


def finish_cancelled_job(
    db: Session,
    job_id: str,
    worker_id: str,
    now: datetime | None = None,
) -> bool:
    current = _now(now)
    job = db.scalar(
        select(AssessmentJob).where(AssessmentJob.id == job_id).with_for_update()
    )
    if (
        job is None
        or job.worker_id != worker_id
        or job.status != "cancel_requested"
        or job.lease_expires_at is None
        or _as_utc(job.lease_expires_at) <= current
    ):
        return False
    job.status = "cancelled"
    job.completed_at = current
    job.worker_id = None
    job.lease_expires_at = None
    job.heartbeat_at = None
    job.updated_at = current
    db.flush()
    return True


def fail_job_permanently(
    db: Session,
    job_id: str,
    worker_id: str,
    error_summary: str,
    now: datetime | None = None,
) -> AssessmentJob | None:
    current = _now(now)
    job = db.scalar(
        select(AssessmentJob).where(AssessmentJob.id == job_id).with_for_update()
    )
    if (
        job is None
        or job.worker_id != worker_id
        or job.lease_expires_at is None
        or _as_utc(job.lease_expires_at) <= current
    ):
        return None
    if job.status == "cancel_requested":
        job.status = "cancelled"
    elif job.status == "running":
        job.status = "failed"
        job.last_error = _safe_error_summary(error_summary)
    else:
        return None
    job.completed_at = current
    job.worker_id = None
    job.lease_expires_at = None
    job.heartbeat_at = None
    job.updated_at = current
    db.flush()
    return job


def retry_job(
    db: Session,
    job: AssessmentJob,
    now: datetime | None = None,
) -> AssessmentJob:
    current = _now(now)
    if job.status not in ("failed", "dead_letter"):
        raise ValueError("Only failed or dead-letter jobs can be manually retried.")
    if job.manual_retries >= MAX_MANUAL_RETRIES:
        raise ValueError("The manual retry limit has been reached.")

    job.status = "queued"
    job.available_at = current
    job.attempts = 0
    job.manual_retries += 1
    job.worker_id = None
    job.lease_expires_at = None
    job.heartbeat_at = None
    job.cancel_requested_at = None
    job.started_at = None
    job.completed_at = None
    job.assessment_id = None
    job.last_error = None
    job.updated_at = current
    db.flush()
    return job
