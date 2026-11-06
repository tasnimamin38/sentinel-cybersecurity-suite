import asyncio
import contextlib
import logging
import time
from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import SessionLocal
from app.models import AssessmentJob, Asset
from app.services.assessment_store import add_assessment_result
from app.services.audit import record_audit_event
from app.services.jobs import (
    claim_next_job,
    fail_job_attempt,
    fail_job_permanently,
    finish_cancelled_job,
    heartbeat_job,
)
from app.services.posture import assess_domain
from app.services.scope import ScopeViolation, authorize_domain

LOGGER = logging.getLogger("sentinel.worker")
POLL_SECONDS = 1.0
HEARTBEAT_SECONDS = 10.0
LEASE_SECONDS = 60


class PermanentJobError(Exception):
    """An assessment cannot run because authorization or registered scope is invalid."""


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def validate_job_asset(
    db: Session,
    job: AssessmentJob,
    allowed_domains: list[str],
    now: datetime | None = None,
    asset_override: Asset | None = None,
) -> Asset:
    if not job.asset_id:
        raise PermanentJobError("The registered asset is no longer available.")
    asset = asset_override or db.get(Asset, job.asset_id)
    if asset is None:
        raise PermanentJobError("The registered asset is no longer available.")
    if asset.status != "active":
        raise PermanentJobError("The registered asset is not active.")
    current = _utc(now or datetime.now(UTC))
    if _utc(asset.authorization_expires_at) <= current:
        raise PermanentJobError("The asset authorization has expired.")
    if asset.hostname != job.target:
        raise PermanentJobError("The job target no longer matches the registered asset.")
    try:
        authorize_domain(job.target, allowed_domains)
    except (ScopeViolation, ValueError) as exc:
        raise PermanentJobError(
            "The job target is no longer in the authorized domain scope."
        ) from exc
    return asset


def persist_job_result(
    db: Session,
    job_id: str,
    worker_id: str,
    asset: Asset,
    result: dict,
    allowed_domains: list[str],
    now: datetime | None = None,
    max_records: int = 250,
) -> bool:
    current = _utc(now or datetime.now(UTC))
    job = db.scalar(select(AssessmentJob).where(AssessmentJob.id == job_id).with_for_update())
    if (
        job is None
        or job.worker_id != worker_id
        or job.lease_expires_at is None
        or _utc(job.lease_expires_at) <= current
        or job.asset_id != asset.id
        or job.target != asset.hostname
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
        db.add(
            record_audit_event(
                db,
                event_type="assessment.job.cancelled",
                subject=job.target,
                details=f"job_id={job.id}; asset_id={job.asset_id}; attempts={job.attempts}",
            )
        )
        return False
    if job.status != "running":
        return False

    locked_asset = db.scalar(select(Asset).where(Asset.id == job.asset_id).with_for_update())
    validate_job_asset(
        db,
        job,
        allowed_domains,
        now=current,
        asset_override=locked_asset,
    )
    assessment = add_assessment_result(
        db,
        result,
        locked_asset,
        max_records=max_records,
    )
    job.status = "succeeded"
    job.assessment_id = assessment.id
    job.completed_at = current
    job.worker_id = None
    job.lease_expires_at = None
    job.heartbeat_at = None
    job.updated_at = current
    job.last_error = None
    db.flush()
    db.add(
        record_audit_event(
            db,
            event_type="assessment.job.succeeded",
            subject=job.target,
            details=f"job_id={job.id}; assessment_id={assessment.id}; attempts={job.attempts}",
        )
    )
    return True


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


def _claim_job(worker_id: str) -> str | None:
    with SessionLocal() as db:
        item = claim_next_job(db, worker_id, lease_seconds=LEASE_SECONDS)
        if item is None:
            db.commit()
            return None
        job_id = item.id
        _record_job_event(db, "assessment.job.claimed", item)
        db.commit()
        return job_id


def _finish_cancel(job_id: str, worker_id: str) -> None:
    with SessionLocal() as db:
        job = db.scalar(select(AssessmentJob).where(AssessmentJob.id == job_id))
        if job and finish_cancelled_job(db, job_id, worker_id):
            _record_job_event(db, "assessment.job.cancelled", job)
            db.commit()


def _fail_permanently(job_id: str, worker_id: str, summary: str) -> None:
    with SessionLocal() as db:
        item = fail_job_permanently(db, job_id, worker_id, summary)
        if item is not None:
            event_type = (
                "assessment.job.cancelled"
                if item.status == "cancelled"
                else "assessment.job.failed"
            )
            result = "denied" if item.status == "failed" else "success"
            _record_job_event(db, event_type, item, result=result)
            db.commit()


def _fail_retryably(job_id: str, worker_id: str, exception_type: str) -> None:
    # Store only a stable exception class and generic summary, never a raw trace,
    # URL, request header, secret or exception message.
    summary = f"{exception_type}: assessment execution failed"
    with SessionLocal() as db:
        item = fail_job_attempt(db, job_id, worker_id, summary)
        if item is not None:
            event_type = (
                "assessment.job.dead_lettered"
                if item.status == "dead_letter"
                else "assessment.job.retry_scheduled"
                if item.status == "queued"
                else "assessment.job.cancelled"
            )
            _record_job_event(db, event_type, item)
            db.commit()


async def _observe_worker_lease(
    job_id: str,
    worker_id: str,
    last_heartbeat: float,
) -> tuple[str, float]:
    with SessionLocal() as db:
        job = db.scalar(select(AssessmentJob).where(AssessmentJob.id == job_id))
        if job is None or job.worker_id != worker_id or job.lease_expires_at is None:
            return "lost", last_heartbeat
        now = datetime.now(UTC)
        if _utc(job.lease_expires_at) <= now:
            return "lost", last_heartbeat
        if job.status == "cancel_requested":
            if finish_cancelled_job(db, job_id, worker_id, now=now):
                _record_job_event(db, "assessment.job.cancelled", job)
                db.commit()
            return "cancelled", last_heartbeat
        if job.status != "running":
            return "lost", last_heartbeat
        monotonic_now = time.monotonic()
        if monotonic_now - last_heartbeat >= HEARTBEAT_SECONDS:
            if not heartbeat_job(db, job_id, worker_id, now=now, lease_seconds=LEASE_SECONDS):
                return "lost", last_heartbeat
            db.commit()
            return "running", monotonic_now
        return "running", last_heartbeat


async def _assess_with_lease(
    job_id: str,
    worker_id: str,
    target: str,
    context: dict,
    allowed_domains: list[str],
    timeout: float,
) -> dict | None:
    assessment_task = asyncio.create_task(
        assess_domain(
            target,
            allowed_domains,
            timeout=timeout,
            context=context,
        )
    )
    last_heartbeat = time.monotonic()
    try:
        while not assessment_task.done():
            await asyncio.wait({assessment_task}, timeout=1.0)
            if assessment_task.done():
                break
            state, last_heartbeat = await _observe_worker_lease(job_id, worker_id, last_heartbeat)
            if state in ("cancelled", "lost"):
                assessment_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await assessment_task
                return None
        return await assessment_task
    except asyncio.CancelledError:
        assessment_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await assessment_task
        raise


def _persist_success(job_id: str, worker_id: str, asset: Asset, result: dict) -> bool:
    settings = get_settings()
    with SessionLocal() as db:
        saved = persist_job_result(
            db,
            job_id,
            worker_id,
            asset,
            result,
            allowed_domains=settings.allowed_domain_list,
            max_records=settings.max_assessment_records,
        )
        # A false result may still be a cooperative cancellation transition.
        # Committing is safe: no Assessment is added on any false path.
        db.commit()
        return saved


async def process_job(job_id: str, worker_id: str) -> None:
    settings = get_settings()
    with SessionLocal() as db:
        job = db.get(AssessmentJob, job_id)
        if job is None or job.worker_id != worker_id or job.status != "running":
            return
        try:
            asset = validate_job_asset(db, job, settings.allowed_domain_list)
        except PermanentJobError as exc:
            db.rollback()
            _fail_permanently(job_id, worker_id, str(exc))
            return
        target = job.target
        context = {
            "asset_criticality": asset.criticality,
            "asset_id": asset.id,
            "asset_environment": asset.environment,
        }
        db.commit()

    try:
        result = await _assess_with_lease(
            job_id,
            worker_id,
            target,
            context,
            settings.allowed_domain_list,
            settings.request_timeout_seconds,
        )
        if result is None:
            return
        try:
            saved = _persist_success(job_id, worker_id, asset, result)
        except PermanentJobError as exc:
            _fail_permanently(job_id, worker_id, str(exc))
            return
        if not saved:
            LOGGER.warning(
                "Worker discarded result after lease loss or state change: job_id=%s", job_id
            )
    except asyncio.CancelledError:
        raise
    except (PermanentJobError, ScopeViolation, ValueError) as exc:
        _fail_permanently(job_id, worker_id, type(exc).__name__)
    except Exception as exc:
        _fail_retryably(job_id, worker_id, type(exc).__name__)
        LOGGER.warning("Assessment job attempt failed: job_id=%s; error_type=%s", job_id, type(exc).__name__)


async def run_worker() -> None:
    worker_id = uuid4().hex
    LOGGER.info("SENTINEL assessment worker started: worker_id=%s", worker_id)
    while True:
        job_id = _claim_job(worker_id)
        if job_id is None:
            await asyncio.sleep(POLL_SECONDS)
            continue
        await process_job(job_id, worker_id)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    asyncio.run(run_worker())


if __name__ == "__main__":
    main()
