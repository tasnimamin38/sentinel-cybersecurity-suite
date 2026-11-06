from datetime import UTC, datetime, timedelta

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.models import ApiCredentialUsage


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def consume_credential_quota(
    db: Session,
    credential_id: str,
    rate_limit_per_minute: int,
    daily_request_limit: int,
    now: datetime | None = None,
) -> int | None:
    """Consume one authorized request from a per-credential UTC fixed-window quota.

    Returns Retry-After seconds when a quota is exhausted. PostgreSQL advisory
    transaction locks serialize first-use and counter updates for both database
    and environment-managed service identities.
    """
    current = _utc(now or datetime.now(UTC))
    minute_bucket = current.replace(second=0, microsecond=0)
    day_bucket = current.replace(hour=0, minute=0, second=0, microsecond=0)

    bind = db.get_bind()
    if bind.dialect.name == "postgresql":
        db.execute(
            text("SELECT pg_advisory_xact_lock(hashtext(:credential_id))"),
            {"credential_id": credential_id},
        )

    usage = db.scalar(
        select(ApiCredentialUsage)
        .where(ApiCredentialUsage.credential_id == credential_id)
        .with_for_update()
    )
    if usage is None:
        usage = ApiCredentialUsage(
            credential_id=credential_id,
            minute_window_start=minute_bucket,
            minute_requests=0,
            day_window_start=day_bucket,
            day_requests=0,
            updated_at=current,
        )
        db.add(usage)
        db.flush()
    else:
        if _utc(usage.minute_window_start) != minute_bucket:
            usage.minute_window_start = minute_bucket
            usage.minute_requests = 0
        if _utc(usage.day_window_start) != day_bucket:
            usage.day_window_start = day_bucket
            usage.day_requests = 0

    if usage.minute_requests >= rate_limit_per_minute:
        remaining = (minute_bucket + timedelta(minutes=1) - current).total_seconds()
        return max(1, int(remaining + 0.999))

    if usage.day_requests >= daily_request_limit:
        next_day = day_bucket + timedelta(days=1)
        remaining = (next_day - current).total_seconds()
        return max(1, int(remaining + 0.999))

    usage.minute_requests += 1
    usage.day_requests += 1
    usage.updated_at = current
    return None
