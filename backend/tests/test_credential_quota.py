from datetime import UTC, datetime, timedelta

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base
from app.models import ApiCredentialUsage
from app.services.credential_quota import consume_credential_quota


def test_credential_quota_uses_utc_minute_and_day_windows():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    start = datetime(2026, 11, 6, 12, 30, 30, tzinfo=UTC)

    try:
        with Session() as db:
            assert consume_credential_quota(db, "quota-window", 2, 3, now=start) is None
            db.commit()
        with Session() as db:
            assert (
                consume_credential_quota(db, "quota-window", 2, 3, now=start + timedelta(seconds=1))
                is None
            )
            db.commit()
        with Session() as db:
            retry_after = consume_credential_quota(
                db, "quota-window", 2, 3, now=start + timedelta(seconds=2)
            )
            assert retry_after is not None
            assert 1 <= retry_after <= 28
            db.rollback()

        # A new minute resets the minute counter without resetting the UTC day.
        next_minute = start + timedelta(seconds=35)
        with Session() as db:
            assert consume_credential_quota(db, "quota-window", 2, 3, now=next_minute) is None
            db.commit()
        with Session() as db:
            usage = db.get(ApiCredentialUsage, "quota-window")
            assert usage.minute_requests == 1
            assert usage.day_requests == 3
            db.commit()

        with Session() as db:
            daily_retry = consume_credential_quota(
                db, "quota-window", 2, 3, now=next_minute + timedelta(seconds=1)
            )
            assert daily_retry is not None
            assert daily_retry > 3600
            db.rollback()

        next_day = next_minute + timedelta(days=1)
        with Session() as db:
            assert consume_credential_quota(db, "quota-window", 2, 3, now=next_day) is None
            db.commit()
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()


def test_credential_quota_returns_longest_retry_after_when_both_windows_exhausted():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    start = datetime(2026, 11, 6, 12, 30, 30, tzinfo=UTC)

    try:
        with Session() as db:
            assert consume_credential_quota(
                db, "quota-both", 1, 1, now=start
            ) is None
            db.commit()

        with Session() as db:
            retry_after = consume_credential_quota(
                db, "quota-both", 1, 1, now=start + timedelta(seconds=2)
            )
            assert retry_after is not None
            assert retry_after > 3600
            db.rollback()
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()
