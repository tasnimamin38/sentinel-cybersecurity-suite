from datetime import UTC, datetime, timedelta
import importlib
import importlib.util

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models import Asset


def queue_service():
    spec = importlib.util.find_spec("app.services.jobs")
    assert spec is not None, "the durable assessment job service has not been implemented"
    return importlib.import_module("app.services.jobs")


def make_asset(db, hostname="app.example.com", status="active", expires_in_days=30):
    asset = Asset(
        hostname=hostname,
        name="Test asset",
        owner="Platform Security",
        environment="production",
        criticality=1.0,
        authorization_expires_at=datetime.now(UTC) + timedelta(days=expires_in_days),
        authorization_reference="CHANGE-QUEUE-001",
        status=status,
        tags=["test"],
    )
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return asset


def test_assessment_job_table_is_registered_in_sqlalchemy_metadata():
    assert "assessment_jobs" in Base.metadata.tables


def test_enqueue_persists_target_snapshot_and_scheduled_availability(tmp_path):
    service = queue_service()
    engine = create_engine(f"sqlite:///{tmp_path / 'enqueue.sqlite'}")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    with Session() as db:
        asset = make_asset(db)
        scheduled = datetime.now(UTC) + timedelta(hours=2)

        job = service.enqueue_assessment_job(db, asset, scheduled_for=scheduled)

        assert job.status == "queued"
        assert job.asset_id == asset.id
        assert job.target == "app.example.com"
        assert job.attempts == 0
        assert job.available_at == scheduled
        assert db.scalar(select(func.count()).select_from(service.AssessmentJob)) == 1
    engine.dispose()


def test_idempotency_digest_returns_original_job_without_duplicate(tmp_path):
    service = queue_service()
    engine = create_engine(f"sqlite:///{tmp_path / 'idempotency.sqlite'}")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    with Session() as db:
        asset = make_asset(db)
        first = service.enqueue_assessment_job(
            db, asset, idempotency_digest="a" * 64
        )
        second = service.enqueue_assessment_job(
            db, asset, idempotency_digest="a" * 64
        )

        assert first.id == second.id
        assert db.scalar(select(func.count()).select_from(service.AssessmentJob)) == 1
    engine.dispose()


def test_claim_skips_future_jobs_and_assigns_one_due_job(tmp_path):
    service = queue_service()
    engine = create_engine(f"sqlite:///{tmp_path / 'claim.sqlite'}")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    now = datetime(2026, 11, 6, 0, 0, tzinfo=UTC)
    with Session() as db:
        asset = make_asset(db)
        future = service.enqueue_assessment_job(
            db, asset, scheduled_for=now + timedelta(minutes=1)
        )
        assert service.claim_next_job(db, "worker-a", now=now) is None

        future.available_at = now - timedelta(seconds=1)
        db.commit()
        claimed = service.claim_next_job(db, "worker-a", now=now)

        assert claimed.id == future.id
        assert claimed.status == "running"
        assert claimed.worker_id == "worker-a"
        assert claimed.attempts == 1
        assert claimed.lease_expires_at == now + timedelta(seconds=60)
    engine.dispose()


def test_expired_lease_can_be_reclaimed_by_only_one_next_worker(tmp_path):
    service = queue_service()
    engine = create_engine(f"sqlite:///{tmp_path / 'lease.sqlite'}")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    now = datetime(2026, 11, 6, 0, 0, tzinfo=UTC)
    with Session() as db:
        asset = make_asset(db)
        job = service.enqueue_assessment_job(db, asset, scheduled_for=now)
        first = service.claim_next_job(db, "worker-a", now=now)
        assert first.id == job.id

        reclaimed = service.claim_next_job(
            db, "worker-b", now=now + timedelta(seconds=61)
        )

        assert reclaimed.id == job.id
        assert reclaimed.status == "running"
        assert reclaimed.worker_id == "worker-b"
        assert reclaimed.attempts == 2
        assert service.heartbeat_job(
            db, job.id, "worker-a", now=now + timedelta(seconds=62)
        ) is False
    engine.dispose()


def test_failed_attempts_use_bounded_backoff_then_dead_letter(tmp_path):
    service = queue_service()
    engine = create_engine(f"sqlite:///{tmp_path / 'retry.sqlite'}")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    now = datetime(2026, 11, 6, 0, 0, tzinfo=UTC)
    with Session() as db:
        asset = make_asset(db)
        service.enqueue_assessment_job(db, asset)
        first = service.claim_next_job(db, "worker-a", now=now)
        queued = service.fail_job_attempt(
            db, first.id, "worker-a", "temporary network failure", now=now
        )
        assert queued.status == "queued"
        assert queued.available_at == now + timedelta(seconds=5)
        assert queued.last_error == "temporary network failure"

        second = service.claim_next_job(
            db, "worker-b", now=now + timedelta(seconds=5)
        )
        queued_again = service.fail_job_attempt(
            db,
            second.id,
            "worker-b",
            "second transient failure",
            now=now + timedelta(seconds=5),
        )
        assert queued_again.status == "queued"
        assert queued_again.available_at == now + timedelta(seconds=35)

        third = service.claim_next_job(
            db, "worker-c", now=now + timedelta(seconds=35)
        )
        dead = service.fail_job_attempt(
            db,
            third.id,
            "worker-c",
            "final bounded failure",
            now=now + timedelta(seconds=35),
        )
        assert dead.status == "dead_letter"
        assert dead.completed_at == now + timedelta(seconds=35)
        assert dead.worker_id is None
    engine.dispose()


def test_cancel_transitions_queued_and_running_jobs_safely(tmp_path):
    service = queue_service()
    engine = create_engine(f"sqlite:///{tmp_path / 'cancel.sqlite'}")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    now = datetime(2026, 11, 6, 0, 0, tzinfo=UTC)
    with Session() as db:
        asset = make_asset(db, hostname="queued.example.com")
        queued = service.enqueue_assessment_job(db, asset)
        cancelled = service.request_job_cancel(db, queued, now=now)
        assert cancelled.status == "cancelled"
        assert cancelled.completed_at == now

        running_asset = make_asset(db, hostname="running.example.com")
        running_job = service.enqueue_assessment_job(db, running_asset, scheduled_for=now)
        claimed = service.claim_next_job(db, "worker-a", now=now)
        assert claimed.id == running_job.id
        cancel_requested = service.request_job_cancel(db, claimed, now=now)
        assert cancel_requested.status == "cancel_requested"
        assert cancel_requested.cancel_requested_at == now
    engine.dispose()


def test_complete_job_requires_current_lease_owner(tmp_path):
    service = queue_service()
    engine = create_engine(f"sqlite:///{tmp_path / 'complete.sqlite'}")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    now = datetime(2026, 11, 6, 0, 0, tzinfo=UTC)
    with Session() as db:
        asset = make_asset(db)
        job = service.enqueue_assessment_job(db, asset, scheduled_for=now)
        claimed = service.claim_next_job(db, "worker-a", now=now)

        assert service.complete_job(db, claimed.id, "worker-b", "assessment-1") is False
        assert service.complete_job(db, claimed.id, "worker-a", "assessment-1", now=now) is True
        db.refresh(job)
        assert job.status == "succeeded"
        assert job.assessment_id == "assessment-1"
        assert job.completed_at == now
    engine.dispose()


def test_expired_lease_owner_cannot_heartbeat_or_complete(tmp_path):
    service = queue_service()
    engine = create_engine(f"sqlite:///{tmp_path / 'expired-owner.sqlite'}")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    now = datetime(2026, 11, 6, 0, 0, tzinfo=UTC)
    with Session() as db:
        asset = make_asset(db)
        job = service.enqueue_assessment_job(db, asset, scheduled_for=now)
        claimed = service.claim_next_job(db, "worker-a", now=now)

        expired = now + timedelta(seconds=61)
        assert service.heartbeat_job(db, claimed.id, "worker-a", now=expired) is False
        assert service.complete_job(
            db, claimed.id, "worker-a", "assessment-1", now=expired
        ) is False
        db.refresh(job)
        assert job.status == "running"
    engine.dispose()


def test_worker_can_finalize_cancellation_and_permanent_failures(tmp_path):
    service = queue_service()
    engine = create_engine(f"sqlite:///{tmp_path / 'terminal-jobs.sqlite'}")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    now = datetime(2026, 11, 6, 0, 0, tzinfo=UTC)
    with Session() as db:
        cancelled_asset = make_asset(db, "cooperative-cancel.example.com")
        cancelled_job = service.enqueue_assessment_job(db, cancelled_asset, scheduled_for=now)
        claimed = service.claim_next_job(db, "worker-a", now=now)
        service.request_job_cancel(db, claimed, now=now)
        assert service.finish_cancelled_job(
            db, cancelled_job.id, "worker-a", now=now + timedelta(seconds=1)
        ) is True
        db.refresh(cancelled_job)
        assert cancelled_job.status == "cancelled"
        assert cancelled_job.worker_id is None

        failed_asset = make_asset(db, "permanent-failure.example.com")
        failed_job = service.enqueue_assessment_job(db, failed_asset, scheduled_for=now)
        service.claim_next_job(db, "worker-b", now=now)
        failed = service.fail_job_permanently(
            db, failed_job.id, "worker-b", "authorization expired", now=now
        )
        assert failed.status == "failed"
        assert failed.last_error == "authorization expired"

        retried = service.retry_job(db, failed, now=now + timedelta(minutes=1))
        assert retried.status == "queued"
        assert retried.manual_retries == 1
        assert retried.attempts == 0
    engine.dispose()
