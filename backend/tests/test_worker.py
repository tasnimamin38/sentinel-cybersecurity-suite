from datetime import UTC, datetime, timedelta
import importlib

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models import Assessment, Asset
from app.services.jobs import claim_next_job, enqueue_assessment_job


def make_asset(db, hostname="worker.example.com", status="active", expires_in_days=30):
    asset = Asset(
        hostname=hostname,
        name="Worker test asset",
        owner="Platform Security",
        environment="production",
        criticality=1.2,
        authorization_expires_at=datetime.now(UTC) + timedelta(days=expires_in_days),
        authorization_reference="CHANGE-WORKER-001",
        status=status,
        tags=["worker-test"],
    )
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return asset


def result_for(hostname):
    return {
        "target": hostname,
        "status": "completed",
        "score": 25,
        "risk_level": "low",
        "findings": [],
        "evidence": {"web": {}, "tls": {}, "dns": {}},
        "risk_explanation": {"model": "sentinel-exponential-v2", "drivers": []},
    }


def worker_module():
    return importlib.import_module("app.worker")


def test_worker_refuses_paused_asset_and_expired_authorization(tmp_path):
    worker = worker_module()
    engine = create_engine(f"sqlite:///{tmp_path / 'worker-authorization.sqlite'}")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    with Session() as db:
        paused = make_asset(db, "paused-worker.example.com", status="paused")
        paused_job = enqueue_assessment_job(db, paused)
        with pytest.raises(worker.PermanentJobError):
            worker.validate_job_asset(db, paused_job, ["example.com"])

        expired = make_asset(db, "expired-worker.example.com", expires_in_days=30)
        expired.authorization_expires_at = datetime.now(UTC) - timedelta(seconds=1)
        db.commit()
        expired_job = enqueue_assessment_job(db, expired)
        with pytest.raises(worker.PermanentJobError):
            worker.validate_job_asset(db, expired_job, ["example.com"])
    engine.dispose()


def test_worker_refuses_target_snapshot_or_allowlist_mismatch(tmp_path):
    worker = worker_module()
    engine = create_engine(f"sqlite:///{tmp_path / 'worker-snapshot.sqlite'}")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    with Session() as db:
        asset = make_asset(db)
        job = enqueue_assessment_job(db, asset)
        job.target = "different.example.com"
        db.commit()
        with pytest.raises(worker.PermanentJobError):
            worker.validate_job_asset(db, job, ["example.com"])

        job.target = asset.hostname
        db.commit()
        with pytest.raises(worker.PermanentJobError):
            worker.validate_job_asset(db, job, ["other.example.net"])
    engine.dispose()


def test_worker_persists_assessment_and_job_success_in_one_transaction(tmp_path):
    worker = worker_module()
    engine = create_engine(f"sqlite:///{tmp_path / 'worker-success.sqlite'}")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    now = datetime(2026, 11, 6, 0, 0, tzinfo=UTC)
    with Session() as db:
        asset = make_asset(db)
        job = enqueue_assessment_job(db, asset, scheduled_for=now)
        claimed = claim_next_job(db, "worker-a", now=now)
        assert claimed.id == job.id

        persisted = worker.persist_job_result(
            db,
            job_id=job.id,
            worker_id="worker-a",
            asset=asset,
            result=result_for(asset.hostname),
            allowed_domains=["example.com"],
            now=now,
        )
        assert persisted is True
        db.commit()

        db.refresh(job)
        assessment = db.get(Assessment, job.assessment_id)
        assert job.status == "succeeded"
        assert assessment.target == asset.hostname
        assert assessment.asset_id == asset.id
        assert db.scalar(select(func.count()).select_from(Assessment)) == 1
    engine.dispose()


def test_worker_discards_result_after_lease_is_lost(tmp_path):
    worker = worker_module()
    engine = create_engine(f"sqlite:///{tmp_path / 'worker-lease.sqlite'}")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    now = datetime(2026, 11, 6, 0, 0, tzinfo=UTC)
    with Session() as db:
        asset = make_asset(db)
        job = enqueue_assessment_job(db, asset, scheduled_for=now)
        claim_next_job(db, "worker-a", now=now)

        persisted = worker.persist_job_result(
            db,
            job_id=job.id,
            worker_id="worker-a",
            asset=asset,
            result=result_for(asset.hostname),
            allowed_domains=["example.com"],
            now=now + timedelta(seconds=61),
        )
        assert persisted is False
        assert db.scalar(select(func.count()).select_from(Assessment)) == 0
        db.refresh(job)
        assert job.status == "running"
    engine.dispose()


def test_worker_rechecks_authorization_before_persisting_result(tmp_path):
    worker = worker_module()
    engine = create_engine(f"sqlite:///{tmp_path / 'worker-expiry-on-completion.sqlite'}")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    now = datetime(2026, 11, 6, 0, 0, tzinfo=UTC)
    with Session() as db:
        asset = make_asset(db)
        job = enqueue_assessment_job(db, asset, scheduled_for=now)
        claim_next_job(db, "worker-a", now=now)
        asset.authorization_expires_at = now - timedelta(seconds=1)
        db.flush()

        with pytest.raises(worker.PermanentJobError):
            worker.persist_job_result(
                db,
                job_id=job.id,
                worker_id="worker-a",
                asset=asset,
                result=result_for(asset.hostname),
                allowed_domains=["example.com"],
                now=now,
            )
        assert db.scalar(select(func.count()).select_from(Assessment)) == 0
    engine.dispose()
