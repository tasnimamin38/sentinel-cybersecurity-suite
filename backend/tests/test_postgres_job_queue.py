import asyncio
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models import AssessmentJob, Asset
from app.services.jobs import claim_next_job, enqueue_assessment_job


def test_postgres_workers_never_claim_the_same_job():
    database_url = os.getenv("SENTINEL_TEST_POSTGRES_URL")
    if not database_url:
        pytest.skip("SENTINEL_TEST_POSTGRES_URL is not configured.")

    schema = f"sentinel_queue_test_{uuid4().hex}"
    admin_engine = create_engine(database_url, pool_pre_ping=True)
    queue_engine = None
    try:
        with admin_engine.begin() as connection:
            connection.execute(text(f'CREATE SCHEMA "{schema}"'))

        queue_engine = create_engine(
            database_url,
            connect_args={"options": f"-csearch_path={schema}"},
            pool_size=4,
            max_overflow=0,
            pool_pre_ping=True,
        )
        Base.metadata.create_all(queue_engine)
        Session = sessionmaker(
            bind=queue_engine,
            autoflush=False,
            expire_on_commit=False,
        )

        with Session() as db:
            asset = Asset(
                hostname="concurrency.example.com",
                name="Queue concurrency test",
                owner="Platform Security",
                environment="test",
                criticality=1.0,
                authorization_expires_at=datetime.now(UTC) + timedelta(days=7),
                authorization_reference="CHANGE-QUEUE-RACE",
                status="active",
                tags=["ci"],
            )
            db.add(asset)
            db.flush()
            job = enqueue_assessment_job(
                db,
                asset,
                scheduled_for=datetime.now(UTC) - timedelta(seconds=1),
            )
            job_id = job.id
            db.commit()

        barrier = threading.Barrier(2)

        def claim(worker_id: str) -> str | None:
            with Session() as db:
                barrier.wait(timeout=5)
                item = claim_next_job(db, worker_id, lease_seconds=60)
                claimed_id = item.id if item else None
                if item is not None:
                    # Keep the row lock open while the other worker executes
                    # its SELECT ... FOR UPDATE SKIP LOCKED query.
                    time.sleep(0.25)
                db.commit()
                return claimed_id

        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [
                executor.submit(claim, "worker-race-a"),
                executor.submit(claim, "worker-race-b"),
            ]
            claimed_ids = [future.result(timeout=10) for future in futures]

        successful_claims = [item for item in claimed_ids if item is not None]
        assert successful_claims == [job_id]
        assert len(successful_claims) == len(set(successful_claims))

        with Session() as db:
            persisted = db.scalar(select(AssessmentJob).where(AssessmentJob.id == job_id))
            assert persisted.status == "running"
            assert persisted.attempts == 1
            assert persisted.worker_id in {"worker-race-a", "worker-race-b"}
    finally:
        if queue_engine is not None:
            Base.metadata.drop_all(queue_engine)
            queue_engine.dispose()
        with admin_engine.begin() as connection:
            connection.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
        admin_engine.dispose()



def test_postgres_worker_tick_allows_only_one_concurrent_executor(monkeypatch):
    database_url = os.getenv("SENTINEL_TEST_POSTGRES_URL")
    if not database_url:
        pytest.skip("SENTINEL_TEST_POSTGRES_URL is not configured.")

    from app import worker

    schema = f"sentinel_tick_lock_test_{uuid4().hex}"
    admin_engine = create_engine(database_url, pool_pre_ping=True)
    tick_engine = None
    try:
        with admin_engine.begin() as connection:
            connection.execute(text(f'CREATE SCHEMA "{schema}"'))

        tick_engine = create_engine(
            database_url,
            connect_args={"options": f"-csearch_path={schema}"},
            pool_size=4,
            max_overflow=0,
            pool_pre_ping=True,
        )
        tick_sessions = sessionmaker(bind=tick_engine, expire_on_commit=False)
        monkeypatch.setattr(worker, "SessionLocal", tick_sessions)

        claimed: list[str] = []

        def claim_one(worker_id: str) -> str:
            claimed.append(worker_id)
            return f"job-{worker_id}"

        async def process_one(job_id: str, worker_id: str) -> None:
            await asyncio.sleep(0.15)

        monkeypatch.setattr(worker, "_claim_job", claim_one)
        monkeypatch.setattr(worker, "process_job", process_one)

        async def run_ticks():
            return await asyncio.gather(
                worker.process_one_job(),
                worker.process_one_job(),
            )

        results = asyncio.run(run_ticks())

        assert len(claimed) == 1
        assert sum(result is not None for result in results) == 1
    finally:
        if tick_engine is not None:
            tick_engine.dispose()
        with admin_engine.begin() as connection:
            connection.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
        admin_engine.dispose()
