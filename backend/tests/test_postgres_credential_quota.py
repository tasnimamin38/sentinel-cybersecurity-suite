import os
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models import ApiCredentialUsage
from app.services.credential_quota import consume_credential_quota


def test_postgres_concurrent_requests_cannot_exceed_a_service_quota():
    database_url = os.getenv("SENTINEL_TEST_POSTGRES_URL")
    if not database_url:
        pytest.skip("SENTINEL_TEST_POSTGRES_URL is not configured.")

    schema = f"sentinel_quota_test_{uuid4().hex}"
    admin_engine = create_engine(database_url, pool_pre_ping=True)
    quota_engine = None
    try:
        with admin_engine.begin() as connection:
            connection.exec_driver_sql(f'CREATE SCHEMA "{schema}"')

        quota_engine = create_engine(
            database_url,
            connect_args={"options": f"-csearch_path={schema}"},
            pool_size=12,
            max_overflow=0,
            pool_pre_ping=True,
        )
        Base.metadata.create_all(quota_engine)
        Session = sessionmaker(
            bind=quota_engine,
            autoflush=False,
            expire_on_commit=False,
        )
        barrier = threading.Barrier(12)
        credential_id = "quota-race-" + uuid4().hex
        quota_now = datetime.now(UTC)

        def consume() -> bool:
            with Session() as db:
                barrier.wait(timeout=10)
                retry_after = consume_credential_quota(
                    db,
                    credential_id,
                    rate_limit_per_minute=6,
                    daily_request_limit=20,
                    now=quota_now,
                )
                if retry_after is None:
                    db.commit()
                    return True
                db.rollback()
                return False

        with ThreadPoolExecutor(max_workers=12) as executor:
            results = list(executor.map(lambda _: consume(), range(12)))

        assert sum(results) == 6
        with Session() as db:
            usage = db.get(ApiCredentialUsage, credential_id)
            assert usage is not None
            assert usage.minute_requests == 6
            assert usage.day_requests == 6
    finally:
        if quota_engine is not None:
            Base.metadata.drop_all(quota_engine)
            quota_engine.dispose()
        with admin_engine.begin() as connection:
            connection.exec_driver_sql(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        admin_engine.dispose()
