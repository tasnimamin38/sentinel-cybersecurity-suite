from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from app.config import get_settings
from app.tenant_constants import LEGACY_TENANT_ID


class Base(DeclarativeBase):
    pass


def build_engine():
    url = get_settings().database_url
    kwargs = {"pool_pre_ping": True}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
    else:
        kwargs.update(
            pool_size=5,
            max_overflow=10,
            pool_timeout=30,
            pool_recycle=1800,
        )
    return create_engine(url, **kwargs)


engine = build_engine()
SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
    info={
        "tenant_id": LEGACY_TENANT_ID,
        "tenant_isolation_required": True,
    },
)


def get_db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
