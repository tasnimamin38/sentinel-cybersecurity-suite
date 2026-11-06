"""Add hash-only, revocable managed API credentials.

Revision ID: 0004_api_credentials
Revises: 0003_assessment_jobs
"""

import sqlalchemy as sa
from sqlalchemy import inspect

from alembic import op

revision = "0004_api_credentials"
down_revision = "0003_assessment_jobs"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = inspect(bind)
    tables = set(inspector.get_table_names())
    if "api_credentials" not in tables:
        op.create_table(
            "api_credentials",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("label", sa.String(length=80), nullable=False),
            sa.Column("role", sa.String(length=24), nullable=False),
            sa.Column("key_hash", sa.String(length=64), nullable=False),
            sa.Column("key_prefix", sa.String(length=16), nullable=False),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_by", sa.String(length=64), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("key_hash", name="uq_api_credentials_key_hash"),
        )

    inspector = inspect(bind)
    indexes = {item["name"] for item in inspector.get_indexes("api_credentials")}
    if "ix_api_credentials_role" not in indexes:
        op.create_index("ix_api_credentials_role", "api_credentials", ["role"], unique=False)


def downgrade():
    bind = op.get_bind()
    inspector = inspect(bind)
    if "api_credentials" not in inspector.get_table_names():
        return
    indexes = {item["name"] for item in inspector.get_indexes("api_credentials")}
    if "ix_api_credentials_role" in indexes:
        op.drop_index("ix_api_credentials_role", table_name="api_credentials")
    op.drop_table("api_credentials")
