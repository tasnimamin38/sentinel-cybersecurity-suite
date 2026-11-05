"""Create the durable PostgreSQL assessment job queue.

Revision ID: 0003_assessment_jobs
Revises: 0002_audit_sequence_numbers
"""

import sqlalchemy as sa
from sqlalchemy import inspect

from alembic import op

revision = "0003_assessment_jobs"
down_revision = "0002_audit_sequence_numbers"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = inspect(bind)
    if "assessment_jobs" not in inspector.get_table_names():
        op.create_table(
            "assessment_jobs",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("asset_id", sa.String(length=36), nullable=True),
            sa.Column("target", sa.String(length=253), nullable=False),
            sa.Column("status", sa.String(length=24), nullable=False),
            sa.Column("available_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("attempts", sa.Integer(), nullable=False),
            sa.Column("max_attempts", sa.Integer(), nullable=False),
            sa.Column("manual_retries", sa.Integer(), nullable=False),
            sa.Column("worker_id", sa.String(length=64), nullable=True),
            sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("cancel_requested_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("assessment_id", sa.String(length=36), nullable=True),
            sa.Column("idempotency_key_hash", sa.String(length=64), nullable=True),
            sa.Column("last_error", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="SET NULL"),
            sa.ForeignKeyConstraint(["assessment_id"], ["assessments.id"], ondelete="SET NULL"),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint(
                "idempotency_key_hash",
                name="uq_assessment_jobs_idempotency_key_hash",
            ),
        )

    inspector = inspect(bind)
    indexes = {item["name"] for item in inspector.get_indexes("assessment_jobs")}
    expected_indexes = {
        "ix_assessment_jobs_asset_id": ["asset_id"],
        "ix_assessment_jobs_status": ["status"],
        "ix_assessment_jobs_status_available": ["status", "available_at"],
        "ix_assessment_jobs_available_at": ["available_at"],
        "ix_assessment_jobs_worker_id": ["worker_id"],
        "ix_assessment_jobs_assessment_id": ["assessment_id"],
        "ix_assessment_jobs_lease_expires_at": ["lease_expires_at"],
    }
    for name, columns in expected_indexes.items():
        if name not in indexes:
            op.create_index(name, "assessment_jobs", columns, unique=False)


def downgrade():
    bind = op.get_bind()
    if "assessment_jobs" not in inspect(bind).get_table_names():
        return
    indexes = {item["name"] for item in inspect(bind).get_indexes("assessment_jobs")}
    for name in (
        "ix_assessment_jobs_lease_expires_at",
        "ix_assessment_jobs_assessment_id",
        "ix_assessment_jobs_worker_id",
        "ix_assessment_jobs_available_at",
        "ix_assessment_jobs_status_available",
        "ix_assessment_jobs_status",
        "ix_assessment_jobs_asset_id",
    ):
        if name in indexes:
            op.drop_index(name, table_name="assessment_jobs")
    op.drop_table("assessment_jobs")
