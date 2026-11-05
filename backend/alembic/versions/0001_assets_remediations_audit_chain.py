"""Add asset registry, remediation workflow and audit hash-chain metadata.

Revision ID: 0001_enterprise_foundation
Revises:
"""

import sqlalchemy as sa
from sqlalchemy import inspect

from alembic import op
from app import models  # noqa: F401
from app.database import Base

revision = "0001_enterprise_foundation"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()

    # Creates missing baseline/new tables but never attempts to alter existing
    # tables. The conditional additive steps below upgrade databases created by
    # the 0.2 line without deleting assessment or audit history.
    Base.metadata.create_all(bind=bind, checkfirst=True)
    inspector = inspect(bind)

    assessment_columns = {column["name"] for column in inspector.get_columns("assessments")}
    if "asset_id" not in assessment_columns:
        with op.batch_alter_table("assessments") as batch:
            batch.add_column(sa.Column("asset_id", sa.String(length=36), nullable=True))
            batch.create_foreign_key(
                "fk_assessments_asset_id_assets",
                "assets",
                ["asset_id"],
                ["id"],
                ondelete="SET NULL",
            )

    inspector = inspect(bind)
    assessment_indexes = {index["name"] for index in inspector.get_indexes("assessments")}
    if "ix_assessments_asset_id" not in assessment_indexes:
        op.create_index("ix_assessments_asset_id", "assessments", ["asset_id"], unique=False)

    inspector = inspect(bind)
    audit_columns = {column["name"] for column in inspector.get_columns("audit_events")}
    if "previous_hash" not in audit_columns:
        op.add_column(
            "audit_events", sa.Column("previous_hash", sa.String(length=64), nullable=True)
        )
    if "event_hash" not in audit_columns:
        op.add_column("audit_events", sa.Column("event_hash", sa.String(length=64), nullable=True))

    inspector = inspect(bind)
    audit_indexes = {index["name"] for index in inspector.get_indexes("audit_events")}
    if "ix_audit_events_event_hash" not in audit_indexes:
        op.create_index("ix_audit_events_event_hash", "audit_events", ["event_hash"], unique=False)


def downgrade():
    bind = op.get_bind()
    inspector = inspect(bind)
    if "audit_events" in inspector.get_table_names():
        indexes = {index["name"] for index in inspector.get_indexes("audit_events")}
        if "ix_audit_events_event_hash" in indexes:
            op.drop_index("ix_audit_events_event_hash", table_name="audit_events")
        columns = {column["name"] for column in inspector.get_columns("audit_events")}
        if "event_hash" in columns:
            op.drop_column("audit_events", "event_hash")
        if "previous_hash" in columns:
            op.drop_column("audit_events", "previous_hash")

    inspector = inspect(bind)
    if "assessments" in inspector.get_table_names():
        indexes = {index["name"] for index in inspector.get_indexes("assessments")}
        if "ix_assessments_asset_id" in indexes:
            op.drop_index("ix_assessments_asset_id", table_name="assessments")
        columns = {column["name"] for column in inspector.get_columns("assessments")}
        if "asset_id" in columns:
            with op.batch_alter_table("assessments") as batch:
                batch.drop_column("asset_id")

    inspector = inspect(bind)
    if "remediation_tasks" in inspector.get_table_names():
        op.drop_table("remediation_tasks")
    inspector = inspect(bind)
    if "assets" in inspector.get_table_names():
        op.drop_table("assets")
