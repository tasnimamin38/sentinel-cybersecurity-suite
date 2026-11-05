"""Add monotonic audit sequence numbers and stable chain ordering.

Revision ID: 0002_audit_sequence_numbers
Revises: 0001_enterprise_foundation
"""

import sqlalchemy as sa
from sqlalchemy import inspect

from alembic import op

revision = "0002_audit_sequence_numbers"
down_revision = "0001_enterprise_foundation"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = inspect(bind)
    columns = {column["name"] for column in inspector.get_columns("audit_events")}
    if "sequence_no" not in columns:
        op.add_column(
            "audit_events",
            sa.Column("sequence_no", sa.Integer(), nullable=True),
        )

    # Preserve all old audit rows. Assign deterministic sequence positions to
    # legacy records that pre-date sequence numbering; do not fabricate hashes.
    rows = bind.execute(
        sa.text("SELECT id, sequence_no FROM audit_events ORDER BY created_at ASC, id ASC")
    ).fetchall()
    max_existing = max((row.sequence_no or 0 for row in rows), default=0)
    next_sequence = max_existing + 1
    for row in rows:
        if row.sequence_no is None:
            bind.execute(
                sa.text("UPDATE audit_events SET sequence_no = :sequence WHERE id = :event_id"),
                {"sequence": next_sequence, "event_id": row.id},
            )
            next_sequence += 1

    inspector = inspect(bind)
    indexes = {index["name"] for index in inspector.get_indexes("audit_events")}
    if "ix_audit_events_sequence_no" not in indexes:
        op.create_index(
            "ix_audit_events_sequence_no",
            "audit_events",
            ["sequence_no"],
            unique=True,
        )


def downgrade():
    bind = op.get_bind()
    inspector = inspect(bind)
    indexes = {index["name"] for index in inspector.get_indexes("audit_events")}
    if "ix_audit_events_sequence_no" in indexes:
        op.drop_index("ix_audit_events_sequence_no", table_name="audit_events")
    columns = {column["name"] for column in inspect(bind).get_columns("audit_events")}
    if "sequence_no" in columns:
        op.drop_column("audit_events", "sequence_no")
