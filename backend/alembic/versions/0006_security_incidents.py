"""Add auditable security incident triage records.

Revision ID: 0006_security_incidents
Revises: 0005_credential_controls
"""

import sqlalchemy as sa
from sqlalchemy import inspect

from alembic import op

revision = "0006_security_incidents"
down_revision = "0005_credential_controls"
branch_labels = None
depends_on = None

_TABLE = "security_incidents"
_REQUIRED_COLUMNS = {
    "id",
    "assessment_id",
    "asset_id",
    "finding_code",
    "title",
    "severity",
    "status",
    "assignee",
    "due_at",
    "notes",
    "acknowledged_at",
    "closed_at",
    "created_at",
    "updated_at",
}
_INDEXES = (
    ("ix_security_incidents_assessment_id", ["assessment_id"]),
    ("ix_security_incidents_asset_id", ["asset_id"]),
    ("ix_security_incidents_severity", ["severity"]),
    ("ix_security_incidents_status", ["status"]),
    ("ix_security_incidents_status_severity", ["status", "severity"]),
)


def upgrade():
    bind = op.get_bind()
    inspector = inspect(bind)
    tables = set(inspector.get_table_names())

    # The 0001 baseline uses Base.metadata.create_all(checkfirst=True). On a
    # legacy upgrade that metadata already contains the current model, so this
    # table may exist before Alembic reaches this revision. Preserve it.
    if _TABLE not in tables:
        op.create_table(
            _TABLE,
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("assessment_id", sa.String(length=36), nullable=False),
            sa.Column("asset_id", sa.String(length=36), nullable=True),
            sa.Column("finding_code", sa.String(length=100), nullable=False),
            sa.Column("title", sa.String(length=200), nullable=False),
            sa.Column("severity", sa.String(length=20), nullable=False),
            sa.Column("status", sa.String(length=24), nullable=False),
            sa.Column("assignee", sa.String(length=120), nullable=False),
            sa.Column("due_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("notes", sa.Text(), nullable=False),
            sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(["assessment_id"], ["assessments.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="SET NULL"),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint(
                "assessment_id",
                "finding_code",
                name="uq_security_incidents_assessment_finding",
            ),
        )

    inspector = inspect(bind)
    columns = {column["name"] for column in inspector.get_columns(_TABLE)}
    missing_columns = _REQUIRED_COLUMNS - columns
    if missing_columns:
        raise RuntimeError(
            "Existing security_incidents table is incomplete; missing columns: "
            + ", ".join(sorted(missing_columns))
        )

    unique_constraints = inspector.get_unique_constraints(_TABLE)
    unique_pairs = {
        tuple(constraint.get("column_names") or []) for constraint in unique_constraints
    }
    if ("assessment_id", "finding_code") not in unique_pairs:
        raise RuntimeError(
            "security_incidents must enforce unique (assessment_id, finding_code) at the database boundary."
        )

    existing_indexes = {index["name"] for index in inspector.get_indexes(_TABLE)}
    for name, columns in _INDEXES:
        if name not in existing_indexes:
            op.create_index(name, _TABLE, columns, unique=False)
            existing_indexes.add(name)


def downgrade():
    bind = op.get_bind()
    inspector = inspect(bind)
    if _TABLE not in set(inspector.get_table_names()):
        return

    existing_indexes = {index["name"] for index in inspector.get_indexes(_TABLE)}
    for name, _columns in reversed(_INDEXES):
        if name in existing_indexes:
            op.drop_index(name, table_name=_TABLE)

    op.drop_table(_TABLE)
