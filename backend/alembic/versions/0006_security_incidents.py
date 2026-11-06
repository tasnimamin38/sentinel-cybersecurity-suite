"""Add auditable security incident triage records.

Revision ID: 0006_security_incidents
Revises: 0005_credential_controls
"""

import sqlalchemy as sa

from alembic import op

revision = "0006_security_incidents"
down_revision = "0005_credential_controls"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "security_incidents",
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
    op.create_index(
        "ix_security_incidents_assessment_id", "security_incidents", ["assessment_id"], unique=False
    )
    op.create_index(
        "ix_security_incidents_asset_id", "security_incidents", ["asset_id"], unique=False
    )
    op.create_index(
        "ix_security_incidents_severity", "security_incidents", ["severity"], unique=False
    )
    op.create_index(
        "ix_security_incidents_status", "security_incidents", ["status"], unique=False
    )
    op.create_index(
        "ix_security_incidents_status_severity",
        "security_incidents",
        ["status", "severity"],
        unique=False,
    )


def downgrade():
    op.drop_index("ix_security_incidents_status_severity", table_name="security_incidents")
    op.drop_index("ix_security_incidents_status", table_name="security_incidents")
    op.drop_index("ix_security_incidents_severity", table_name="security_incidents")
    op.drop_index("ix_security_incidents_asset_id", table_name="security_incidents")
    op.drop_index("ix_security_incidents_assessment_id", table_name="security_incidents")
    op.drop_table("security_incidents")
