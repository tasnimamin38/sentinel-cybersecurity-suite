"""Add service credential quotas and controlled rotation.

Revision ID: 0005_credential_controls
Revises: 0004_api_credentials
"""

import sqlalchemy as sa
from sqlalchemy import inspect

from alembic import op

revision = "0005_credential_controls"
down_revision = "0004_api_credentials"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = inspect(bind)
    tables = set(inspector.get_table_names())
    if "api_credentials" in tables:
        columns = {column["name"] for column in inspector.get_columns("api_credentials")}
        additions = (
            ("rate_limit_per_minute", sa.Integer(), sa.text("120")),
            ("daily_request_limit", sa.Integer(), sa.text("10000")),
            ("rotated_to_id", sa.String(length=36), None),
            ("rotation_grace_expires_at", sa.DateTime(timezone=True), None),
        )
        for name, column_type, server_default in additions:
            if name not in columns:
                op.add_column(
                    "api_credentials",
                    sa.Column(
                        name,
                        column_type,
                        nullable=name not in {"rate_limit_per_minute", "daily_request_limit"},
                        server_default=server_default,
                    ),
                )

        inspector = inspect(bind)
        indexes = {item["name"] for item in inspector.get_indexes("api_credentials")}
        if "ix_api_credentials_rotated_to_id" not in indexes:
            op.create_index(
                "ix_api_credentials_rotated_to_id",
                "api_credentials",
                ["rotated_to_id"],
                unique=False,
            )

    inspector = inspect(bind)
    if "api_credential_usage" not in set(inspector.get_table_names()):
        op.create_table(
            "api_credential_usage",
            sa.Column("credential_id", sa.String(length=64), nullable=False),
            sa.Column("minute_window_start", sa.DateTime(timezone=True), nullable=False),
            sa.Column("minute_requests", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("day_window_start", sa.DateTime(timezone=True), nullable=False),
            sa.Column("day_requests", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.PrimaryKeyConstraint("credential_id"),
        )


def downgrade():
    bind = op.get_bind()
    if "api_credential_usage" in set(inspect(bind).get_table_names()):
        op.drop_table("api_credential_usage")
    if "api_credentials" not in set(inspect(bind).get_table_names()):
        return

    inspector = inspect(bind)
    indexes = {item["name"] for item in inspector.get_indexes("api_credentials")}
    if "ix_api_credentials_rotated_to_id" in indexes:
        op.drop_index("ix_api_credentials_rotated_to_id", table_name="api_credentials")

    columns = {column["name"] for column in inspect(bind).get_columns("api_credentials")}
    for name in (
        "rotation_grace_expires_at",
        "rotated_to_id",
        "daily_request_limit",
        "rate_limit_per_minute",
    ):
        if name in columns:
            op.drop_column("api_credentials", name)
