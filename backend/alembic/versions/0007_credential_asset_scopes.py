"""Add per-managed-credential asset authorization scope.

Revision ID: 0007_credential_asset_scopes
Revises: 0006_security_incidents
"""

import sqlalchemy as sa
from sqlalchemy import inspect

from alembic import op

revision = "0007_credential_asset_scopes"
down_revision = "0006_security_incidents"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = inspect(bind)
    if "api_credentials" not in set(inspector.get_table_names()):
        raise RuntimeError("api_credentials table is required before asset-scope migration.")

    columns = {column["name"] for column in inspector.get_columns("api_credentials")}
    if "asset_scope_mode" not in columns:
        op.add_column(
            "api_credentials",
            sa.Column("asset_scope_mode", sa.String(length=16), nullable=False, server_default="all"),
        )
    if "asset_scope_ids" not in columns:
        op.add_column(
            "api_credentials",
            sa.Column("asset_scope_ids", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        )


def downgrade():
    bind = op.get_bind()
    inspector = inspect(bind)
    if "api_credentials" not in set(inspector.get_table_names()):
        return

    columns = {column["name"] for column in inspector.get_columns("api_credentials")}
    if "asset_scope_ids" in columns:
        op.drop_column("api_credentials", "asset_scope_ids")
    if "asset_scope_mode" in columns:
        op.drop_column("api_credentials", "asset_scope_mode")
