"""Add the legacy tenant registry and explicit tenant ownership columns.

Revision ID: 0008_tenant_registry_and_ownership
Revises: 0007_credential_asset_scopes

This is an additive schema foundation only. It assigns all existing rows to
one migration-owned legacy tenant; it does not enable tenant authorization.
"""

from datetime import UTC, datetime

import sqlalchemy as sa
from sqlalchemy import inspect

from alembic import op

revision = "0008_tenant_registry_and_ownership"
down_revision = "0007_credential_asset_scopes"
branch_labels = None
depends_on = None

LEGACY_TENANT_ID = "00000000-0000-4000-8000-000000000001"
TENANT_TABLE = "tenants"
TENANT_OWNED_TABLES = (
    "assets",
    "assessments",
    "remediation_tasks",
    "audit_events",
    "assessment_jobs",
    "api_credentials",
    "api_credential_usage",
    "security_incidents",
)


def _ensure_tenant_table(bind):
    inspector = inspect(bind)
    if TENANT_TABLE not in set(inspector.get_table_names()):
        op.create_table(
            TENANT_TABLE,
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("slug", sa.String(length=63), nullable=False),
            sa.Column("name", sa.String(length=120), nullable=False),
            sa.Column("status", sa.String(length=24), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.PrimaryKeyConstraint("id"),
        )

    inspector = inspect(bind)
    indexes = {item["name"] for item in inspector.get_indexes(TENANT_TABLE)}
    if "ix_tenants_slug" not in indexes:
        op.create_index("ix_tenants_slug", TENANT_TABLE, ["slug"], unique=True)

    row = bind.execute(
        sa.text("SELECT id FROM tenants WHERE id = :tenant_id"),
        {"tenant_id": LEGACY_TENANT_ID},
    ).first()
    if row is None:
        now = datetime.now(UTC)
        bind.execute(
            sa.text(
                "INSERT INTO tenants (id, slug, name, status, created_at, updated_at) "
                "VALUES (:id, :slug, :name, :status, :created_at, :updated_at)"
            ),
            {
                "id": LEGACY_TENANT_ID,
                "slug": "legacy-default",
                "name": "Legacy Installation",
                "status": "active",
                "created_at": now,
                "updated_at": now,
            },
        )


def _ensure_tenant_column(bind, table_name):
    inspector = inspect(bind)
    if table_name not in set(inspector.get_table_names()):
        raise RuntimeError(f"Expected tenant-owned table is missing: {table_name}")

    columns = {column["name"]: column for column in inspector.get_columns(table_name)}
    if "tenant_id" not in columns:
        with op.batch_alter_table(table_name) as batch:
            batch.add_column(sa.Column("tenant_id", sa.String(length=36), nullable=True))

    bind.execute(
        sa.text(f"UPDATE {table_name} SET tenant_id = :tenant_id WHERE tenant_id IS NULL"),
        {"tenant_id": LEGACY_TENANT_ID},
    )

    inspector = inspect(bind)
    column = next(
        item for item in inspector.get_columns(table_name) if item["name"] == "tenant_id"
    )
    if column["nullable"] or column.get("default") is None:
        with op.batch_alter_table(table_name) as batch:
            batch.alter_column(
                "tenant_id",
                existing_type=sa.String(length=36),
                existing_nullable=column["nullable"],
                nullable=False,
                server_default=LEGACY_TENANT_ID,
            )

    inspector = inspect(bind)
    foreign_keys = inspector.get_foreign_keys(table_name)
    has_tenant_fk = any(
        item.get("constrained_columns") == ["tenant_id"]
        and item.get("referred_table") == TENANT_TABLE
        for item in foreign_keys
    )
    if not has_tenant_fk:
        with op.batch_alter_table(table_name) as batch:
            batch.create_foreign_key(
                f"fk_{table_name}_tenant_id_tenants",
                TENANT_TABLE,
                ["tenant_id"],
                ["id"],
                ondelete="RESTRICT",
            )

    inspector = inspect(bind)
    indexes = {item["name"] for item in inspector.get_indexes(table_name)}
    index_name = f"ix_{table_name}_tenant_id"
    if index_name not in indexes:
        op.create_index(index_name, table_name, ["tenant_id"], unique=False)

    missing = bind.execute(
        sa.text(f"SELECT COUNT(*) FROM {table_name} WHERE tenant_id IS NULL")
    ).scalar_one()
    if missing:
        raise RuntimeError(f"Tenant ownership backfill failed for {table_name}: {missing} rows")


def upgrade():
    bind = op.get_bind()
    _ensure_tenant_table(bind)
    for table_name in TENANT_OWNED_TABLES:
        _ensure_tenant_column(bind, table_name)


def downgrade():
    bind = op.get_bind()
    inspector = inspect(bind)
    if TENANT_TABLE not in set(inspector.get_table_names()):
        return

    tenant_ids = bind.execute(sa.text("SELECT id FROM tenants")).scalars().all()
    if any(tenant_id != LEGACY_TENANT_ID for tenant_id in tenant_ids):
        raise RuntimeError(
            "Refusing to remove tenant ownership after additional tenants have been created."
        )

    for table_name in TENANT_OWNED_TABLES:
        inspector = inspect(bind)
        if table_name not in set(inspector.get_table_names()):
            continue
        columns = {column["name"] for column in inspector.get_columns(table_name)}
        if "tenant_id" not in columns:
            continue
        foreign_keys = inspector.get_foreign_keys(table_name)
        for item in foreign_keys:
            if (
                item.get("constrained_columns") == ["tenant_id"]
                and item.get("referred_table") == TENANT_TABLE
                and item.get("name")
            ):
                with op.batch_alter_table(table_name) as batch:
                    batch.drop_constraint(item["name"], type_="foreignkey")
        index_name = f"ix_{table_name}_tenant_id"
        indexes = {item["name"] for item in inspect(bind).get_indexes(table_name)}
        if index_name in indexes:
            op.drop_index(index_name, table_name=table_name)
        with op.batch_alter_table(table_name) as batch:
            batch.drop_column("tenant_id")

    op.drop_index("ix_tenants_slug", table_name=TENANT_TABLE)
    op.drop_table(TENANT_TABLE)
