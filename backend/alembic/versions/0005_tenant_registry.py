"""Add tenant registry and migrate legacy operational records into one tenant.

Revision ID: 0005_tenant_registry
Revises: 0004_api_credentials

This is a transitional schema foundation. It does not enable public signup.
Existing API-key operations retain the deterministic legacy tenant default.
"""

import sqlalchemy as sa
from sqlalchemy import inspect

from alembic import op

revision = "0005_tenant_registry"
down_revision = "0004_api_credentials"
branch_labels = None
depends_on = None

LEGACY_TENANT_ID = "00000000-0000-4000-8000-000000000001"
LEGACY_SLUG = "legacy-installation"
CORE_TABLES = (
    "assets",
    "assessments",
    "remediation_tasks",
    "audit_events",
    "assessment_jobs",
    "api_credentials",
)


def _inspector():
    return inspect(op.get_bind())


def _create_registry_tables() -> None:
    tables = set(_inspector().get_table_names())
    if "tenants" not in tables:
        op.create_table(
            "tenants",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("slug", sa.String(80), nullable=False),
            sa.Column("name", sa.String(200), nullable=False),
            sa.Column("workspace_type", sa.String(16), nullable=False),
            sa.Column("status", sa.String(24), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.CheckConstraint(
                "workspace_type IN ('legacy', 'personal', 'company')",
                name="ck_tenants_workspace_type",
            ),
            sa.UniqueConstraint("slug", name="uq_tenants_slug"),
        )
        op.create_index("ix_tenants_status", "tenants", ["status"], unique=False)

    tables = set(_inspector().get_table_names())
    if "human_profiles" not in tables:
        op.create_table(
            "human_profiles",
            sa.Column("user_id", sa.String(36), primary_key=True),
            sa.Column("username", sa.String(40), nullable=False),
            sa.Column("username_normalized", sa.String(40), nullable=False),
            sa.Column("first_name", sa.String(80), nullable=False),
            sa.Column("last_name", sa.String(80), nullable=False),
            sa.Column("primary_use_case", sa.String(80), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.UniqueConstraint(
                "username_normalized",
                name="uq_human_profiles_username_normalized",
            ),
        )

    tables = set(_inspector().get_table_names())
    if "tenant_memberships" not in tables:
        op.create_table(
            "tenant_memberships",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("tenant_id", sa.String(36), nullable=False),
            sa.Column("user_id", sa.String(36), nullable=False),
            sa.Column("role", sa.String(24), nullable=False),
            sa.Column("status", sa.String(24), nullable=False),
            sa.Column("invited_by_user_id", sa.String(36), nullable=True),
            sa.Column("invited_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("joined_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
            sa.UniqueConstraint(
                "tenant_id",
                "user_id",
                name="uq_tenant_memberships_tenant_user",
            ),
            sa.CheckConstraint(
                "role IN ('owner', 'admin', 'analyst', 'auditor', 'read_only')",
                name="ck_tenant_memberships_role",
            ),
            sa.CheckConstraint(
                "status IN ('invited', 'active', 'suspended')",
                name="ck_tenant_memberships_status",
            ),
        )
        op.create_index(
            "ix_tenant_memberships_tenant_id",
            "tenant_memberships",
            ["tenant_id"],
            unique=False,
        )
        op.create_index(
            "ix_tenant_memberships_user_id",
            "tenant_memberships",
            ["user_id"],
            unique=False,
        )
        op.create_index(
            "ix_tenant_memberships_user_status",
            "tenant_memberships",
            ["user_id", "status"],
            unique=False,
        )

    tables = set(_inspector().get_table_names())
    if "company_profiles" not in tables:
        op.create_table(
            "company_profiles",
            sa.Column("tenant_id", sa.String(36), primary_key=True),
            sa.Column("legal_name", sa.String(200), nullable=False),
            sa.Column("company_type", sa.String(40), nullable=False),
            sa.Column("industry", sa.String(80), nullable=False),
            sa.Column("employee_range", sa.String(24), nullable=False),
            sa.Column("country_code", sa.String(2), nullable=False),
            sa.Column("official_website", sa.String(253), nullable=True),
            sa.Column("primary_domain", sa.String(253), nullable=False),
            sa.Column("registration_number", sa.String(120), nullable=True),
            sa.Column("tax_vat_number", sa.String(120), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        )

    tables = set(_inspector().get_table_names())
    if "company_domain_challenges" not in tables:
        op.create_table(
            "company_domain_challenges",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("tenant_id", sa.String(36), nullable=False),
            sa.Column("domain", sa.String(253), nullable=False),
            sa.Column("challenge_hash", sa.String(64), nullable=False),
            sa.Column("status", sa.String(24), nullable=False),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_by_user_id", sa.String(36), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
            sa.UniqueConstraint(
                "challenge_hash",
                name="uq_company_domain_challenges_hash",
            ),
        )
        op.create_index(
            "ix_company_domain_challenges_tenant_domain",
            "company_domain_challenges",
            ["tenant_id", "domain"],
            unique=False,
        )


def _ensure_legacy_tenant() -> None:
    bind = op.get_bind()
    existing = bind.execute(
        sa.text("SELECT id, slug, workspace_type FROM tenants WHERE id = :tenant_id"),
        {"tenant_id": LEGACY_TENANT_ID},
    ).first()
    if existing is not None:
        if existing.slug != LEGACY_SLUG or existing.workspace_type != "legacy":
            raise RuntimeError("The deterministic legacy tenant ID is already used by another tenant.")
        return

    slug_owner = bind.execute(
        sa.text("SELECT id FROM tenants WHERE slug = :slug"),
        {"slug": LEGACY_SLUG},
    ).first()
    if slug_owner is not None:
        raise RuntimeError("The legacy tenant slug is already owned by a different tenant.")

    bind.execute(
        sa.text(
            """
            INSERT INTO tenants
                (id, slug, name, workspace_type, status, created_at, updated_at)
            VALUES
                (:id, :slug, :name, 'legacy', 'active', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            """
        ),
        {
            "id": LEGACY_TENANT_ID,
            "slug": LEGACY_SLUG,
            "name": "Legacy Installation",
        },
    )


def _has_foreign_key(table: str, columns: list[str], referred_table: str, referred_columns: list[str]) -> bool:
    for foreign_key in _inspector().get_foreign_keys(table):
        if (
            foreign_key.get("constrained_columns") == columns
            and foreign_key.get("referred_table") == referred_table
            and foreign_key.get("referred_columns") == referred_columns
        ):
            return True
    return False


def _has_unique(table: str, columns: list[str]) -> bool:
    inspector = _inspector()
    if any(
        item.get("column_names") == columns
        for item in inspector.get_unique_constraints(table)
    ):
        return True
    return any(
        item.get("unique") and item.get("column_names") == columns
        for item in inspector.get_indexes(table)
    )


def _ensure_unique(table: str, name: str, columns: list[str]) -> None:
    if _has_unique(table, columns):
        return
    with op.batch_alter_table(table) as batch:
        batch.create_unique_constraint(name, columns)


def _ensure_foreign_key(
    table: str,
    name: str,
    columns: list[str],
    referred_table: str,
    referred_columns: list[str],
    ondelete: str | None = None,
) -> None:
    if _has_foreign_key(table, columns, referred_table, referred_columns):
        return
    with op.batch_alter_table(table) as batch:
        batch.create_foreign_key(
            name,
            referred_table,
            columns,
            referred_columns,
            ondelete=ondelete,
        )


def _ensure_tenant_column(table: str) -> None:
    columns = {column["name"]: column for column in _inspector().get_columns(table)}
    if "tenant_id" not in columns:
        op.add_column(
            table,
            sa.Column(
                "tenant_id",
                sa.String(36),
                nullable=True,
                server_default=sa.text(f"'{LEGACY_TENANT_ID}'"),
            ),
        )
    op.get_bind().execute(
        sa.text(f'UPDATE "{table}" SET tenant_id = :tenant_id WHERE tenant_id IS NULL'),
        {"tenant_id": LEGACY_TENANT_ID},
    )

    column = next(
        item for item in _inspector().get_columns(table) if item["name"] == "tenant_id"
    )
    if column.get("nullable", True) or column.get("default") is None:
        with op.batch_alter_table(table) as batch:
            batch.alter_column(
                "tenant_id",
                existing_type=sa.String(36),
                nullable=False,
                server_default=sa.text(f"'{LEGACY_TENANT_ID}'"),
            )

    _ensure_foreign_key(
        table,
        f"fk_{table}_tenant_id_tenants",
        ["tenant_id"],
        "tenants",
        ["id"],
        ondelete="RESTRICT",
    )
    indexes = _inspector().get_indexes(table)
    if not any(
        item.get("column_names") == ["tenant_id"]
        for item in indexes
    ):
        op.create_index(f"ix_{table}_tenant_id", table, ["tenant_id"], unique=False)


def _drop_legacy_global_uniqueness() -> None:
    # A hostname is unique within a workspace, not across all customers.
    inspector = _inspector()
    for item in inspector.get_indexes("assets"):
        if item.get("unique") and item.get("column_names") == ["hostname"]:
            op.drop_index(item["name"], table_name="assets")
    inspector = _inspector()
    for item in inspector.get_unique_constraints("assets"):
        if item.get("column_names") == ["hostname"]:
            with op.batch_alter_table("assets") as batch:
                batch.drop_constraint(item["name"], type_="unique")

    # Preserve the hostname lookup path after removing the old global unique index.
    if not any(
        item.get("column_names") == ["hostname"]
        for item in _inspector().get_indexes("assets")
    ):
        op.create_index("ix_assets_hostname", "assets", ["hostname"], unique=False)

    # Audit sequence numbers restart inside each workspace. Existing global
    # sequence uniqueness must be relaxed before the composite tenant constraint.
    inspector = _inspector()
    for item in inspector.get_indexes("audit_events"):
        if item.get("unique") and item.get("column_names") == ["sequence_no"]:
            op.drop_index(item["name"], table_name="audit_events")
    if not any(
        item.get("column_names") == ["sequence_no"]
        for item in _inspector().get_indexes("audit_events")
    ):
        op.create_index(
            "ix_audit_events_sequence_no",
            "audit_events",
            ["sequence_no"],
            unique=False,
        )

    # Audit sequences restart for each workspace. Remove the old global unique
    # index and retain a non-unique lookup index plus tenant-scoped uniqueness.
    inspector = _inspector()
    for item in inspector.get_indexes("audit_events"):
        if item.get("unique") and item.get("column_names") == ["sequence_no"]:
            op.drop_index(item["name"], table_name="audit_events")
    audit_indexes = _inspector().get_indexes("audit_events")
    if not any(
        item.get("column_names") == ["sequence_no"]
        for item in audit_indexes
    ):
        op.create_index(
            "ix_audit_events_sequence_no",
            "audit_events",
            ["sequence_no"],
            unique=False,
        )

    # Idempotency tokens are scoped to a workspace; the same token may be used
    # independently by another tenant.
    inspector = _inspector()
    for item in inspector.get_indexes("assessment_jobs"):
        if item.get("unique") and item.get("column_names") == ["idempotency_key_hash"]:
            op.drop_index(item["name"], table_name="assessment_jobs")
    inspector = _inspector()
    for item in inspector.get_unique_constraints("assessment_jobs"):
        if item.get("column_names") == ["idempotency_key_hash"]:
            with op.batch_alter_table("assessment_jobs") as batch:
                batch.drop_constraint(item["name"], type_="unique")


def upgrade() -> None:
    _create_registry_tables()
    _ensure_legacy_tenant()

    for table in CORE_TABLES:
        _ensure_tenant_column(table)

    _drop_legacy_global_uniqueness()

    for table in CORE_TABLES:
        _ensure_unique(table, f"uq_{table}_tenant_id", ["tenant_id", "id"])

    _ensure_unique(
        "assets",
        "uq_assets_tenant_hostname",
        ["tenant_id", "hostname"],
    )
    _ensure_unique(
        "assessment_jobs",
        "uq_assessment_jobs_tenant_idempotency_key_hash",
        ["tenant_id", "idempotency_key_hash"],
    )
    _ensure_unique(
        "audit_events",
        "uq_audit_events_tenant_sequence",
        ["tenant_id", "sequence_no"],
    )
    _ensure_unique(
        "audit_events",
        "uq_audit_events_tenant_sequence",
        ["tenant_id", "sequence_no"],
    )

    # Composite foreign keys are the database-level guard against linking a
    # row in one workspace to an asset or assessment owned by another.
    _ensure_foreign_key(
        "assessments",
        "fk_assessments_tenant_asset",
        ["tenant_id", "asset_id"],
        "assets",
        ["tenant_id", "id"],
    )
    _ensure_foreign_key(
        "remediation_tasks",
        "fk_remediation_tasks_tenant_assessment",
        ["tenant_id", "assessment_id"],
        "assessments",
        ["tenant_id", "id"],
    )
    _ensure_foreign_key(
        "remediation_tasks",
        "fk_remediation_tasks_tenant_asset",
        ["tenant_id", "asset_id"],
        "assets",
        ["tenant_id", "id"],
    )
    _ensure_foreign_key(
        "assessment_jobs",
        "fk_assessment_jobs_tenant_asset",
        ["tenant_id", "asset_id"],
        "assets",
        ["tenant_id", "id"],
    )
    _ensure_foreign_key(
        "assessment_jobs",
        "fk_assessment_jobs_tenant_assessment",
        ["tenant_id", "assessment_id"],
        "assessments",
        ["tenant_id", "id"],
    )


def _drop_tenant_artifacts(table: str) -> None:
    inspector = _inspector()

    # Drop every index that depends on tenant_id before SQLite batch mode
    # rebuilds the table without that column.
    for item in inspector.get_indexes(table):
        if "tenant_id" in (item.get("column_names") or []):
            op.drop_index(item["name"], table_name=table)

    inspector = _inspector()
    foreign_keys = [
        item
        for item in inspector.get_foreign_keys(table)
        if "tenant_id" in (item.get("constrained_columns") or [])
    ]
    unique_constraints = [
        item
        for item in inspector.get_unique_constraints(table)
        if "tenant_id" in (item.get("column_names") or [])
    ]

    with op.batch_alter_table(table) as batch:
        for item in foreign_keys:
            name = item.get("name")
            if name:
                batch.drop_constraint(name, type_="foreignkey")
        for item in unique_constraints:
            name = item.get("name")
            if name:
                batch.drop_constraint(name, type_="unique")
        batch.drop_column("tenant_id")


def _drop_tenant_artifacts(table: str) -> None:
    inspector = _inspector()

    # Drop indexes that depend on tenant_id before a SQLite batch table rebuild.
    for item in inspector.get_indexes(table):
        if "tenant_id" in (item.get("column_names") or []):
            op.drop_index(item["name"], table_name=table)

    inspector = _inspector()
    foreign_keys = [
        item
        for item in inspector.get_foreign_keys(table)
        if "tenant_id" in (item.get("constrained_columns") or [])
    ]
    unique_constraints = [
        item
        for item in inspector.get_unique_constraints(table)
        if "tenant_id" in (item.get("column_names") or [])
    ]

    with op.batch_alter_table(table) as batch:
        for item in foreign_keys:
            name = item.get("name")
            if name:
                batch.drop_constraint(name, type_="foreignkey")
        for item in unique_constraints:
            name = item.get("name")
            if name:
                batch.drop_constraint(name, type_="unique")
        batch.drop_column("tenant_id")


def downgrade() -> None:
    bind = op.get_bind()
    tables = set(_inspector().get_table_names())
    if "tenants" not in tables:
        return

    non_legacy_tenants = bind.execute(
        sa.text("SELECT COUNT(*) FROM tenants WHERE id <> :tenant_id"),
        {"tenant_id": LEGACY_TENANT_ID},
    ).scalar_one()
    if non_legacy_tenants:
        raise RuntimeError("Refusing tenant downgrade: customer workspaces already exist.")

    for table in ("tenant_memberships", "human_profiles", "company_profiles", "company_domain_challenges"):
        if table in tables:
            count = bind.execute(sa.text(f'SELECT COUNT(*) FROM "{table}"')).scalar_one()
            if count:
                raise RuntimeError(
                    f"Refusing tenant downgrade: {table} contains customer identity data."
                )

    for table in CORE_TABLES:
        if table in tables:
            count = bind.execute(
                sa.text(
                    f'SELECT COUNT(*) FROM "{table}" WHERE tenant_id <> :tenant_id OR tenant_id IS NULL'
                ),
                {"tenant_id": LEGACY_TENANT_ID},
            ).scalar_one()
            if count:
                raise RuntimeError(
                    f"Refusing tenant downgrade: {table} contains non-legacy workspace data."
                )

    # Drop child-side tenant constraints before parent-side tenant keys.
    for table in reversed(CORE_TABLES):
        if table in set(_inspector().get_table_names()):
            _drop_tenant_artifacts(table)

    # Restore the legacy global uniqueness rules after all tenant-scoped
    # constraints/indexes and tenant_id columns have been removed.
    indexes = {item["name"]: item for item in _inspector().get_indexes("assets")}
    if "ix_assets_hostname" in indexes:
        op.drop_index("ix_assets_hostname", table_name="assets")
    op.create_index("ix_assets_hostname", "assets", ["hostname"], unique=True)

    _ensure_unique(
        "assessment_jobs",
        "uq_assessment_jobs_idempotency_key_hash",
        ["idempotency_key_hash"],
    )

    audit_indexes = {
        item["name"]: item
        for item in _inspector().get_indexes("audit_events")
    }
    if "ix_audit_events_sequence_no" in audit_indexes:
        op.drop_index("ix_audit_events_sequence_no", table_name="audit_events")
    op.create_index(
        "ix_audit_events_sequence_no",
        "audit_events",
        ["sequence_no"],
        unique=True,
    )

    for table in (
        "company_domain_challenges",
        "company_profiles",
        "tenant_memberships",
        "human_profiles",
        "tenants",
    ):
        if table in set(_inspector().get_table_names()):
            op.drop_table(table)
