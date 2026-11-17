"""Use Supabase Auth UUIDs for human and tenant identities.

Revision ID: 0006_auth_identity_uuids
Revises: 0005_tenant_registry

PostgreSQL deployments enforce foreign keys to auth.users. SQLite remains
supported for isolated repository migration tests.
"""

import sqlalchemy as sa
from sqlalchemy import inspect, text
from alembic import op

revision = "0006_auth_identity_uuids"
down_revision = "0005_tenant_registry"
branch_labels = None
depends_on = None

IDENTITY_COLUMNS = (
    ("human_profiles", "user_id"),
    ("tenant_memberships", "user_id"),
    ("tenant_memberships", "invited_by_user_id"),
    ("company_domain_challenges", "created_by_user_id"),
)

AUTH_FOREIGN_KEYS = (
    ("human_profiles", "fk_human_profiles_auth_user", "user_id", "CASCADE"),
    ("tenant_memberships", "fk_tenant_memberships_auth_user", "user_id", "RESTRICT"),
    ("tenant_memberships", "fk_tenant_memberships_invited_by_auth_user", "invited_by_user_id", "SET NULL"),
    ("company_domain_challenges", "fk_company_domain_challenges_created_by_auth_user", "created_by_user_id", "RESTRICT"),
)


def _inspector():
    return inspect(op.get_bind())


def _column(table: str, name: str) -> dict:
    for item in _inspector().get_columns(table):
        if item["name"] == name:
            return item
    raise RuntimeError(f"Required identity column {table}.{name} is missing.")


def _is_uuid_type(value) -> bool:
    return str(value).strip().lower() == "uuid" or isinstance(value, sa.Uuid)


def _ensure_uuid_type(table: str, name: str) -> None:
    column = _column(table, name)
    if _is_uuid_type(column["type"]):
        return

    dialect = op.get_bind().dialect.name
    if dialect == "postgresql":
        op.alter_column(
            table,
            name,
            existing_type=column["type"],
            type_=sa.Uuid(as_uuid=False),
            existing_nullable=column["nullable"],
            postgresql_using=f'"{name}"::uuid',
        )
        return

    if dialect == "sqlite":
        op.execute(
            text(
                f'UPDATE "{table}" '
                f'SET "{name}" = lower(replace("{name}", \'-\', \'\')) '
                f'WHERE "{name}" IS NOT NULL'
            )
        )
        with op.batch_alter_table(table, recreate="always") as batch:
            batch.alter_column(
                name,
                existing_type=column["type"],
                type_=sa.Uuid(as_uuid=False),
                existing_nullable=column["nullable"],
            )
        return

    raise RuntimeError(f"UUID identity migration is not implemented for {dialect}.")


def _has_auth_foreign_key(table: str, column: str) -> bool:
    for item in _inspector().get_foreign_keys(table):
        if (
            item.get("constrained_columns") == [column]
            and item.get("referred_schema") == "auth"
            and item.get("referred_table") == "users"
            and item.get("referred_columns") == ["id"]
        ):
            return True
    return False


def _ensure_auth_foreign_key(table: str, name: str, column: str, ondelete: str) -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    if _has_auth_foreign_key(table, column):
        return
    op.create_foreign_key(
        name,
        table,
        "users",
        [column],
        ["id"],
        source_schema="sentinel",
        referent_schema="auth",
        ondelete=ondelete,
    )


def upgrade() -> None:
    for table, column in IDENTITY_COLUMNS:
        _ensure_uuid_type(table, column)

    for table, name, column, ondelete in AUTH_FOREIGN_KEYS:
        _ensure_auth_foreign_key(table, name, column, ondelete)


def _drop_auth_foreign_keys() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    for table, name, column, ondelete in AUTH_FOREIGN_KEYS:
        names = {item.get("name") for item in _inspector().get_foreign_keys(table)}
        if name in names:
            op.drop_constraint(name, table, type_="foreignkey", schema="sentinel")


def downgrade() -> None:
    _drop_auth_foreign_keys()
    dialect = op.get_bind().dialect.name

    for table, column_name in IDENTITY_COLUMNS:
        column = _column(table, column_name)
        if not _is_uuid_type(column["type"]):
            continue
        if dialect == "postgresql":
            op.alter_column(
                table,
                column_name,
                existing_type=column["type"],
                type_=sa.String(36),
                existing_nullable=column["nullable"],
                postgresql_using=f'"{column_name}"::text',
            )
        elif dialect == "sqlite":
            op.execute(
                text(
                    f'UPDATE "{table}" SET "{column_name}" = '
                    f'substr("{column_name}",1,8) || \'-\' || '
                    f'substr("{column_name}",9,4) || \'-\' || '
                    f'substr("{column_name}",13,4) || \'-\' || '
                    f'substr("{column_name}",17,4) || \'-\' || '
                    f'substr("{column_name}",21,12) '
                    f'WHERE "{column_name}" IS NOT NULL AND length("{column_name}") = 32'
                )
            )
            with op.batch_alter_table(table, recreate="always") as batch:
                batch.alter_column(
                    column_name,
                    existing_type=column["type"],
                    type_=sa.String(36),
                    existing_nullable=column["nullable"],
                )
        else:
            raise RuntimeError(f"UUID identity downgrade is not implemented for {dialect}.")
