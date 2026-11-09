"""Fail-closed tenant scoping for SQLAlchemy ORM sessions.

Sessions created by the production session factory carry an explicit tenant
context. ORM SELECT/UPDATE/DELETE statements and flushes are constrained to
that tenant. The only query bypass is the authentication lookup performed
before the managed API credential's tenant is known.
"""

from collections.abc import Iterable

from sqlalchemy import event
from sqlalchemy.orm import Session, with_loader_criteria

from app.models import (
    ApiCredential,
    Asset,
    Assessment,
    AssessmentJob,
    AuditEvent,
    CompanyDomainChallenge,
    CompanyProfile,
    RemediationTask,
    TenantMembership,
)

TENANT_SCOPED_MODELS = (
    ApiCredential,
    Asset,
    Assessment,
    AssessmentJob,
    AuditEvent,
    CompanyDomainChallenge,
    CompanyProfile,
    RemediationTask,
    TenantMembership,
)


class TenantScopeViolation(RuntimeError):
    """Raised when a session attempts to access or mutate another tenant's row."""


def set_tenant_context(session: Session, tenant_id: str) -> None:
    """Bind one tenant to a request session after authenticating its principal."""
    if not isinstance(tenant_id, str) or not tenant_id.strip():
        raise TenantScopeViolation("A verified tenant context is required.")

    current = session.info.get("tenant_id")
    bound = session.info.get("tenant_context_bound", False)
    if bound and current != tenant_id:
        raise TenantScopeViolation("A database session cannot switch tenants.")
    session.info["tenant_id"] = tenant_id
    session.info["tenant_isolation_required"] = True
    session.info["tenant_context_bound"] = True


@event.listens_for(Session, "do_orm_execute")
def _apply_tenant_criteria(execute_state) -> None:
    session = execute_state.session
    if not session.info.get("tenant_isolation_required"):
        return
    if execute_state.execution_options.get("skip_tenant_scope", False):
        return
    if not execute_state.is_orm_statement:
        return
    if execute_state.is_insert:
        raise TenantScopeViolation(
            "Bulk ORM inserts are disabled; persist tenant-owned objects through the scoped session."
        )
    if not (execute_state.is_select or execute_state.is_update or execute_state.is_delete):
        return

    if execute_state.is_update:
        assigned_columns = getattr(execute_state.statement, "_values", None) or {}
        for column in assigned_columns:
            if getattr(column, "key", None) == "tenant_id" or str(column) == "tenant_id":
                raise TenantScopeViolation("A tenant-owned row cannot change its tenant_id.")

    tenant_id = session.info.get("tenant_id")
    if not isinstance(tenant_id, str) or not tenant_id:
        raise TenantScopeViolation("A tenant-scoped session is missing its tenant context.")

    criteria = [
        with_loader_criteria(
            model,
            lambda row: row.tenant_id == tenant_id,
            include_aliases=True,
        )
        for model in TENANT_SCOPED_MODELS
    ]
    criteria.append(
        with_loader_criteria(
            Tenant,
            lambda row: row.id == tenant_id,
            include_aliases=True,
        )
    )
    execute_state.statement = execute_state.statement.options(*criteria)


@event.listens_for(Session, "before_flush")
def _enforce_tenant_on_flush(
    session: Session,
    flush_context,
    instances: Iterable[object] | None,
) -> None:
    if not session.info.get("tenant_isolation_required"):
        return

    tenant_id = session.info.get("tenant_id")
    if not isinstance(tenant_id, str) or not tenant_id:
        raise TenantScopeViolation("A tenant-scoped session is missing its tenant context.")

    for instance in session.new.union(session.dirty).union(session.deleted):
        if isinstance(instance, Tenant):
            if instance in session.new or instance.id != tenant_id:
                raise TenantScopeViolation(
                    "Tenant registry writes require the privileged workspace provisioning service."
                )
            continue
        if not isinstance(instance, TENANT_SCOPED_MODELS):
            continue

        object_tenant_id = getattr(instance, "tenant_id", None)
        if instance in session.new and object_tenant_id is None:
            instance.tenant_id = tenant_id
            continue
        if object_tenant_id != tenant_id:
            raise TenantScopeViolation(
                "A tenant-scoped session cannot insert or mutate another tenant's row."
            )
