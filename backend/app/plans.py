"""Public Free Early Access plan catalogue.

This module is intentionally static until the tenant subscription ledger is
implemented. Preview prices are display metadata only: no payment or checkout
integration exists in the launch release.
"""

from copy import deepcopy
from typing import Any

BILLING_ENABLED = False
CHECKOUT_ENABLED = False
DEFAULT_PLAN_CODE = "free_early_access"

FREE_FEATURE_CODES = (
    "asset_inventory",
    "authorized_domain_assessments",
    "assessment_jobs",
    "security_findings",
    "remediation_workflows",
    "security_controls",
    "audit_integrity",
    "security_event_monitoring",
    "secret_scanning",
    "api_credential_management",
    "csv_exports",
)

_FREE_LIMITS_BY_WORKSPACE_TYPE: dict[str, dict[str, int | str]] = {
    "personal": {
        "workspace_type": "personal",
        "max_assets": 10,
        "assessments_per_month": 20,
        "max_members": 1,
        "max_machine_identities": 2,
        "evidence_retention_days": 30,
    },
    "company": {
        "workspace_type": "company",
        "max_assets": 25,
        "assessments_per_month": 50,
        "max_members": 5,
        "max_machine_identities": 3,
        "evidence_retention_days": 30,
    },
}

_PREVIEW_PLANS: tuple[dict[str, Any], ...] = (
    {
        "code": "pro",
        "name": "Pro",
        "status": "preview",
        "price": {
            "amount_cents": 2900,
            "currency": "USD",
            "interval": "month",
            "display": "$29/month",
        },
        "purchasable": False,
        "checkout_enabled": False,
        "planned_for": "independent security professionals and small teams",
        "capacity_preview": {
            "max_assets": 100,
            "assessments_per_month": 300,
            "max_members": 3,
            "max_machine_identities": 10,
            "evidence_retention_days": 90,
        },
    },
    {
        "code": "team",
        "name": "Team",
        "status": "preview",
        "price": {
            "amount_cents": 9900,
            "currency": "USD",
            "interval": "month",
            "display": "$99/month",
        },
        "purchasable": False,
        "checkout_enabled": False,
        "planned_for": "collaborative security teams",
        "capacity_preview": {
            "max_assets": 500,
            "assessments_per_month": 1500,
            "max_members": 15,
            "max_machine_identities": 30,
            "evidence_retention_days": 180,
        },
    },
    {
        "code": "business",
        "name": "Business",
        "status": "preview",
        "price": {
            "amount_cents": 29900,
            "currency": "USD",
            "interval": "month",
            "display": "$299/month",
        },
        "purchasable": False,
        "checkout_enabled": False,
        "planned_for": "growing organizations with formal security operations",
        "capacity_preview": {
            "max_assets": 2000,
            "assessments_per_month": 8000,
            "max_members": 50,
            "max_machine_identities": 100,
            "evidence_retention_days": 365,
        },
    },
    {
        "code": "enterprise",
        "name": "Enterprise",
        "status": "preview",
        "price": {
            "amount_cents": None,
            "currency": "USD",
            "interval": "custom",
            "display": "Custom",
        },
        "purchasable": False,
        "checkout_enabled": False,
        "planned_for": "large and regulated organizations with negotiated requirements",
        "capacity_preview": None,
    },
)


def get_public_plan_catalog(workspace_type: str | None = None) -> dict[str, Any]:
    """Return a defensive copy of the public plan catalogue.

    workspace_type selects Personal or Company launch limits. If omitted,
    the Free plan returns both profiles. Unknown values fail closed.
    """
    if workspace_type not in {None, "personal", "company"}:
        raise ValueError("workspace_type must be 'personal' or 'company'.")

    if workspace_type is None:
        free_limits: dict[str, Any] = {
            "by_workspace_type": deepcopy(_FREE_LIMITS_BY_WORKSPACE_TYPE)
        }
    else:
        free_limits = deepcopy(_FREE_LIMITS_BY_WORKSPACE_TYPE[workspace_type])

    plans: list[dict[str, Any]] = [
        {
            "code": DEFAULT_PLAN_CODE,
            "name": "Free Early Access",
            "status": "active",
            "price": {
                "amount_cents": 0,
                "currency": "USD",
                "interval": "month",
                "display": "Free",
            },
            "default_for_new_workspaces": True,
            "purchasable": False,
            "checkout_enabled": False,
            "feature_codes": list(FREE_FEATURE_CODES),
            "limits": free_limits,
            "notice": (
                "All currently shipped core security modules are included. "
                "Fair-use limits protect shared assessment capacity."
            ),
        }
    ]
    plans.extend(deepcopy(list(_PREVIEW_PLANS)))

    return {
        "catalog_version": 1,
        "launch_mode": "free_early_access",
        "default_plan_code": DEFAULT_PLAN_CODE,
        "billing_enabled": BILLING_ENABLED,
        "checkout_enabled": CHECKOUT_ENABLED,
        "currency": "USD",
        "workspace_type": workspace_type,
        "plans": plans,
        "notice": (
            "SENTINEL is in Free Early Access. All current core modules are free. "
            "Preview prices are proposals only; no payments or paid upgrades are enabled."
        ),
    }
