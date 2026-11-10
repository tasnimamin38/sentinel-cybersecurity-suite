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

_FEATURE_CATALOG: tuple[dict[str, str], ...] = (
    {
        "code": "asset_inventory",
        "name": "Authorized asset inventory",
        "category": "Asset governance",
        "description": "Register approved assets with ownership, environment, criticality and authorization expiry.",
        "status": "available",
    },
    {
        "code": "authorized_domain_assessments",
        "name": "Authorized posture assessments",
        "category": "Assessment",
        "description": "Run bounded DNS-pinned HTTPS posture checks only inside configured authorized asset scope.",
        "status": "available",
    },
    {
        "code": "dns_tls_posture",
        "name": "DNS and TLS posture",
        "category": "Assessment",
        "description": "Review supported DNS email, certificate and TLS posture signals.",
        "status": "available",
    },
    {
        "code": "security_header_analysis",
        "name": "Security-header analysis",
        "category": "Assessment",
        "description": "Evaluate supported HTTPS response-header policies including HSTS and CSP.",
        "status": "available",
    },
    {
        "code": "assessment_jobs",
        "name": "Durable assessment jobs",
        "category": "Automation",
        "description": "Queue, lease, retry, recover and cooperatively cancel supported assessment jobs.",
        "status": "available",
    },
    {
        "code": "scheduled_assessments",
        "name": "Scheduled assessments",
        "category": "Automation",
        "description": "Schedule authorized asset reviews within the supported scheduling window.",
        "status": "available",
    },
    {
        "code": "security_findings",
        "name": "Explainable findings and risk scoring",
        "category": "Risk",
        "description": "Review evidence-backed security findings and explainable risk scores.",
        "status": "available",
    },
    {
        "code": "remediation_workflows",
        "name": "Remediation workflows",
        "category": "Remediation",
        "description": "Assign, track, update and resolve security remediation actions.",
        "status": "available",
    },
    {
        "code": "security_controls",
        "name": "Security control mapping",
        "category": "Assurance",
        "description": "Map observed findings to the platform's framework-neutral security controls.",
        "status": "available",
    },
    {
        "code": "audit_integrity",
        "name": "Tamper-evident audit chain",
        "category": "Audit",
        "description": "Inspect hash-linked audit events and verify chain integrity.",
        "status": "available",
    },
    {
        "code": "csv_exports",
        "name": "Audited CSV exports",
        "category": "Reporting",
        "description": "Export supported operational records with audit logging and formula-injection defenses.",
        "status": "available",
    },
    {
        "code": "security_event_monitoring",
        "name": "Runtime security event monitoring",
        "category": "Monitoring",
        "description": "Review defensive evidence for suspicious requests reaching SENTINEL's own API.",
        "status": "available",
    },
    {
        "code": "secret_scanning",
        "name": "Redacted secret scanning",
        "category": "Developer security",
        "description": "Identify supported secret patterns while redacting values and not persisting submitted source content.",
        "status": "available",
    },
    {
        "code": "api_credential_management",
        "name": "API credential lifecycle",
        "category": "Access control",
        "description": "Create, expire, rotate and revoke machine API credentials with one-time secret display.",
        "status": "available",
    },
    {
        "code": "role_based_access_control",
        "name": "Role-based access control",
        "category": "Access control",
        "description": "Apply route-level permissions and role-scoped service credential permissions.",
        "status": "available",
    },
    {
        "code": "shared_rate_limiting",
        "name": "Shared abuse protection",
        "category": "Platform security",
        "description": "Use shared Redis-backed request budgets and fail-closed protection for supported API paths.",
        "status": "available",
    },
    {
        "code": "signed_alert_webhooks",
        "name": "Signed security alert webhooks",
        "category": "Notifications",
        "description": "Deliver supported high and critical alerts with HMAC-SHA256 request signatures.",
        "status": "available",
    },
)

FREE_FEATURE_CODES = tuple(feature["code"] for feature in _FEATURE_CATALOG)

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
            "limits_enforced": False,
            "limit_enforcement_status": "not_enforced",
            "capacity_guidance_only": True,
            "feature_codes": list(FREE_FEATURE_CODES),
            "limits": free_limits,
            "notice": (
                "All currently shipped core security modules are free for Personal and Company "
                "workspaces during Early Access. No subscription quota is enforced. "
                "Capacity values are planning guidance only."
            ),
        }
    ]
    plans.extend(deepcopy(list(_PREVIEW_PLANS)))

    return {
        "catalog_version": 2,
        "launch_mode": "free_early_access",
        "default_plan_code": DEFAULT_PLAN_CODE,
        "billing_enabled": BILLING_ENABLED,
        "checkout_enabled": CHECKOUT_ENABLED,
        "usage_limits_enforced": False,
        "currency": "USD",
        "workspace_type": workspace_type,
        "feature_catalog": deepcopy(list(_FEATURE_CATALOG)),
        "plans": plans,
        "notice": (
            "SENTINEL Free Early Access includes every currently shipped core module for "
            "Personal and Company workspaces. No subscription-based feature or usage quota "
            "gates are active. Platform safety controls remain in force. Preview prices are "
            "proposals only; checkout and payments are disabled."
        ),
    }
