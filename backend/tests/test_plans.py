from copy import deepcopy

import pytest

from app.plans import (
    BILLING_ENABLED,
    CHECKOUT_ENABLED,
    DEFAULT_PLAN_CODE,
    FREE_FEATURE_CODES,
    get_public_plan_catalog,
)


def test_new_workspaces_default_to_free_early_access_without_billing():
    catalog = get_public_plan_catalog()
    assert catalog["default_plan_code"] == "free_early_access"
    assert catalog["launch_mode"] == "free_early_access"
    assert catalog["billing_enabled"] is False
    assert catalog["checkout_enabled"] is False
    assert catalog["usage_limits_enforced"] is False
    assert BILLING_ENABLED is False
    assert CHECKOUT_ENABLED is False
    assert DEFAULT_PLAN_CODE == "free_early_access"


@pytest.mark.parametrize("workspace_type", ["personal", "company"])
def test_free_early_access_unlocks_all_current_core_security_modules(workspace_type):
    catalog = get_public_plan_catalog(workspace_type)
    free = next(plan for plan in catalog["plans"] if plan["code"] == "free_early_access")
    assert free["status"] == "active"
    assert free["price"]["amount_cents"] == 0
    assert free["purchasable"] is False
    assert free["limits_enforced"] is False
    assert free["limit_enforcement_status"] == "planned"
    assert set(free["feature_codes"]) == set(FREE_FEATURE_CODES)
    assert free["limits"]["workspace_type"] == workspace_type


def test_personal_and_company_free_usage_limits_are_different():
    personal = get_public_plan_catalog("personal")["plans"][0]["limits"]
    company = get_public_plan_catalog("company")["plans"][0]["limits"]

    assert personal["max_assets"] == 10
    assert personal["assessments_per_month"] == 20
    assert personal["max_members"] == 1
    assert personal["max_machine_identities"] == 2
    assert personal["evidence_retention_days"] == 30

    assert company["max_assets"] == 25
    assert company["assessments_per_month"] == 50
    assert company["max_members"] == 5
    assert company["max_machine_identities"] == 3
    assert company["evidence_retention_days"] == 30


def test_future_paid_plans_are_visible_as_previews_but_never_purchasable():
    catalog = get_public_plan_catalog()
    previews = {
        plan["code"]: plan for plan in catalog["plans"] if plan["code"] != "free_early_access"
    }

    assert set(previews) == {"pro", "team", "business", "enterprise"}
    assert previews["pro"]["price"]["amount_cents"] == 2900
    assert previews["team"]["price"]["amount_cents"] == 9900
    assert previews["business"]["price"]["amount_cents"] == 29900
    assert previews["enterprise"]["price"]["amount_cents"] is None

    for plan in previews.values():
        assert plan["status"] == "preview"
        assert plan["purchasable"] is False
        assert plan["checkout_enabled"] is False


def test_invalid_workspace_type_is_rejected():
    with pytest.raises(ValueError, match="workspace_type"):
        get_public_plan_catalog("government")


def test_returned_catalog_cannot_mutate_the_shared_plan_definitions():
    first = get_public_plan_catalog("personal")
    first["plans"][0]["feature_codes"].clear()
    first["plans"][0]["limits"]["max_assets"] = 0

    second = get_public_plan_catalog("personal")
    free = next(plan for plan in second["plans"] if plan["code"] == "free_early_access")
    assert set(free["feature_codes"]) == set(FREE_FEATURE_CODES)
    assert free["limits"]["max_assets"] == 10
