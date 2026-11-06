import hashlib
import json
import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

os.environ["SENTINEL_API_KEY"] = "S" * 40
os.environ["SENTINEL_ALLOWED_DOMAINS"] = "example.com"
os.environ["SENTINEL_DATABASE_URL"] = f"sqlite:///./sentinel_api_tests_{uuid4().hex}.db"
os.environ["SENTINEL_CORS_ORIGINS"] = "http://localhost:5173"

from fastapi.testclient import TestClient

from app.auth import ROUTE_PERMISSIONS, require_api_key
from app.database import SessionLocal
from app.main import _persist_assessment, app, settings
from app.models import ApiCredential, Assessment, RemediationTask

API_HEADERS = {"X-API-Key": "S" * 40}


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as test_client:
        yield test_client


def _asset_payload(hostname="app.example.com"):
    return {
        "hostname": hostname,
        "name": "Customer Portal",
        "owner": "Platform Security",
        "environment": "production",
        "criticality": 1.4,
        "authorization_expires_at": (datetime.now(UTC) + timedelta(days=30)).isoformat(),
        "authorization_reference": "CHANGE-SEC-2048",
        "tags": ["internet-facing", "tier-1"],
    }


def test_health_endpoint_is_public_and_returns_security_headers(client):
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.json()["version"] == "0.7.0-pre"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert len(response.headers["x-request-id"]) == 32


def test_readiness_endpoint_checks_database_connection(client):
    response = client.get("/readyz")
    assert response.status_code == 200
    assert response.json() == {"status": "ready", "database": "reachable"}


def test_protected_config_rejects_missing_api_key(client):
    response = client.get("/api/v1/config")
    assert response.status_code == 401


def test_protected_config_returns_security_features(client):
    response = client.get("/api/v1/config", headers=API_HEADERS)
    assert response.status_code == 200
    assert response.json()["authorized_domains"] == ["example.com"]
    assert "dns-pinned-https-headers" in response.json()["features"]
    assert "asset-inventory" in response.json()["features"]


def test_assessment_rejects_target_outside_scope_before_network_access(client):
    response = client.post(
        "/api/v1/assessments",
        headers=API_HEADERS,
        json={"domain": "outside.invalid"},
    )
    assert response.status_code == 403
    assert "authorized domain scope" in response.json()["detail"]


def test_asset_registry_requires_allowlisted_hostname_and_time_bounded_authorization(client):
    outside = client.post(
        "/api/v1/assets", headers=API_HEADERS, json=_asset_payload("outside.invalid")
    )
    assert outside.status_code == 403

    expired = _asset_payload()
    expired["authorization_expires_at"] = (datetime.now(UTC) - timedelta(days=1)).isoformat()
    rejected = client.post("/api/v1/assets", headers=API_HEADERS, json=expired)
    assert rejected.status_code == 422

    created = client.post("/api/v1/assets", headers=API_HEADERS, json=_asset_payload())
    assert created.status_code == 201
    asset = created.json()
    assert asset["hostname"] == "app.example.com"
    assert asset["criticality"] == 1.4
    assert asset["authorization_reference"] == "CHANGE-SEC-2048"

    duplicate = client.post("/api/v1/assets", headers=API_HEADERS, json=_asset_payload())
    assert duplicate.status_code == 409

    listed = client.get("/api/v1/assets", headers=API_HEADERS)
    assert listed.status_code == 200
    assert any(item["id"] == asset["id"] for item in listed.json())


def test_registered_asset_assessment_uses_criticality_and_records_asset_link(client, monkeypatch):
    created = client.post(
        "/api/v1/assets", headers=API_HEADERS, json=_asset_payload("api.example.com")
    )
    assert created.status_code == 201
    asset = created.json()

    async def fake_assess_domain(domain, allowed_domains, timeout=8.0, context=None):
        assert domain == "api.example.com"
        assert context["asset_criticality"] == 1.4
        return {
            "target": domain,
            "status": "completed",
            "score": 55,
            "risk_level": "moderate",
            "counts": {"critical": 0, "high": 0, "medium": 1, "low": 0, "info": 0},
            "risk_explanation": {
                "model": "sentinel-exponential-v2",
                "unique_findings": 1,
                "drivers": [],
            },
            "findings": [
                {
                    "code": "MISSING_CSP",
                    "title": "Content Security Policy is not present",
                    "severity": "medium",
                    "category": "web-security",
                    "description": "No CSP header.",
                    "recommendation": "Deploy a restrictive CSP.",
                }
            ],
            "evidence": {"web": {}, "tls": {}, "dns": {}, "assessment_context": context},
        }

    monkeypatch.setattr("app.main.assess_domain", fake_assess_domain)
    response = client.post(f"/api/v1/assets/{asset['id']}/assessments", headers=API_HEADERS)
    assert response.status_code == 200
    assert response.json()["asset_id"] == asset["id"]
    assert response.json()["target"] == "api.example.com"


def test_remediation_workflow_requires_real_finding_and_tracks_status(client):
    db = SessionLocal()
    try:
        assessment = Assessment(
            target="app.example.com",
            status="completed",
            score=45,
            risk_level="moderate",
            findings=[
                {
                    "code": "MISSING_CSP",
                    "title": "Content Security Policy is not present",
                    "severity": "medium",
                    "category": "web-security",
                    "description": "No CSP header.",
                    "recommendation": "Deploy a restrictive CSP.",
                }
            ],
            evidence={},
        )
        db.add(assessment)
        db.commit()
        assessment_id = assessment.id
    finally:
        db.close()

    invalid = client.post(
        "/api/v1/remediations",
        headers=API_HEADERS,
        json={"assessment_id": assessment_id, "finding_code": "NOT_A_REAL_FINDING"},
    )
    assert invalid.status_code == 404

    created = client.post(
        "/api/v1/remediations",
        headers=API_HEADERS,
        json={
            "assessment_id": assessment_id,
            "finding_code": "MISSING_CSP",
            "assignee": "Web Platform",
            "notes": "Create report-only policy, then enforce after validation.",
        },
    )
    assert created.status_code == 201
    task = created.json()
    assert task["status"] == "open"
    assert task["severity"] == "medium"

    updated = client.patch(
        f"/api/v1/remediations/{task['id']}",
        headers=API_HEADERS,
        json={"status": "in_progress", "assignee": "AppSec"},
    )
    assert updated.status_code == 200
    assert updated.json()["status"] == "in_progress"
    assert updated.json()["assignee"] == "AppSec"


def test_audit_hash_chain_and_control_mapping_are_exposed(client):
    integrity = client.get("/api/v1/audit/integrity", headers=API_HEADERS)
    assert integrity.status_code == 200
    assert integrity.json()["integrity_valid"] is True
    assert integrity.json()["sealed_events"] >= 1

    controls = client.get("/api/v1/controls", headers=API_HEADERS)
    assert controls.status_code == 200
    assert len(controls.json()["controls"]) >= 4
    web = next(item for item in controls.json()["controls"] if item["id"] == "SNT-WEB-01")
    assert "MISSING_CSP" in web["matched_findings"]


def test_secret_scanner_api_redacts_values_and_never_persists_source(client):
    token = "ghp_" + "A" * 35
    response = client.post(
        "/api/v1/secrets/scan",
        headers=API_HEADERS,
        json={"content": f"SECRET_TOKEN={token}"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["source_persisted"] is False
    assert payload["finding_count"] == 1
    assert token not in response.text
    assert "[REDACTED]" in response.text

    events = client.get("/api/v1/audit?limit=20", headers=API_HEADERS).json()
    event = next(item for item in events if item["event_type"] == "secrets.scan")
    assert token not in event["details"]
    assert "source_persisted=false" in event["details"]


def test_authenticated_csv_exports_are_bounded_and_audited(client):
    response = client.get("/api/v1/exports/assets.csv", headers=API_HEADERS)
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    assert 'attachment; filename="sentinel-assets.csv"' in response.headers["content-disposition"]
    assert "hostname" in response.text
    events = client.get("/api/v1/audit?limit=20", headers=API_HEADERS).json()
    assert any(item["event_type"] == "data.exported" for item in events)


def test_csv_export_rejects_unknown_dataset_and_missing_key(client):
    unknown = client.get("/api/v1/exports/arbitrary.csv", headers=API_HEADERS)
    assert unknown.status_code == 404
    denied = client.get("/api/v1/exports/assets.csv")
    assert denied.status_code == 401


def test_assessment_retention_preserves_records_referenced_by_remediation(client):
    db = SessionLocal()
    try:
        old_assessment = Assessment(
            target=f"retained-{uuid4().hex[:8]}.example.com",
            status="completed",
            score=72,
            risk_level="high",
            findings=[
                {
                    "code": "MISSING_CSP",
                    "title": "Content Security Policy is not present",
                    "severity": "medium",
                    "category": "web-security",
                    "description": "No CSP header.",
                    "recommendation": "Deploy a restrictive CSP.",
                }
            ],
            evidence={},
        )
        db.add(old_assessment)
        db.flush()
        task = RemediationTask(
            assessment_id=old_assessment.id,
            finding_code="MISSING_CSP",
            title="Content Security Policy is not present",
            severity="medium",
            assignee="AppSec",
            status="in_progress",
            notes="Preserve this operational record.",
        )
        db.add(task)
        db.commit()
        assessment_id = old_assessment.id
        task_id = task.id

        previous_limit = settings.max_assessment_records
        settings.max_assessment_records = 1
        try:
            _persist_assessment(
                db,
                {
                    "target": "new.example.com",
                    "status": "completed",
                    "score": 5,
                    "risk_level": "low",
                    "findings": [],
                    "evidence": {},
                    "risk_explanation": {"model": "sentinel-exponential-v2", "drivers": []},
                },
            )
        finally:
            settings.max_assessment_records = previous_limit

        assert db.get(Assessment, assessment_id) is not None
        assert db.get(RemediationTask, task_id) is not None
    finally:
        db.close()


def test_assessment_job_api_is_idempotent_and_exposes_lifecycle(client):
    asset_response = client.post(
        "/api/v1/assets",
        headers=API_HEADERS,
        json=_asset_payload("jobs.example.com"),
    )
    assert asset_response.status_code == 201
    asset_id = asset_response.json()["id"]
    headers = {**API_HEADERS, "Idempotency-Key": "job-request-2026-0001"}

    created = client.post(
        "/api/v1/assessment-jobs",
        headers=headers,
        json={"asset_id": asset_id},
    )
    assert created.status_code == 202
    job = created.json()
    assert job["status"] == "queued"
    assert job["asset_id"] == asset_id
    assert job["target"] == "jobs.example.com"
    assert job["attempts"] == 0
    assert "idempotency_key_hash" not in job

    repeated = client.post(
        "/api/v1/assessment-jobs",
        headers=headers,
        json={"asset_id": asset_id},
    )
    assert repeated.status_code == 200
    assert repeated.json()["id"] == job["id"]

    listed = client.get("/api/v1/assessment-jobs?status=queued", headers=API_HEADERS)
    assert listed.status_code == 200
    assert sum(item["id"] == job["id"] for item in listed.json()) == 1

    detail = client.get(f"/api/v1/assessment-jobs/{job['id']}", headers=API_HEADERS)
    assert detail.status_code == 200
    assert detail.json()["target"] == "jobs.example.com"

    events = client.get("/api/v1/audit?limit=50", headers=API_HEADERS).json()
    matching = [
        item
        for item in events
        if item["event_type"] == "assessment.job.queued"
        and f"job_id={job['id']}" in item["details"]
    ]
    assert len(matching) == 1


def test_assessment_job_api_rejects_unknown_and_unauthorized_assets(client):
    missing = client.post(
        "/api/v1/assessment-jobs",
        headers=API_HEADERS,
        json={"asset_id": "00000000-0000-0000-0000-000000000000"},
    )
    assert missing.status_code == 404

    created = client.post(
        "/api/v1/assets",
        headers=API_HEADERS,
        json=_asset_payload("paused-jobs.example.com"),
    )
    assert created.status_code == 201
    asset_id = created.json()["id"]
    paused = client.patch(
        f"/api/v1/assets/{asset_id}",
        headers=API_HEADERS,
        json={"status": "paused"},
    )
    assert paused.status_code == 200

    rejected = client.post(
        "/api/v1/assessment-jobs",
        headers=API_HEADERS,
        json={"asset_id": asset_id},
    )
    assert rejected.status_code == 409

    denied = client.post(
        "/api/v1/assessment-jobs",
        json={"asset_id": asset_id},
    )
    assert denied.status_code == 401


def test_assessment_job_api_validates_schedule_and_idempotency_header(client):
    created = client.post(
        "/api/v1/assets",
        headers=API_HEADERS,
        json=_asset_payload("scheduled-jobs.example.com"),
    )
    assert created.status_code == 201
    asset_id = created.json()["id"]

    naive = client.post(
        "/api/v1/assessment-jobs",
        headers=API_HEADERS,
        json={"asset_id": asset_id, "scheduled_for": "2026-11-07T12:00:00"},
    )
    assert naive.status_code == 422

    too_far = client.post(
        "/api/v1/assessment-jobs",
        headers=API_HEADERS,
        json={
            "asset_id": asset_id,
            "scheduled_for": (datetime.now(UTC) + timedelta(days=31)).isoformat(),
        },
    )
    assert too_far.status_code == 422

    invalid_key = client.post(
        "/api/v1/assessment-jobs",
        headers={**API_HEADERS, "Idempotency-Key": "bad"},
        json={"asset_id": asset_id},
    )
    assert invalid_key.status_code == 422


def test_assessment_job_api_cancels_queued_job_and_rejects_retry(client):
    created = client.post(
        "/api/v1/assets",
        headers=API_HEADERS,
        json=_asset_payload("cancel-jobs.example.com"),
    )
    assert created.status_code == 201
    job = client.post(
        "/api/v1/assessment-jobs",
        headers=API_HEADERS,
        json={"asset_id": created.json()["id"]},
    )
    assert job.status_code == 202

    cancelled = client.post(
        f"/api/v1/assessment-jobs/{job.json()['id']}/cancel",
        headers=API_HEADERS,
    )
    assert cancelled.status_code == 200
    assert cancelled.json()["status"] == "cancelled"

    retry = client.post(
        f"/api/v1/assessment-jobs/{job.json()['id']}/retry",
        headers=API_HEADERS,
    )
    assert retry.status_code == 409


def test_role_scoped_environment_credentials_enforce_route_permissions(client, monkeypatch):
    analyst_key = "A" * 40
    monkeypatch.setattr(
        settings,
        "api_credentials_json",
        json.dumps([{"id": "analyst-ci", "key": analyst_key, "role": "analyst"}]),
    )
    analyst_headers = {"X-API-Key": analyst_key}

    identity = client.get("/api/v1/me", headers=analyst_headers)
    assert identity.status_code == 200
    assert identity.json()["role"] == "analyst"
    assert identity.json()["credential_source"] == "environment"

    assets = client.get("/api/v1/assets", headers=analyst_headers)
    assert assets.status_code == 200

    denied_write = client.post(
        "/api/v1/assets",
        headers=analyst_headers,
        json=_asset_payload("analyst-denied.example.com"),
    )
    assert denied_write.status_code == 403

    denied_admin = client.get("/api/v1/credentials", headers=analyst_headers)
    assert denied_admin.status_code == 403


def test_managed_api_credential_is_hash_only_one_time_and_revocable(client):
    created = client.post(
        "/api/v1/credentials",
        headers=API_HEADERS,
        json={"label": "Read-only integration", "role": "read_only"},
    )
    assert created.status_code == 201
    assert created.headers["cache-control"] == "no-store"
    assert created.headers["pragma"] == "no-cache"

    payload = created.json()
    secret = payload["secret"]
    credential = payload["credential"]
    assert len(secret) >= 60
    assert credential["role"] == "read_only"
    assert credential["key_prefix"] == secret[:12]
    assert "key_hash" not in created.text

    db = SessionLocal()
    try:
        stored = db.get(ApiCredential, credential["id"])
        assert stored is not None
        assert stored.key_hash == hashlib.sha256(secret.encode("utf-8")).hexdigest()
        assert secret not in stored.key_hash
    finally:
        db.close()

    listed = client.get("/api/v1/credentials", headers=API_HEADERS)
    assert listed.status_code == 200
    listed_item = next(item for item in listed.json() if item["id"] == credential["id"])
    assert secret not in listed.text
    assert "key_hash" not in listed.text
    assert listed_item["role"] == "read_only"

    managed_headers = {"X-API-Key": secret}
    identity = client.get("/api/v1/me", headers=managed_headers)
    assert identity.status_code == 200
    assert identity.json()["credential_source"] == "database"
    assert identity.json()["credential_id"] == credential["id"]

    read_allowed = client.get("/api/v1/assets", headers=managed_headers)
    assert read_allowed.status_code == 200
    write_denied = client.post(
        "/api/v1/assets",
        headers=managed_headers,
        json=_asset_payload("managed-readonly-denied.example.com"),
    )
    assert write_denied.status_code == 403

    db = SessionLocal()
    try:
        stored = db.get(ApiCredential, credential["id"])
        assert stored.last_used_at is not None
    finally:
        db.close()

    revoked = client.post(
        f"/api/v1/credentials/{credential['id']}/revoke",
        headers=API_HEADERS,
    )
    assert revoked.status_code == 200
    assert revoked.json()["status"] == "revoked"

    rejected = client.get("/api/v1/me", headers=managed_headers)
    assert rejected.status_code == 401

    events = client.get("/api/v1/audit?limit=50", headers=API_HEADERS).json()
    related = [event for event in events if credential["id"] in event["details"]]
    assert any(event["event_type"] == "api_credential.created" for event in related)
    assert any(event["event_type"] == "api_credential.revoked" for event in related)
    assert all(secret not in event["details"] for event in events)


def test_managed_admin_credential_cannot_revoke_itself(client):
    created = client.post(
        "/api/v1/credentials",
        headers=API_HEADERS,
        json={"label": "Break-glass admin", "role": "admin"},
    )
    assert created.status_code == 201
    credential = created.json()["credential"]
    managed_headers = {"X-API-Key": created.json()["secret"]}

    self_revoke = client.post(
        f"/api/v1/credentials/{credential['id']}/revoke",
        headers=managed_headers,
    )
    assert self_revoke.status_code == 409

    admin_revoke = client.post(
        f"/api/v1/credentials/{credential['id']}/revoke",
        headers=API_HEADERS,
    )
    assert admin_revoke.status_code == 200

    revoked_key = client.get("/api/v1/me", headers=managed_headers)
    assert revoked_key.status_code == 401


def test_every_versioned_api_route_has_explicit_authentication_and_permission_policy():
    for route in app.routes:
        route_path = getattr(route, "path", "")
        if not route_path.startswith("/api/v1/"):
            continue
        assert any(
            dependency.call is require_api_key for dependency in route.dependant.dependencies
        ), f"Missing authentication dependency: {route_path}"
        for method in route.methods or set():
            assert (method, route_path) in ROUTE_PERMISSIONS, (
                f"Missing role permission mapping: {method} {route_path}"
            )


def test_managed_credential_expiry_blocks_authentication(client):
    created = client.post(
        "/api/v1/credentials",
        headers=API_HEADERS,
        json={"label": "Short lived monitor", "role": "read_only"},
    )
    assert created.status_code == 201
    payload = created.json()
    key = payload["secret"]
    credential_id = payload["credential"]["id"]

    db = SessionLocal()
    try:
        stored = db.get(ApiCredential, credential_id)
        stored.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        db.commit()
    finally:
        db.close()

    rejected = client.get("/api/v1/me", headers={"X-API-Key": key})
    assert rejected.status_code == 401
