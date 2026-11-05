import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

os.environ["SENTINEL_API_KEY"] = "S" * 40
os.environ["SENTINEL_ALLOWED_DOMAINS"] = "example.com"
os.environ["SENTINEL_DATABASE_URL"] = f"sqlite:///./sentinel_api_tests_{uuid4().hex}.db"
os.environ["SENTINEL_CORS_ORIGINS"] = "http://localhost:5173"

from fastapi.testclient import TestClient

from app.database import SessionLocal
from app.main import app
from app.models import Assessment

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
    assert response.json()["version"] == "0.3.2"
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
