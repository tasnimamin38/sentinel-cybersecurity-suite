import os

import pytest

os.environ["SENTINEL_API_KEY"] = "S" * 40
os.environ["SENTINEL_ALLOWED_DOMAINS"] = "example.com"
os.environ["SENTINEL_DATABASE_URL"] = "sqlite:///./sentinel_api_tests.db"
os.environ["SENTINEL_CORS_ORIGINS"] = "http://localhost:5173"

from fastapi.testclient import TestClient

from app.main import app

API_HEADERS = {"X-API-Key": "S" * 40}


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as test_client:
        yield test_client


def test_health_endpoint_is_public_and_returns_security_headers(client):
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert len(response.headers["x-request-id"]) == 32


def test_readiness_endpoint_checks_database_connection(client):
    response = client.get("/readyz")
    assert response.status_code == 200
    assert response.json() == {"status": "ready", "database": "reachable"}


def test_protected_config_rejects_missing_api_key(client):
    response = client.get("/api/v1/config")
    assert response.status_code == 401


def test_protected_config_returns_only_configured_scope(client):
    response = client.get("/api/v1/config", headers=API_HEADERS)
    assert response.status_code == 200
    assert response.json()["authorized_domains"] == ["example.com"]
    assert "dns-pinned-https-headers" in response.json()["features"]


def test_assessment_rejects_target_outside_scope_before_network_access(client):
    response = client.post(
        "/api/v1/assessments",
        headers=API_HEADERS,
        json={"domain": "outside.invalid"},
    )
    assert response.status_code == 403
    assert "authorized domain scope" in response.json()["detail"]