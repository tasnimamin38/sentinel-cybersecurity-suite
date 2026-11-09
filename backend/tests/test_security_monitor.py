from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.database import Base
from app.models import AuditEvent, Tenant
from app.services.security_monitor import persist_security_evidence

from app.services.security_monitor import (
    classify_honeypot_path,
    classify_security_response,
    resolve_client_ip,
    sanitize_user_agent,
    sign_alert_payload,
)


def test_honeypot_classifier_detects_common_secret_and_admin_probes():
    assert classify_honeypot_path("/.env") == "sensitive_file_probe"
    assert classify_honeypot_path("/.git/config") == "repository_metadata_probe"
    assert classify_honeypot_path("/.aws/credentials") == "sensitive_file_probe"
    assert classify_honeypot_path("/phpmyadmin/index.php") == "admin_console_probe"
    assert classify_honeypot_path("/actuator/env") == "sensitive_file_probe"


def test_honeypot_classifier_normalizes_case_and_percent_encoded_paths():
    assert classify_honeypot_path("/%2e%65nv") == "sensitive_file_probe"
    assert classify_honeypot_path("/.GIT/HEAD") == "repository_metadata_probe"


def test_honeypot_classifier_does_not_flag_normal_application_routes():
    assert classify_honeypot_path("/") is None
    assert classify_honeypot_path("/api/v1/assets") is None
    assert classify_honeypot_path("/login") is None
    assert classify_honeypot_path("/assets/.env.example") is None


def test_real_ip_is_accepted_only_from_a_configured_trusted_proxy():
    observed = resolve_client_ip(
        peer_ip="172.30.240.12",
        x_real_ip="198.51.100.24",
        trusted_proxy_cidrs=["172.30.240.0/24"],
    )
    assert observed == "198.51.100.24"


def test_untrusted_peer_cannot_spoof_x_real_ip():
    observed = resolve_client_ip(
        peer_ip="198.51.100.8",
        x_real_ip="203.0.113.99",
        trusted_proxy_cidrs=["172.30.240.0/24"],
    )
    assert observed == "198.51.100.8"


def test_missing_or_invalid_proxy_header_falls_back_to_peer_ip():
    missing = resolve_client_ip(
        peer_ip="172.30.240.12",
        x_real_ip=None,
        trusted_proxy_cidrs=["172.30.240.0/24"],
    )
    invalid = resolve_client_ip(
        peer_ip="172.30.240.12",
        x_real_ip="not-an-ip",
        trusted_proxy_cidrs=["172.30.240.0/24"],
    )
    assert missing == "172.30.240.12"
    assert invalid == "172.30.240.12"


def test_user_agent_is_bounded_and_control_characters_are_removed():
    result = sanitize_user_agent("scanner\x00\nagent" + ("x" * 400))
    assert result.startswith("scanneragent")
    assert len(result) <= 256


def test_security_response_classifier_emits_only_known_signal_classes():
    assert classify_security_response("/.env", 404)["event_type"] == "security.honeypot_probe"
    assert classify_security_response("/api/v1/config", 401)["rule_id"] == "API_AUTH_FAILURE"
    assert classify_security_response("/api/v1/assets", 429)["rule_id"] == "API_RATE_LIMIT"
    assert classify_security_response("/api/v1/assets", 200) is None
    assert classify_security_response("/.env", 429) is None


def test_webhook_payload_signature_is_stable_and_verifiable():
    import hashlib
    import hmac

    payload = {"severity": "high", "source_ip": "198.51.100.8", "rule_id": "probe"}
    body, signature = sign_alert_payload(payload, "K" * 40)
    expected = hmac.new(("K" * 40).encode(), body, hashlib.sha256).hexdigest()
    assert signature == "sha256=" + expected


def test_cloudflare_client_ip_is_used_only_when_explicitly_trusted():
    observed = resolve_client_ip(
        peer_ip="172.30.240.12",
        x_real_ip=None,
        trusted_proxy_cidrs=[],
        cf_connecting_ip="198.51.100.24",
        trust_cf_connecting_ip=True,
    )
    assert observed == "198.51.100.24"


def test_cloudflare_client_ip_is_ignored_when_trust_is_disabled():
    observed = resolve_client_ip(
        peer_ip="172.30.240.12",
        x_real_ip=None,
        trusted_proxy_cidrs=[],
        cf_connecting_ip="198.51.100.24",
        trust_cf_connecting_ip=False,
    )
    assert observed == "172.30.240.12"


def test_invalid_cloudflare_client_ip_falls_back_to_peer_ip():
    observed = resolve_client_ip(
        peer_ip="172.30.240.12",
        x_real_ip=None,
        trusted_proxy_cidrs=[],
        cf_connecting_ip="not-an-ip",
        trust_cf_connecting_ip=True,
    )
    assert observed == "172.30.240.12"


def test_authenticated_security_evidence_is_written_to_its_own_tenant():
    tenant_id = "00000000-0000-4000-8000-00000000000d"
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    try:
        with Session(engine) as db:
            db.add(
                Tenant(
                    id=tenant_id,
                    slug="security-company",
                    name="Security Company",
                    workspace_type="company",
                    status="active",
                )
            )
            db.commit()

            persist_security_evidence(
                db,
                signal={
                    "event_type": "security.api_auth_failure",
                    "rule_id": "API_AUTH_FAILURE",
                    "severity": "high",
                },
                source_ip="198.51.100.42",
                path="/api/v1/assets",
                method="GET",
                user_agent="test-agent",
                request_id="tenant-event-test",
                tenant_id=tenant_id,
            )
            db.commit()

            events = db.scalars(select(AuditEvent)).all()
            assert len(events) == 1
            assert events[0].tenant_id == tenant_id
            assert events[0].event_type == "security.api_auth_failure"
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()
