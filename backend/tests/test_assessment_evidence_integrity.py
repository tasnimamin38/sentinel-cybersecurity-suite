from datetime import UTC, datetime
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.auth import ROUTE_PERMISSIONS, require_api_key
from app.database import Base, get_db
from app.models import Assessment, AuditEvent
from app.routes.assessment_evidence import router
from app.services.assessment_integrity import (
    assessment_evidence_digest,
    verify_assessment_evidence,
)
from app.services.assessment_store import add_assessment_result
from app.services.audit import record_audit_event


@pytest.fixture
def db_session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    try:
        with Session(engine, expire_on_commit=False) as db:
            yield db
    finally:
        engine.dispose()


def _new_assessment(db: Session, *, target: str | None = None) -> Assessment:
    item = Assessment(
        id=str(uuid4()),
        target=target or f"{uuid4().hex[:12]}.example.com",
        status="completed",
        score=37,
        risk_level="moderate",
        findings=[
            {
                "code": "MISSING_CSP",
                "severity": "medium",
                "title": "Content Security Policy is missing",
            }
        ],
        evidence={
            "web": {"status_code": 200, "headers": {"server": "example"}},
            "risk_explanation": {"model": "sentinel-exponential-v2", "drivers": []},
        },
        created_at=datetime(2026, 11, 6, 12, 0, tzinfo=UTC),
    )
    db.add(item)
    db.flush()
    return item


def _add_completion_event(
    db: Session,
    assessment: Assessment,
    *,
    include_digest: bool = True,
    digest: str | None = None,
):
    fields = [f"assessment_id={assessment.id}"]
    if include_digest:
        fields.append(f"evidence_sha256={digest or assessment_evidence_digest(assessment)}")
    event = record_audit_event(
        db,
        event_type="assessment.completed",
        subject=assessment.target,
        details="; ".join(fields),
    )
    db.commit()
    db.refresh(assessment)
    db.refresh(event)
    return event


def test_assessment_evidence_digest_is_stable_across_json_key_order():
    first = Assessment(
        id="assessment-stable",
        asset_id="asset-stable",
        target="app.example.com",
        status="completed",
        score=10,
        risk_level="low",
        findings=[{"a": 1, "b": 2}],
        evidence={"web": {"x": 1, "y": 2}},
        created_at=datetime(2026, 11, 6, 12, 0, tzinfo=UTC),
    )
    second = Assessment(
        id="assessment-stable",
        asset_id="asset-stable",
        target="app.example.com",
        status="completed",
        score=10,
        risk_level="low",
        findings=[{"b": 2, "a": 1}],
        evidence={"web": {"y": 2, "x": 1}},
        created_at=datetime(2026, 11, 6, 12, 0, tzinfo=UTC),
    )

    assert assessment_evidence_digest(first) == assessment_evidence_digest(second)


def test_assessment_persistence_anchors_digest_in_same_audit_transaction(db_session):
    result = {
        "target": "persisted.example.com",
        "status": "completed",
        "score": 21,
        "risk_level": "low",
        "findings": [{"code": "MISSING_CSP", "severity": "low"}],
        "evidence": {"web": {"status_code": 200}},
        "risk_explanation": {"model": "sentinel-exponential-v2", "drivers": []},
    }

    assessment = add_assessment_result(
        db_session,
        result,
        asset=None,
        max_records=100,
    )
    db_session.commit()
    db_session.refresh(assessment)

    event = db_session.scalar(
        select(AuditEvent).where(
            AuditEvent.event_type == "assessment.completed",
            AuditEvent.subject == assessment.target,
        )
    )
    assert event is not None
    assert f"assessment_id={assessment.id}" in event.details
    assert f"evidence_sha256={assessment_evidence_digest(assessment)}" in event.details

    verification = verify_assessment_evidence(db_session, assessment)
    assert verification["integrity_valid"] is True
    assert verification["verification_status"] == "verified"


def test_assessment_and_digest_event_roll_back_as_one_transaction(db_session):
    result = {
        "target": "rollback.example.com",
        "status": "completed",
        "score": 10,
        "risk_level": "low",
        "findings": [],
        "evidence": {"web": {}},
        "risk_explanation": {"model": "sentinel-exponential-v2", "drivers": []},
    }

    assessment = add_assessment_result(
        db_session,
        result,
        asset=None,
        max_records=100,
    )
    assessment_id = assessment.id
    db_session.rollback()

    assert db_session.get(Assessment, assessment_id) is None
    events = db_session.scalars(
        select(AuditEvent).where(
            AuditEvent.event_type == "assessment.completed",
            AuditEvent.subject == result["target"],
        )
    ).all()
    assert events == []


def test_valid_assessment_snapshot_and_audit_anchor_verify(db_session):
    assessment = _new_assessment(db_session)
    event = _add_completion_event(db_session, assessment)

    result = verify_assessment_evidence(db_session, assessment)

    assert result["integrity_valid"] is True
    assert result["verification_status"] == "verified"
    assert result["payload_digest_matches"] is True
    assert result["audit_chain_valid"] is True
    assert result["audit_event_id"] == event.id
    assert result["evidence_sha256"] == assessment_evidence_digest(assessment)


@pytest.mark.parametrize("field", ["findings", "evidence", "score", "risk_level", "status"])
def test_assessment_payload_tampering_is_detected_without_breaking_audit_chain(
    db_session,
    field,
):
    assessment = _new_assessment(db_session)
    _add_completion_event(db_session, assessment)
    if field == "findings":
        assessment.findings = [{**assessment.findings[0], "title": "tampered finding"}]
    elif field == "evidence":
        assessment.evidence = {
            **assessment.evidence,
            "web": {"status_code": 200, "headers": {"server": "tampered"}},
        }
    elif field == "score":
        assessment.score = 99
    elif field == "risk_level":
        assessment.risk_level = "critical"
    else:
        assessment.status = "failed"
    db_session.commit()
    db_session.refresh(assessment)

    result = verify_assessment_evidence(db_session, assessment)

    assert result["integrity_valid"] is False
    assert result["verification_status"] == "invalid"
    assert result["payload_digest_matches"] is False
    assert result["audit_chain_valid"] is True
    assert any("snapshot does not match" in error for error in result["errors"])


def test_tampered_audit_event_is_detected(db_session):
    assessment = _new_assessment(db_session)
    event = _add_completion_event(db_session, assessment)
    event.details += "; operator_override=true"
    db_session.commit()

    result = verify_assessment_evidence(db_session, assessment)

    assert result["integrity_valid"] is False
    assert result["verification_status"] == "invalid"
    assert result["payload_digest_matches"] is True
    assert result["audit_chain_valid"] is False
    assert result["audit_chain_status"] == "invalid"


def test_legacy_assessment_reports_missing_digest_without_claiming_verified(db_session):
    assessment = _new_assessment(db_session)
    _add_completion_event(db_session, assessment, include_digest=False)

    result = verify_assessment_evidence(db_session, assessment)

    assert result["integrity_valid"] is False
    assert result["verification_status"] == "incomplete_legacy"
    assert result["payload_digest_matches"] is False
    assert result["audit_chain_valid"] is True
    assert result["audit_chain_status"] == "verified"


def test_missing_completion_event_is_incomplete_legacy(db_session):
    assessment = _new_assessment(db_session)
    db_session.commit()

    result = verify_assessment_evidence(db_session, assessment)

    assert result["integrity_valid"] is False
    assert result["verification_status"] == "incomplete_legacy"
    assert result["audit_chain_valid"] is False
    assert result["audit_chain_status"] == "empty"


def test_duplicate_completion_anchors_are_invalid(db_session):
    assessment = _new_assessment(db_session)
    _add_completion_event(db_session, assessment)
    _add_completion_event(db_session, assessment)

    result = verify_assessment_evidence(db_session, assessment)

    assert result["integrity_valid"] is False
    assert result["verification_status"] == "invalid"
    assert any("Multiple" in error for error in result["errors"])


def test_malformed_digest_is_invalid_even_when_audit_chain_is_valid(db_session):
    assessment = _new_assessment(db_session)
    _add_completion_event(db_session, assessment, digest="not-a-sha256-digest")

    result = verify_assessment_evidence(db_session, assessment)

    assert result["integrity_valid"] is False
    assert result["verification_status"] == "invalid"
    assert result["audit_chain_valid"] is True
    assert any("malformed" in error for error in result["errors"])


def test_evidence_integrity_endpoint_is_authenticated_and_read_only(db_session):
    assessment = _new_assessment(db_session)
    _add_completion_event(db_session, assessment)

    application = FastAPI()
    application.include_router(router)

    def override_db():
        yield db_session

    application.dependency_overrides[get_db] = override_db
    application.dependency_overrides[require_api_key] = lambda: None

    with TestClient(application) as client:
        response = client.get(f"/api/v1/assessments/{assessment.id}/evidence-integrity")
        missing = client.get("/api/v1/assessments/not-present/evidence-integrity")

    assert response.status_code == 200
    assert response.json()["verification_status"] == "verified"
    assert missing.status_code == 404
    assert (
        ROUTE_PERMISSIONS[("GET", "/api/v1/assessments/{assessment_id}/evidence-integrity")]
        == "assessment.read"
    )
