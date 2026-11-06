import hashlib
import hmac
import json
import re
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Assessment, AuditEvent
from app.services.audit import verify_audit_chain

_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_FORMAT = "sentinel.assessment.evidence.v1"


def _utc_iso(value: datetime) -> str:
    normalized = value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
    return normalized.isoformat()


def assessment_evidence_digest(assessment: Assessment) -> str:
    """Return a deterministic SHA-256 digest of the complete persisted assessment snapshot."""
    payload = {
        "format": _FORMAT,
        "assessment_id": assessment.id,
        "asset_id": assessment.asset_id,
        "target": assessment.target,
        "status": assessment.status,
        "score": assessment.score,
        "risk_level": assessment.risk_level,
        "findings": assessment.findings,
        "evidence": assessment.evidence,
        "created_at": _utc_iso(assessment.created_at),
    }
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _event_fields(details: str | None) -> dict[str, str]:
    if not isinstance(details, str):
        return {}
    fields: dict[str, str] = {}
    for token in details.split(";"):
        key, separator, value = token.strip().partition("=")
        if separator and key:
            fields[key] = value
    return fields


def verify_assessment_evidence(db: Session, assessment: Assessment) -> dict:
    """Compare the live assessment snapshot with its digest anchored in the audit chain."""
    events = db.scalars(
        select(AuditEvent)
        .where(
            AuditEvent.event_type == "assessment.completed",
            AuditEvent.subject == assessment.target,
        )
        .order_by(AuditEvent.sequence_no.asc().nullsfirst(), AuditEvent.created_at.asc())
    ).all()
    matching = [
        event
        for event in events
        if _event_fields(event.details).get("assessment_id") == assessment.id
    ]
    if len(matching) != 1:
        duplicate = bool(matching)
        chain = verify_audit_chain(db)
        return {
            "format": "sentinel.assessment.evidence-integrity.v1",
            "assessment_id": assessment.id,
            "integrity_valid": False,
            "verification_status": (
                "invalid" if duplicate or chain["verification_status"] == "invalid"
                else "incomplete_legacy"
            ),
            "payload_digest_matches": False,
            "audit_chain_valid": bool(chain["integrity_valid"]),
            "audit_chain_status": chain["verification_status"],
            "evidence_sha256": None,
            "computed_sha256": None,
            "audit_event_id": None,
            "audit_sequence_no": None,
            "audit_event_hash": None,
            "errors": [
                "Multiple assessment.completed audit events reference this assessment."
                if duplicate
                else "No unique assessment.completed audit event is available for this assessment.",
                *chain["errors"],
            ][:50],
            "assurance_note": (
                "The digest is an integrity anchor, not proof against a privileged database "
                "operator who can rewrite the assessment and the complete audit chain. Preserve "
                "offline signed audit checkpoints in independently controlled storage."
            ),
        }

    event = matching[0]
    fields = _event_fields(event.details)
    expected_digest = fields.get("evidence_sha256")
    if expected_digest is None:
        chain = verify_audit_chain(db, through_sequence=event.sequence_no)
        return {
            "format": "sentinel.assessment.evidence-integrity.v1",
            "assessment_id": assessment.id,
            "integrity_valid": False,
            "verification_status": (
                "invalid" if chain["verification_status"] == "invalid" else "incomplete_legacy"
            ),
            "payload_digest_matches": False,
            "audit_chain_valid": bool(chain["integrity_valid"]),
            "audit_chain_status": chain["verification_status"],
            "evidence_sha256": None,
            "computed_sha256": None,
            "audit_event_id": event.id,
            "audit_sequence_no": event.sequence_no,
            "audit_event_hash": event.event_hash,
            "errors": [
                "This assessment predates evidence-digest anchoring.",
                *chain["errors"],
            ][:50],
            "assurance_note": (
                "Legacy assessment evidence is not retroactively marked as verified. Preserve "
                "offline signed audit checkpoints in independently controlled storage."
            ),
        }
    if not _DIGEST_PATTERN.fullmatch(expected_digest):
        chain = verify_audit_chain(db, through_sequence=event.sequence_no)
        return {
            "format": "sentinel.assessment.evidence-integrity.v1",
            "assessment_id": assessment.id,
            "integrity_valid": False,
            "verification_status": "invalid",
            "payload_digest_matches": False,
            "audit_chain_valid": bool(chain["integrity_valid"]),
            "audit_chain_status": chain["verification_status"],
            "evidence_sha256": expected_digest,
            "computed_sha256": None,
            "audit_event_id": event.id,
            "audit_sequence_no": event.sequence_no,
            "audit_event_hash": event.event_hash,
            "errors": [
                "The audit event contains a malformed assessment evidence digest.",
                *chain["errors"],
            ][:50],
            "assurance_note": (
                "The digest is an integrity anchor, not proof against a privileged database "
                "operator who can rewrite the assessment and the complete audit chain."
            ),
        }

    try:
        computed_digest = assessment_evidence_digest(assessment)
    except (TypeError, ValueError):
        computed_digest = None
    digest_matches = computed_digest is not None and hmac.compare_digest(
        expected_digest, computed_digest
    )
    chain = verify_audit_chain(db, through_sequence=event.sequence_no)
    chain_valid = bool(chain["integrity_valid"])
    errors = list(chain["errors"])
    if computed_digest is None:
        errors.append("The current assessment snapshot cannot be canonically serialized.")
    elif not digest_matches:
        errors.append("The current assessment snapshot does not match its anchored SHA-256 digest.")

    if not digest_matches or chain["verification_status"] == "invalid":
        verification_status = "invalid"
    elif chain_valid and chain["verification_status"] == "verified":
        verification_status = "verified"
    else:
        verification_status = "incomplete_legacy"

    return {
        "format": "sentinel.assessment.evidence-integrity.v1",
        "assessment_id": assessment.id,
        "integrity_valid": chain_valid and digest_matches,
        "verification_status": verification_status,
        "payload_digest_matches": digest_matches,
        "audit_chain_valid": chain_valid,
        "audit_chain_status": chain["verification_status"],
        "evidence_sha256": expected_digest,
        "computed_sha256": computed_digest,
        "audit_event_id": event.id,
        "audit_sequence_no": event.sequence_no,
        "audit_event_hash": event.event_hash,
        "verified_until": chain["verified_until"],
        "errors": errors[:50],
        "assurance_note": (
            "This verifies the current assessment snapshot against its hash-linked completion "
            "event. A privileged database operator may still rewrite both the snapshot and the "
            "complete journal; retain offline signed audit checkpoints independently."
        ),
    }
