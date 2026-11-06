import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts.assessment_attestation import build_signed_attestation


def response():
    return {
        "format": "sentinel.assessment.evidence-integrity.v1",
        "assessment_id": "assessment-123",
        "integrity_valid": True,
        "verification_status": "verified",
        "payload_digest_matches": True,
        "audit_chain_valid": True,
        "audit_chain_status": "verified",
        "evidence_sha256": "a" * 64,
        "computed_sha256": "a" * 64,
        "audit_event_id": "event-456",
        "audit_sequence_no": 17,
        "audit_event_hash": "b" * 64,
    }


def test_signer_rejects_unexpected_response_format():
    item = response()
    item["format"] = "sentinel.other.v1"
    with pytest.raises(ValueError, match="format"):
        build_signed_attestation(item, Ed25519PrivateKey.generate())


def test_signer_rejects_mismatched_computed_digest():
    item = response()
    item["computed_sha256"] = "c" * 64
    with pytest.raises(ValueError, match="computed_sha256"):
        build_signed_attestation(item, Ed25519PrivateKey.generate())
