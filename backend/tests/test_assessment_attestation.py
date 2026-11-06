import copy

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts.assessment_attestation import build_signed_attestation, verify_signed_attestation


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


def test_round_trip_and_current_anchor():
    key = Ed25519PrivateKey.generate()
    current = response()
    envelope = build_signed_attestation(current, key, signed_at="2026-11-06T12:00:00Z")
    verified = verify_signed_attestation(envelope, key.public_key(), current)
    assert verified["assessment_id"] == "assessment-123"
    assert verified["audit_sequence_no"] == 17


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("integrity_valid", False),
        ("verification_status", "incomplete_legacy"),
        ("payload_digest_matches", False),
        ("audit_chain_valid", False),
        ("audit_chain_status", "invalid"),
    ],
)
def test_signing_refuses_unverified_states(field, value):
    item = response()
    item[field] = value
    with pytest.raises(ValueError, match="Refusing to sign"):
        build_signed_attestation(item, Ed25519PrivateKey.generate())


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("evidence_sha256", "bad"),
        ("audit_event_hash", "F" * 64),
        ("audit_sequence_no", True),
        ("assessment_id", ""),
        ("audit_event_id", None),
    ],
)
def test_signing_rejects_malformed_anchor(field, value):
    item = response()
    item[field] = value
    with pytest.raises(ValueError):
        build_signed_attestation(item, Ed25519PrivateKey.generate())


def test_tampered_payload_is_rejected():
    key = Ed25519PrivateKey.generate()
    signed = build_signed_attestation(response(), key)
    tampered = copy.deepcopy(signed)
    tampered["payload"]["evidence_sha256"] = "c" * 64
    with pytest.raises(ValueError, match="signature verification failed"):
        verify_signed_attestation(tampered, key.public_key())


def test_wrong_public_key_is_rejected():
    key = Ed25519PrivateKey.generate()
    signed = build_signed_attestation(response(), key)
    with pytest.raises(ValueError, match="does not match"):
        verify_signed_attestation(signed, Ed25519PrivateKey.generate().public_key())


def test_current_anchor_mismatch_is_rejected():
    key = Ed25519PrivateKey.generate()
    signed = build_signed_attestation(response(), key)
    changed = response()
    changed["evidence_sha256"] = "c" * 64
    changed["computed_sha256"] = "c" * 64
    with pytest.raises(ValueError, match="does not match the signed"):
        verify_signed_attestation(signed, key.public_key(), changed)


def test_naive_timestamp_is_rejected():
    with pytest.raises(ValueError, match="timezone"):
        build_signed_attestation(
            response(), Ed25519PrivateKey.generate(), signed_at="2026-11-06T12:00:00"
        )


def test_extra_envelope_field_is_rejected():
    key = Ed25519PrivateKey.generate()
    signed = build_signed_attestation(response(), key)
    signed["unexpected"] = True
    with pytest.raises(ValueError, match="unsupported or incomplete schema"):
        verify_signed_attestation(signed, key.public_key())
