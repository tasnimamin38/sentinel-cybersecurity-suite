from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts.audit_checkpoint import (
    build_signed_envelope,
    verify_signed_envelope,
)


def _integrity_response(sequence_no=3, event_hash="a" * 64):
    return {
        "integrity_valid": True,
        "verification_status": "verified",
        "checkpoint": {
            "format": "sentinel.audit.checkpoint.v1",
            "sequence_no": sequence_no,
            "event_hash": event_hash,
            "sealed_events": sequence_no,
            "verified_until": "2026-11-06T01:00:00+00:00",
        },
    }


def _public_pem(private_key):
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def test_signed_checkpoint_round_trip_and_current_prefix_match():
    private_key = Ed25519PrivateKey.generate()
    response = _integrity_response()
    envelope = build_signed_envelope(response, private_key)
    public_key = serialization.load_pem_public_key(_public_pem(private_key))

    verified = verify_signed_envelope(envelope, public_key, response)

    assert verified == response["checkpoint"]


def test_signature_rejects_payload_tampering():
    private_key = Ed25519PrivateKey.generate()
    envelope = build_signed_envelope(_integrity_response(), private_key)
    envelope["payload"]["event_hash"] = "b" * 64
    public_key = serialization.load_pem_public_key(_public_pem(private_key))

    try:
        verify_signed_envelope(envelope, public_key)
    except ValueError as exc:
        assert "signature verification failed" in str(exc).lower()
    else:
        raise AssertionError("A modified checkpoint must not verify.")


def test_checkpoint_rejects_a_different_current_journal_prefix():
    private_key = Ed25519PrivateKey.generate()
    envelope = build_signed_envelope(_integrity_response(), private_key)
    public_key = serialization.load_pem_public_key(_public_pem(private_key))
    current = _integrity_response(event_hash="c" * 64)

    try:
        verify_signed_envelope(envelope, public_key, current)
    except ValueError as exc:
        assert "does not match" in str(exc).lower()
    else:
        raise AssertionError("A different journal prefix must not verify.")


def test_wrong_public_key_is_rejected():
    signer = Ed25519PrivateKey.generate()
    other = Ed25519PrivateKey.generate()
    envelope = build_signed_envelope(_integrity_response(), signer)
    public_key = serialization.load_pem_public_key(_public_pem(other))

    try:
        verify_signed_envelope(envelope, public_key)
    except ValueError as exc:
        assert "does not match" in str(exc).lower()
    else:
        raise AssertionError("A different public key must not verify.")


def test_invalid_integrity_response_cannot_be_signed():
    private_key = Ed25519PrivateKey.generate()
    invalid = _integrity_response()
    invalid["integrity_valid"] = False

    try:
        build_signed_envelope(invalid, private_key)
    except ValueError as exc:
        assert "refusing to sign" in str(exc).lower()
    else:
        raise AssertionError("An invalid audit chain must never be signed.")
