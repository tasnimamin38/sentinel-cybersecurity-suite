from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

try:
    from .audit_checkpoint import _prompt_passphrase, load_json, load_private_key, load_public_key, write_json_new
except ImportError:  # Executed directly as a script from backend/scripts.
    from audit_checkpoint import _prompt_passphrase, load_json, load_private_key, load_public_key, write_json_new

ATTESTATION_FORMAT = "sentinel.assessment.evidence-attestation.v1"
SIGNED_FORMAT = "sentinel.assessment.signed-attestation.v1"
ALGORITHM = "Ed25519"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PAYLOAD_FIELDS = {
    "format", "assessment_id", "evidence_sha256", "audit_event_id",
    "audit_sequence_no", "audit_event_hash", "signed_at",
}
_ENVELOPE_FIELDS = {"format", "algorithm", "key_id", "payload", "signature"}


def canonical_json(value: Any) -> bytes:
    """Return the deterministic UTF-8 representation covered by Ed25519."""
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def _verified_anchor(response: Any) -> dict[str, Any]:
    """Extract an assessment anchor only when both payload and journal are verified."""
    if not isinstance(response, dict):
        raise ValueError("Input must be a SENTINEL assessment evidence-integrity JSON response.")
    if not (
        response.get("integrity_valid") is True
        and response.get("verification_status") == "verified"
        and response.get("payload_digest_matches") is True
        and response.get("audit_chain_valid") is True
        and response.get("audit_chain_status") == "verified"
    ):
        raise ValueError("Refusing to sign: assessment evidence and audit chain must both be verified.")

    assessment_id = response.get("assessment_id")
    event_id = response.get("audit_event_id")
    sequence = response.get("audit_sequence_no")
    digest = response.get("evidence_sha256")
    event_hash = response.get("audit_event_hash")
    if not isinstance(assessment_id, str) or not assessment_id.strip() or len(assessment_id) > 128:
        raise ValueError("assessment_id must be a non-empty string of at most 128 characters.")
    if not isinstance(event_id, str) or not event_id.strip() or len(event_id) > 128:
        raise ValueError("audit_event_id must be a non-empty string of at most 128 characters.")
    if type(sequence) is not int or sequence < 1:
        raise ValueError("audit_sequence_no must be a positive integer.")
    if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
        raise ValueError("evidence_sha256 must be a lowercase SHA-256 digest.")
    if not isinstance(event_hash, str) or not _SHA256.fullmatch(event_hash):
        raise ValueError("audit_event_hash must be a lowercase SHA-256 digest.")
    return {
        "assessment_id": assessment_id,
        "evidence_sha256": digest,
        "audit_event_id": event_id,
        "audit_sequence_no": sequence,
        "audit_event_hash": event_hash,
    }


def _validate_payload(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict) or set(payload) != _PAYLOAD_FIELDS:
        raise ValueError("Attestation payload has an unsupported or incomplete schema.")
    if payload.get("format") != ATTESTATION_FORMAT:
        raise ValueError("Unsupported assessment attestation format.")
    anchor = {
        "integrity_valid": True, "verification_status": "verified",
        "payload_digest_matches": True, "audit_chain_valid": True,
        "audit_chain_status": "verified",
        **{key: payload[key] for key in (
            "assessment_id", "evidence_sha256", "audit_event_id",
            "audit_sequence_no", "audit_event_hash",
        )},
    }
    _verified_anchor(anchor)
    signed_at = payload.get("signed_at")
    if not isinstance(signed_at, str) or not signed_at:
        raise ValueError("signed_at must be a timezone-aware ISO 8601 timestamp.")
    try:
        parsed = datetime.fromisoformat(signed_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("signed_at must be a timezone-aware ISO 8601 timestamp.") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("signed_at must include a timezone.")
    return payload


def build_signed_attestation(
    integrity_response: dict[str, Any],
    private_key: Ed25519PrivateKey,
    *,
    signed_at: str | None = None,
) -> dict[str, Any]:
    """Create a detached signature for a fully verified assessment snapshot."""
    payload = {
        "format": ATTESTATION_FORMAT,
        **_verified_anchor(integrity_response),
        "signed_at": signed_at or datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    }
    _validate_payload(payload)
    public_raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return {
        "format": SIGNED_FORMAT,
        "algorithm": ALGORITHM,
        "key_id": hashlib.sha256(public_raw).hexdigest(),
        "payload": payload,
        "signature": base64.b64encode(private_key.sign(canonical_json(payload))).decode("ascii"),
    }


def verify_signed_attestation(
    envelope: Any,
    public_key: Ed25519PublicKey,
    current_integrity_response: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Verify signature and, optionally, the current assessment's exact evidence anchor."""
    if not isinstance(envelope, dict) or set(envelope) != _ENVELOPE_FIELDS:
        raise ValueError("Signed attestation envelope has an unsupported or incomplete schema.")
    if envelope.get("format") != SIGNED_FORMAT or envelope.get("algorithm") != ALGORITHM:
        raise ValueError("Unsupported signed attestation format or algorithm.")
    payload = _validate_payload(envelope.get("payload"))
    public_raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    expected_id = hashlib.sha256(public_raw).hexdigest()
    if not isinstance(envelope.get("key_id"), str) or not hmac.compare_digest(
        envelope["key_id"], expected_id
    ):
        raise ValueError("The supplied public key does not match the attestation signing key.")
    try:
        signature = base64.b64decode(envelope.get("signature", ""), validate=True)
        if len(signature) != 64:
            raise ValueError("Ed25519 signature must contain exactly 64 bytes.")
        public_key.verify(signature, canonical_json(payload))
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise ValueError("Assessment attestation signature verification failed.") from exc

    if current_integrity_response is not None:
        current = _verified_anchor(current_integrity_response)
        signed = {key: payload[key] for key in current}
        if canonical_json(current) != canonical_json(signed):
            raise ValueError("Current verified assessment does not match the signed evidence/audit anchor.")
    return payload


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Sign and verify SENTINEL assessment evidence attestations offline."
    )
    commands = parser.add_subparsers(dest="command", required=True)
    sign = commands.add_parser("sign", help="Sign a fully verified assessment response.")
    sign.add_argument("--input", required=True, type=Path)
    sign.add_argument("--private-key", required=True, type=Path)
    sign.add_argument("--output", required=True, type=Path)
    verify = commands.add_parser("verify", help="Verify an attestation and optional current anchor.")
    verify.add_argument("--input", required=True, type=Path)
    verify.add_argument("--public-key", required=True, type=Path)
    verify.add_argument("--current", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "sign":
            key = load_private_key(args.private_key, _prompt_passphrase())
            envelope = build_signed_attestation(load_json(args.input), key)
            write_json_new(args.output, envelope)
            print(
                f"Signed assessment {envelope['payload']['assessment_id']} "
                f"at audit sequence {envelope['payload']['audit_sequence_no']}."
            )
            return 0
        key = load_public_key(args.public_key)
        current = load_json(args.current) if args.current else None
        payload = verify_signed_attestation(load_json(args.input), key, current)
        print(
            f"Verified assessment {payload['assessment_id']} "
            f"at audit sequence {payload['audit_sequence_no']}."
        )
        return 0
    except (OSError, ValueError, TypeError, InvalidSignature) as exc:
        parser.exit(2, f"error: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
