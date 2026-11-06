from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import json
import os
import re
import stat
from datetime import datetime
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

CHECKPOINT_FORMAT = "sentinel.audit.checkpoint.v1"
SIGNED_FORMAT = "sentinel.audit.signed-checkpoint.v1"
ALGORITHM = "Ed25519"
_EVENT_HASH = re.compile(r"^[0-9a-f]{64}$")
_REQUIRED_CHECKPOINT_FIELDS = {
    "format",
    "sequence_no",
    "event_hash",
    "sealed_events",
    "verified_until",
}


def canonical_json(value: Any) -> bytes:
    """Serialize signed data with one deterministic JSON representation."""
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _validate_checkpoint(checkpoint: Any) -> dict[str, Any]:
    if not isinstance(checkpoint, dict) or set(checkpoint) != _REQUIRED_CHECKPOINT_FIELDS:
        raise ValueError("Checkpoint payload has an unsupported or incomplete schema.")
    if checkpoint["format"] != CHECKPOINT_FORMAT:
        raise ValueError("Unsupported checkpoint format.")
    sequence_no = checkpoint["sequence_no"]
    sealed_events = checkpoint["sealed_events"]
    if type(sequence_no) is not int or sequence_no < 1:
        raise ValueError("Checkpoint sequence_no must be a positive integer.")
    if type(sealed_events) is not int or sealed_events != sequence_no:
        raise ValueError("A checkpoint must contain a complete, gap-free sealed sequence.")
    if not isinstance(checkpoint["event_hash"], str) or not _EVENT_HASH.fullmatch(
        checkpoint["event_hash"]
    ):
        raise ValueError("Checkpoint event_hash must be a lowercase SHA-256 digest.")
    verified_until = checkpoint["verified_until"]
    if not isinstance(verified_until, str) or not verified_until:
        raise ValueError("Checkpoint verified_until timestamp is missing.")
    try:
        parsed = datetime.fromisoformat(verified_until.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Checkpoint verified_until must be an ISO 8601 timestamp.") from exc
    if parsed.tzinfo is None:
        raise ValueError("Checkpoint verified_until must include a timezone.")
    return checkpoint


def extract_checkpoint(integrity_response: Any) -> dict[str, Any]:
    if not isinstance(integrity_response, dict):
        raise ValueError("Input must be a SENTINEL audit integrity JSON response.")
    if integrity_response.get("integrity_valid") is not True:
        raise ValueError("Refusing to sign: the audit journal is not integrity-valid.")
    if integrity_response.get("verification_status") != "verified":
        raise ValueError("Refusing to sign: the audit journal is not fully verified.")
    return _validate_checkpoint(integrity_response.get("checkpoint"))


def build_signed_envelope(
    integrity_response: dict[str, Any],
    private_key: Ed25519PrivateKey,
) -> dict[str, Any]:
    checkpoint = extract_checkpoint(integrity_response)
    public_raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    signature = private_key.sign(canonical_json(checkpoint))
    return {
        "format": SIGNED_FORMAT,
        "algorithm": ALGORITHM,
        "key_id": hashlib.sha256(public_raw).hexdigest(),
        "payload": checkpoint,
        "signature": base64.b64encode(signature).decode("ascii"),
    }


def verify_signed_envelope(
    envelope: Any,
    public_key: Ed25519PublicKey,
    current_integrity_response: dict[str, Any] | None = None,
) -> dict[str, Any]:
    required = {"format", "algorithm", "key_id", "payload", "signature"}
    if not isinstance(envelope, dict) or set(envelope) != required:
        raise ValueError("Signed checkpoint envelope has an unsupported or incomplete schema.")
    if envelope["format"] != SIGNED_FORMAT or envelope["algorithm"] != ALGORITHM:
        raise ValueError("Unsupported signed checkpoint format or algorithm.")

    checkpoint = _validate_checkpoint(envelope["payload"])
    public_raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    expected_key_id = hashlib.sha256(public_raw).hexdigest()
    if not isinstance(envelope["key_id"], str) or envelope["key_id"] != expected_key_id:
        raise ValueError("The supplied public key does not match the checkpoint signing key.")

    try:
        signature = base64.b64decode(envelope["signature"], validate=True)
        public_key.verify(signature, canonical_json(checkpoint))
    except (InvalidSignature, ValueError) as exc:
        raise ValueError("Checkpoint signature verification failed.") from exc

    if current_integrity_response is not None:
        current_checkpoint = extract_checkpoint(current_integrity_response)
        if canonical_json(current_checkpoint) != canonical_json(checkpoint):
            raise ValueError(
                "The current verified journal prefix does not match the signed checkpoint. "
                "Request /api/v1/audit/integrity?through_sequence=<signed sequence>."
            )
    return checkpoint


def _write_new_file(path: Path, content: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, mode)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(content)


def generate_key_pair(
    private_path: Path,
    public_path: Path,
    passphrase: bytes,
) -> str:
    if len(passphrase) < 12:
        raise ValueError("The private-key passphrase must contain at least 12 bytes.")
    if private_path.resolve() == public_path.resolve():
        raise ValueError("Private and public key paths must be different.")
    if private_path.exists() or public_path.exists():
        raise FileExistsError("Refusing to overwrite an existing key file.")

    private_key = Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    try:
        _write_new_file(private_path, private_pem, 0o600)
        _write_new_file(public_path, public_pem, 0o644)
    except OSError:
        private_path.unlink(missing_ok=True)
        raise
    public_raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(public_raw).hexdigest()


def load_private_key(path: Path, passphrase: bytes) -> Ed25519PrivateKey:
    if os.name == "posix":
        permissions = stat.S_IMODE(path.stat().st_mode)
        if permissions & 0o077:
            raise ValueError("Private key permissions are too broad; use chmod 600.")
    key = serialization.load_pem_private_key(path.read_bytes(), password=passphrase)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("The private key must be an Ed25519 PEM key.")
    return key


def load_public_key(path: Path) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(path.read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("The public key must be an Ed25519 PEM key.")
    return key


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json_new(path: Path, value: Any) -> None:
    content = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    _write_new_file(path, content.encode("utf-8"), 0o600)


def _prompt_passphrase(confirm: bool = False) -> bytes:
    value = getpass.getpass("Private-key passphrase: ")
    if confirm:
        repeated = getpass.getpass("Repeat passphrase: ")
        if value != repeated:
            raise ValueError("Passphrases do not match.")
    if len(value.encode("utf-8")) < 12:
        raise ValueError("Passphrase must contain at least 12 characters.")
    return value.encode("utf-8")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create and verify offline Ed25519 signatures for SENTINEL audit checkpoints."
    )
    commands = parser.add_subparsers(dest="command", required=True)

    generate = commands.add_parser("generate-key", help="Generate an encrypted offline key pair.")
    generate.add_argument("--private-key", required=True, type=Path)
    generate.add_argument("--public-key", required=True, type=Path)

    sign = commands.add_parser("sign", help="Sign a verified audit integrity JSON response.")
    sign.add_argument("--input", required=True, type=Path)
    sign.add_argument("--private-key", required=True, type=Path)
    sign.add_argument("--output", required=True, type=Path)

    verify = commands.add_parser("verify", help="Verify a signature and optional live journal prefix.")
    verify.add_argument("--input", required=True, type=Path)
    verify.add_argument("--public-key", required=True, type=Path)
    verify.add_argument("--current", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "generate-key":
            passphrase = _prompt_passphrase(confirm=True)
            key_id = generate_key_pair(args.private_key, args.public_key, passphrase)
            print(f"Ed25519 key pair created. key_id={key_id}")
            print("Keep the encrypted private key offline; publish only the public key.")
            return 0

        if args.command == "sign":
            passphrase = _prompt_passphrase()
            private_key = load_private_key(args.private_key, passphrase)
            envelope = build_signed_envelope(load_json(args.input), private_key)
            write_json_new(args.output, envelope)
            print(
                "Signed checkpoint written: "
                f"sequence_no={envelope['payload']['sequence_no']} "
                f"key_id={envelope['key_id']}"
            )
            return 0

        public_key = load_public_key(args.public_key)
        current = load_json(args.current) if args.current else None
        checkpoint = verify_signed_envelope(load_json(args.input), public_key, current)
        print(
            "Signature and checkpoint verified: "
            f"sequence_no={checkpoint['sequence_no']} "
            f"event_hash={checkpoint['event_hash']}"
        )
        return 0
    except (OSError, ValueError, TypeError, InvalidSignature) as exc:
        parser.exit(2, f"error: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
