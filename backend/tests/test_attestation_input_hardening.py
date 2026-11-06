import os

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts.assessment_attestation import build_signed_attestation
from scripts.audit_checkpoint import load_json, load_private_key


def _verified_response():
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


def _write_encrypted_private_key(path):
    key = Ed25519PrivateKey.generate()
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(b"correct horse battery"),
        )
    )
    path.chmod(0o600)
    return key


def test_signer_rejects_explicitly_empty_timestamp():
    with pytest.raises(ValueError, match="signed_at"):
        build_signed_attestation(
            _verified_response(),
            Ed25519PrivateKey.generate(),
            signed_at="",
        )


def test_private_key_loader_rejects_empty_file(tmp_path):
    key_path = tmp_path / "empty-private.pem"
    key_path.touch()
    key_path.chmod(0o600)

    with pytest.raises(ValueError, match="non-empty"):
        load_private_key(key_path, b"correct horse battery")


def test_private_key_loader_rejects_oversized_file(tmp_path):
    key_path = tmp_path / "oversized-private.pem"
    key_path.write_bytes(b"x" * (64 * 1024 + 1))
    key_path.chmod(0o600)

    with pytest.raises(ValueError, match="64 KiB"):
        load_private_key(key_path, b"correct horse battery")


def test_private_key_loader_rejects_non_regular_file(tmp_path):
    directory = tmp_path / "not-a-private-key-file"
    directory.mkdir()
    directory.chmod(0o700)

    with pytest.raises(ValueError, match="regular file"):
        load_private_key(directory, b"correct horse battery")


@pytest.mark.skipif(os.name != "posix", reason="POSIX symlink no-follow guarantee")
def test_private_key_loader_rejects_symlink(tmp_path):
    target = tmp_path / "private.pem"
    _write_encrypted_private_key(target)
    linked_path = tmp_path / "linked-private.pem"
    linked_path.symlink_to(target)

    with pytest.raises(ValueError, match="symlink|regular file"):
        load_private_key(linked_path, b"correct horse battery")


@pytest.mark.skipif(os.name != "posix", reason="POSIX symlink replacement guarantee")
def test_private_key_loader_rejects_path_replaced_after_open(tmp_path, monkeypatch):
    key_path = tmp_path / "private.pem"
    _write_encrypted_private_key(key_path)
    replacement = tmp_path / "replacement.pem"
    _write_encrypted_private_key(replacement)
    real_read = os.read
    replaced = False

    def replace_path_before_first_read(descriptor, size):
        nonlocal replaced
        if not replaced:
            key_path.unlink()
            key_path.symlink_to(replacement)
            replaced = True
        return real_read(descriptor, size)

    monkeypatch.setattr(os, "read", replace_path_before_first_read)
    with pytest.raises(ValueError, match="symlink|changed"):
        load_private_key(key_path, b"correct horse battery")


def test_json_loader_rejects_duplicate_object_keys(tmp_path):
    source = tmp_path / "duplicate.json"
    source.write_text(
        '{"integrity_valid": false, "integrity_valid": true}',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="duplicate"):
        load_json(source)


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_json_loader_rejects_non_standard_numeric_constants(tmp_path, constant):
    source = tmp_path / "non-standard-number.json"
    source.write_text(f'{{"score": {constant}}}', encoding="utf-8")

    with pytest.raises(ValueError, match="non-standard"):
        load_json(source)
