import base64
import os
import stat

import pytest

from app.services.backup_crypto import (
    BackupCryptoError,
    decrypt_file,
    encrypt_file,
    encrypt_stream,
)


def set_backup_key(monkeypatch, key: bytes, key_id: str = "test-key-v1"):
    monkeypatch.setenv("SENTINEL_BACKUP_ENCRYPTION_KEY", base64.b64encode(key).decode("ascii"))
    monkeypatch.setenv("SENTINEL_BACKUP_ENCRYPTION_KEY_ID", key_id)


def test_large_backup_round_trips_with_streaming_authenticated_encryption(tmp_path, monkeypatch):
    key = os.urandom(32)
    set_backup_key(monkeypatch, key)
    original = (b"sentinel-backup-record\x00" * 150_000) + os.urandom(1024)
    source = tmp_path / "source.dump"
    encrypted = tmp_path / "source.dump.enc"
    restored = tmp_path / "restored.dump"
    source.write_bytes(original)

    assert encrypt_file(source, encrypted) == "test-key-v1"
    ciphertext = encrypted.read_bytes()
    assert ciphertext.startswith(b"SNTLBK01")
    assert original not in ciphertext
    assert stat.S_IMODE(encrypted.stat().st_mode) == 0o600

    assert decrypt_file(encrypted, restored) == "test-key-v1"
    assert restored.read_bytes() == original
    assert stat.S_IMODE(restored.stat().st_mode) == 0o600


def test_wrong_key_fails_without_publishing_plaintext(tmp_path, monkeypatch):
    source = tmp_path / "source.dump"
    encrypted = tmp_path / "source.dump.enc"
    restored = tmp_path / "restored.dump"
    source.write_bytes(os.urandom(8192))
    set_backup_key(monkeypatch, os.urandom(32))
    encrypt_file(source, encrypted)

    set_backup_key(monkeypatch, os.urandom(32))
    with pytest.raises(BackupCryptoError, match="authentication failed"):
        decrypt_file(encrypted, restored)
    assert not restored.exists()
    assert not list(tmp_path.glob(".restored.dump.*"))


def test_tampered_ciphertext_is_rejected(tmp_path, monkeypatch):
    source = tmp_path / "source.dump"
    encrypted = tmp_path / "source.dump.enc"
    restored = tmp_path / "restored.dump"
    source.write_bytes(b"database contents" * 500)
    set_backup_key(monkeypatch, os.urandom(32))
    encrypt_file(source, encrypted)

    payload = bytearray(encrypted.read_bytes())
    payload[-1] ^= 0x80
    encrypted.write_bytes(payload)
    with pytest.raises(BackupCryptoError, match="authentication failed"):
        decrypt_file(encrypted, restored)
    assert not restored.exists()


def test_key_id_must_match_the_archive_header(tmp_path, monkeypatch):
    source = tmp_path / "source.dump"
    encrypted = tmp_path / "source.dump.enc"
    restored = tmp_path / "restored.dump"
    source.write_bytes(b"archive")
    key = os.urandom(32)
    set_backup_key(monkeypatch, key, "key-2026-11")
    encrypt_file(source, encrypted)

    set_backup_key(monkeypatch, key, "key-2026-12")
    with pytest.raises(BackupCryptoError, match="Backup key ID"):
        decrypt_file(encrypted, restored)
    assert not restored.exists()


def test_key_must_be_base64_32_bytes_and_key_id_valid(tmp_path, monkeypatch):
    monkeypatch.delenv("SENTINEL_BACKUP_ENCRYPTION_KEY", raising=False)
    monkeypatch.delenv("SENTINEL_BACKUP_ENCRYPTION_KEY_ID", raising=False)
    source = tmp_path / "source.dump"
    encrypted = tmp_path / "source.dump.enc"
    source.write_bytes(b"archive")

    with pytest.raises(BackupCryptoError, match="is required"):
        encrypt_file(source, encrypted)

    monkeypatch.setenv("SENTINEL_BACKUP_ENCRYPTION_KEY", base64.b64encode(b"x" * 16).decode())
    monkeypatch.setenv("SENTINEL_BACKUP_ENCRYPTION_KEY_ID", "bad")
    with pytest.raises(BackupCryptoError, match="exactly 32 bytes"):
        encrypt_file(source, encrypted)

    monkeypatch.setenv("SENTINEL_BACKUP_ENCRYPTION_KEY", base64.b64encode(os.urandom(32)).decode())
    monkeypatch.setenv("SENTINEL_BACKUP_ENCRYPTION_KEY_ID", "../unsafe")
    with pytest.raises(BackupCryptoError, match="key identifier"):
        encrypt_file(source, encrypted)


def test_encryption_refuses_to_overwrite_existing_output(tmp_path, monkeypatch):
    source = tmp_path / "source.dump"
    encrypted = tmp_path / "source.dump.enc"
    source.write_bytes(b"archive")
    encrypted.write_bytes(b"preserve-me")
    set_backup_key(monkeypatch, os.urandom(32))

    with pytest.raises(BackupCryptoError, match="overwrite"):
        encrypt_file(source, encrypted)
    assert encrypted.read_bytes() == b"preserve-me"


def test_malformed_or_truncated_archive_is_rejected(tmp_path, monkeypatch):
    malformed = tmp_path / "malformed.dump.enc"
    restored = tmp_path / "restored.dump"
    malformed.write_bytes(b"not-an-encrypted-backup")
    set_backup_key(monkeypatch, os.urandom(32))

    with pytest.raises(BackupCryptoError, match="truncated|malformed"):
        decrypt_file(malformed, restored)
    assert not restored.exists()



def test_stdin_stream_is_encrypted_without_creating_plaintext_staging_file(tmp_path, monkeypatch):
    import io

    original = (b"postgres-stream\\x00" * 100_000) + os.urandom(2048)
    encrypted = tmp_path / "stdin.dump.enc"
    set_backup_key(monkeypatch, os.urandom(32))

    assert encrypt_stream(io.BytesIO(original), encrypted) == "test-key-v1"
    ciphertext = encrypted.read_bytes()
    assert ciphertext.startswith(b"SNTLBK01")
    assert original not in ciphertext
    assert sorted(path.name for path in tmp_path.iterdir()) == ["stdin.dump.enc"]
