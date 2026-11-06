"""Streaming authenticated encryption for SENTINEL PostgreSQL backups.

The encryption key and non-secret key identifier are supplied through the process
environment by an operator or secret manager. Neither is stored in the archive.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import os
import re
import secrets
import stat
import sys
import tempfile
from pathlib import Path
from typing import BinaryIO

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

MAGIC = b"SNTLBK01"
NONCE_BYTES = 12
TAG_BYTES = 16
KEY_BYTES = 32
CHUNK_BYTES = 1024 * 1024
KEY_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class BackupCryptoError(ValueError):
    """A backup encryption/decryption operation could not be completed safely."""


def load_key_material() -> tuple[bytes, str]:
    encoded = os.environ.get("SENTINEL_BACKUP_ENCRYPTION_KEY", "").strip()
    key_id = os.environ.get("SENTINEL_BACKUP_ENCRYPTION_KEY_ID", "").strip()
    if not encoded:
        raise BackupCryptoError("SENTINEL_BACKUP_ENCRYPTION_KEY is required.")
    if not key_id or not KEY_ID_PATTERN.fullmatch(key_id):
        raise BackupCryptoError(
            "SENTINEL_BACKUP_ENCRYPTION_KEY_ID must be a 1-64 character safe key identifier "
            "(letters, digits, dot, underscore or hyphen)."
        )
    try:
        key = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise BackupCryptoError("SENTINEL_BACKUP_ENCRYPTION_KEY must be standard Base64.") from exc
    if len(key) != KEY_BYTES:
        raise BackupCryptoError(
            "SENTINEL_BACKUP_ENCRYPTION_KEY must decode to exactly 32 bytes."
        )
    return key, key_id


def _validate_destination(destination: Path) -> None:
    if destination.exists() or destination.is_symlink():
        raise BackupCryptoError("Refusing to overwrite an existing output file.")
    if not destination.parent.is_dir():
        raise BackupCryptoError("Output directory must already exist.")


def _open_private_temp(destination: Path) -> tuple[int, Path]:
    fd, name = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    try:
        os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)
    except (AttributeError, OSError):
        pass
    return fd, Path(name)


def _publish_temp(temp_path: Path, destination: Path) -> None:
    # A hard-link publication is atomic and fails if destination already exists.
    # Unlike check-then-os.replace, it cannot clobber a file created in the race window.
    try:
        os.link(temp_path, destination)
    except FileExistsError as exc:
        raise BackupCryptoError(
            "Output appeared during the operation; refusing to overwrite it."
        ) from exc
    temp_path.unlink()
    try:
        os.chmod(destination, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


def _encrypt_stream(input_file: BinaryIO, destination: Path, key: bytes, key_id: str) -> str:
    _validate_destination(destination)
    key_id_bytes = key_id.encode("ascii")
    nonce = secrets.token_bytes(NONCE_BYTES)
    header = MAGIC + nonce + bytes((len(key_id_bytes),)) + key_id_bytes
    encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    encryptor.authenticate_additional_data(header)

    fd, temp_path = _open_private_temp(destination)
    try:
        with os.fdopen(fd, "wb") as output_file:
            output_file.write(header)
            while chunk := input_file.read(CHUNK_BYTES):
                output_file.write(encryptor.update(chunk))
            output_file.write(encryptor.finalize())
            output_file.write(encryptor.tag)
            output_file.flush()
            os.fsync(output_file.fileno())
        _publish_temp(temp_path, destination)
    except Exception:
        temp_path.unlink(missing_ok=True)
        raise
    return key_id


def encrypt_stream(input_file: BinaryIO, destination_path: str | Path) -> str:
    """Encrypt an existing binary stream without staging plaintext on disk."""
    key, key_id = load_key_material()
    return _encrypt_stream(input_file, Path(destination_path), key, key_id)


def encrypt_file(source_path: str | Path, destination_path: str | Path) -> str:
    source = Path(source_path)
    if source.is_symlink() or not source.is_file():
        raise BackupCryptoError("Input must be a regular, non-symlink file.")
    destination = Path(destination_path)
    if source.resolve() == destination.resolve():
        raise BackupCryptoError("Input and output paths must be different.")
    key, key_id = load_key_material()
    with source.open("rb") as input_file:
        return _encrypt_stream(input_file, destination, key, key_id)


def decrypt_file(source_path: str | Path, destination_path: str | Path) -> str:
    key, expected_key_id = load_key_material()
    source = Path(source_path)
    destination = Path(destination_path)
    if source.is_symlink() or not source.is_file():
        raise BackupCryptoError("Input must be a regular, non-symlink file.")
    if source.resolve() == destination.resolve():
        raise BackupCryptoError("Input and output paths must be different.")
    _validate_destination(destination)

    fd, temp_path = _open_private_temp(destination)
    try:
        with source.open("rb") as input_file, os.fdopen(fd, "wb") as output_file:
            file_size = source.stat().st_size
            fixed_header_bytes = len(MAGIC) + NONCE_BYTES + 1
            if file_size < fixed_header_bytes + TAG_BYTES:
                raise BackupCryptoError("Encrypted backup is truncated.")
            fixed_header = input_file.read(fixed_header_bytes)
            if len(fixed_header) != fixed_header_bytes or fixed_header[: len(MAGIC)] != MAGIC:
                raise BackupCryptoError("Unsupported or malformed encrypted backup format.")

            nonce_start = len(MAGIC)
            nonce = fixed_header[nonce_start : nonce_start + NONCE_BYTES]
            key_id_length = fixed_header[-1]
            if not 1 <= key_id_length <= 64:
                raise BackupCryptoError(
                    "Encrypted backup contains an invalid key identifier length."
                )
            key_id_bytes = input_file.read(key_id_length)
            if len(key_id_bytes) != key_id_length:
                raise BackupCryptoError("Encrypted backup header is truncated.")
            try:
                key_id = key_id_bytes.decode("ascii")
            except UnicodeDecodeError as exc:
                raise BackupCryptoError("Encrypted backup key identifier is malformed.") from exc
            if not KEY_ID_PATTERN.fullmatch(key_id):
                raise BackupCryptoError("Encrypted backup key identifier is malformed.")
            if key_id != expected_key_id:
                raise BackupCryptoError(
                    f"Backup key ID is {key_id!r}; configured key ID is {expected_key_id!r}."
                )

            header = fixed_header + key_id_bytes
            header_size = len(header)
            ciphertext_remaining = file_size - header_size - TAG_BYTES
            if ciphertext_remaining < 0:
                raise BackupCryptoError("Encrypted backup is truncated.")

            decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).decryptor()
            decryptor.authenticate_additional_data(header)
            while ciphertext_remaining:
                chunk = input_file.read(min(CHUNK_BYTES, ciphertext_remaining))
                if not chunk:
                    raise BackupCryptoError(
                        "Encrypted backup ended before its authentication tag."
                    )
                ciphertext_remaining -= len(chunk)
                output_file.write(decryptor.update(chunk))

            tag = input_file.read(TAG_BYTES)
            if len(tag) != TAG_BYTES or input_file.read(1):
                raise BackupCryptoError("Encrypted backup authentication trailer is malformed.")
            try:
                output_file.write(decryptor.finalize_with_tag(tag))
            except InvalidTag as exc:
                raise BackupCryptoError(
                    "Backup authentication failed: the key is incorrect or the archive was altered."
                ) from exc
            output_file.flush()
            os.fsync(output_file.fileno())

        _publish_temp(temp_path, destination)
    except Exception:
        temp_path.unlink(missing_ok=True)
        raise
    return key_id


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Encrypt or authenticate/decrypt a SENTINEL backup."
    )
    subparsers = parser.add_subparsers(dest="operation", required=True)
    encrypt = subparsers.add_parser("encrypt")
    encrypt.add_argument("source")
    encrypt.add_argument("destination")
    encrypt_stdin = subparsers.add_parser("encrypt-stdin")
    encrypt_stdin.add_argument("destination")
    decrypt = subparsers.add_parser("decrypt")
    decrypt.add_argument("source")
    decrypt.add_argument("destination")
    args = parser.parse_args(argv)
    try:
        if args.operation == "encrypt":
            key_id = encrypt_file(args.source, args.destination)
            print(f"Backup encrypted with AES-256-GCM (key ID: {key_id}).")
        elif args.operation == "encrypt-stdin":
            key_id = encrypt_stream(sys.stdin.buffer, args.destination)
            print(f"Backup encrypted from stdin with AES-256-GCM (key ID: {key_id}).")
        else:
            key_id = decrypt_file(args.source, args.destination)
            print(f"Backup authenticated and decrypted (key ID: {key_id}).")
    except (BackupCryptoError, OSError) as exc:
        print(f"backup_crypto: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
