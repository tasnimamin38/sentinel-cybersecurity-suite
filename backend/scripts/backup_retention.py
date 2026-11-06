#!/usr/bin/env python3
"""Prune verified SENTINEL encrypted backups without unsafe implicit deletion.

Dry-run is the default. Deletion requires the explicit --apply flag.
The backup directory must be owned by the invoking user and be private (mode 0700 or stricter). Archive and checksum files must also be user-owned, private (mode 0600 or stricter), and single-linked.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import stat
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

ARCHIVE_NAME = re.compile(r"^sentinel-(?P<timestamp>\d{8}T\d{6}Z)\.dump\.enc$")
CHUNK_BYTES = 1024 * 1024
SIDECAR_MAX_BYTES = 256


class RetentionError(ValueError):
    """A retention operation could not safely continue."""


@dataclass(frozen=True)
class BackupRecord:
    name: str
    timestamp: str
    device: int
    inode: int
    sidecar_device: int
    sidecar_inode: int


def _open_regular_at(directory_fd: int, name: str) -> tuple[int, os.stat_result]:
    if not hasattr(os, "O_NOFOLLOW"):
        raise RetentionError("This platform lacks O_NOFOLLOW; refusing unsafe retention.")
    flags = (
        os.O_RDONLY
        | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        fd = os.open(name, flags, dir_fd=directory_fd)
    except OSError:
        raise
    metadata = os.fstat(fd)
    if metadata.st_uid != os.geteuid():
        os.close(fd)
        raise RetentionError(f"{name}: must be owned by the invoking user.")
    if metadata.st_nlink != 1:
        os.close(fd)
        raise RetentionError(f"{name}: hard-linked files are not eligible for retention.")
    if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) & ~0o600:
        os.close(fd)
        raise RetentionError(f"{name}: must be a private regular file (0600 or stricter).")
    path_metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    if (
        not stat.S_ISREG(path_metadata.st_mode)
        or path_metadata.st_dev != metadata.st_dev
        or path_metadata.st_ino != metadata.st_ino
    ):
        os.close(fd)
        raise RetentionError(f"{name}: file changed while being opened.")
    return fd, metadata


def _digest_file(fd: int) -> str:
    digest = hashlib.sha256()
    while True:
        chunk = os.read(fd, CHUNK_BYTES)
        if not chunk:
            break
        digest.update(chunk)
    return digest.hexdigest()


def _verify_archive(directory_fd: int, name: str) -> BackupRecord:
    match = ARCHIVE_NAME.fullmatch(name)
    if match is None:
        raise RetentionError(f"{name}: unexpected archive name.")
    timestamp = match.group("timestamp")
    try:
        datetime.strptime(timestamp, "%Y%m%dT%H%M%SZ")
    except ValueError as exc:
        raise RetentionError(f"{name}: archive timestamp is not a valid UTC date/time.") from exc
    archive_fd, archive_stat = _open_regular_at(directory_fd, name)
    if archive_stat.st_size == 0:
        os.close(archive_fd)
        raise RetentionError(f"{name}: empty encrypted archives are not eligible for retention.")
    sidecar_name = f"{name}.sha256"
    try:
        actual_digest = _digest_file(archive_fd)
    finally:
        os.close(archive_fd)

    sidecar_fd, sidecar_stat = _open_regular_at(directory_fd, sidecar_name)
    try:
        sidecar = os.read(sidecar_fd, SIDECAR_MAX_BYTES + 1)
    finally:
        os.close(sidecar_fd)
    if len(sidecar) > SIDECAR_MAX_BYTES:
        raise RetentionError(f"{sidecar_name}: checksum sidecar is oversized.")
    expected_line = f"{actual_digest}  {name}\n".encode("ascii")
    if sidecar != expected_line and sidecar != expected_line.rstrip(b"\n"):
        raise RetentionError(f"{name}: checksum sidecar is missing, malformed or mismatched.")

    return BackupRecord(
        name=name,
        timestamp=timestamp,
        device=archive_stat.st_dev,
        inode=archive_stat.st_ino,
        sidecar_device=sidecar_stat.st_dev,
        sidecar_inode=sidecar_stat.st_ino,
    )


def _same_inode(directory_fd: int, name: str, device: int, inode: int) -> bool:
    try:
        current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    return (
        stat.S_ISREG(current.st_mode)
        and current.st_dev == device
        and current.st_ino == inode
    )


def _open_private_directory(path: Path) -> int:
    if path.is_symlink():
        raise RetentionError("Backup directory must not be a symlink.")
    if not path.is_dir():
        raise RetentionError("Backup directory must already exist.")
    if (
        not hasattr(os, "O_NOFOLLOW")
        or not hasattr(os, "O_DIRECTORY")
        or not hasattr(os, "geteuid")
        or os.open not in os.supports_dir_fd
        or os.stat not in os.supports_dir_fd
        or os.unlink not in os.supports_dir_fd
    ):
        raise RetentionError("This platform lacks safe directory-file operations; refusing retention.")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    directory_fd = os.open(path, flags)
    metadata = os.fstat(directory_fd)
    if not stat.S_ISDIR(metadata.st_mode):
        os.close(directory_fd)
        raise RetentionError("Backup path is not a directory.")
    if metadata.st_uid != os.geteuid():
        os.close(directory_fd)
        raise RetentionError("Backup directory must be owned by the invoking user.")
    if metadata.st_mode & 0o077:
        os.close(directory_fd)
        raise RetentionError("Backup directory permissions must be private (0700 or stricter).")
    return directory_fd


def prune_backups(directory: Path, keep_last: int = 7, apply: bool = False) -> tuple[int, int, int]:
    """Return (verified_count, retained_count, deleted_count)."""
    if keep_last < 1:
        raise RetentionError("--keep-last must be at least 1.")
    directory_fd = _open_private_directory(directory)
    try:
        verified: list[BackupRecord] = []
        for name in sorted(os.listdir(directory_fd)):
            if not ARCHIVE_NAME.fullmatch(name):
                continue
            try:
                verified.append(_verify_archive(directory_fd, name))
            except (OSError, RetentionError) as exc:
                print(f"SKIP {name}: {exc}", file=sys.stderr)

        verified.sort(key=lambda item: item.timestamp, reverse=True)
        retained = verified[:keep_last]
        candidates = verified[keep_last:]
        for record in retained:
            print(f"KEEP {record.name}")
        deleted = 0
        for record in candidates:
            sidecar_name = f"{record.name}.sha256"
            if not _same_inode(directory_fd, record.name, record.device, record.inode):
                print(f"SKIP {record.name}: archive changed after verification.", file=sys.stderr)
                continue
            if not _same_inode(
                directory_fd, sidecar_name, record.sidecar_device, record.sidecar_inode
            ):
                print(f"SKIP {record.name}: checksum sidecar changed after verification.", file=sys.stderr)
                continue
            try:
                current = _verify_archive(directory_fd, record.name)
            except (OSError, RetentionError) as exc:
                print(f"SKIP {record.name}: final verification failed: {exc}", file=sys.stderr)
                continue
            if (current.device, current.inode) != (record.device, record.inode):
                print(f"SKIP {record.name}: archive identity changed.", file=sys.stderr)
                continue
            if (
                current.sidecar_device,
                current.sidecar_inode,
            ) != (record.sidecar_device, record.sidecar_inode):
                print(f"SKIP {record.name}: checksum sidecar identity changed.", file=sys.stderr)
                continue
            if not apply:
                print(f"DRY-RUN DELETE {record.name}")
                continue
            os.unlink(record.name, dir_fd=directory_fd)
            try:
                os.unlink(sidecar_name, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
            deleted += 1
            print(f"DELETED {record.name}")
        return len(verified), len(retained), deleted
    finally:
        os.close(directory_fd)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Retain verified SENTINEL encrypted backups; dry-run unless --apply is set."
    )
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--keep-last", type=int, default=7)
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Actually delete older verified archives and their checksum sidecars.",
    )
    args = parser.parse_args(argv)
    try:
        verified, retained, deleted = prune_backups(args.directory, args.keep_last, args.apply)
    except (OSError, RetentionError) as exc:
        print(f"backup_retention: {exc}", file=sys.stderr)
        return 1
    mode = "apply" if args.apply else "dry-run"
    print(
        f"Retention {mode} complete: verified={verified}, retained={retained}, deleted={deleted}."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
