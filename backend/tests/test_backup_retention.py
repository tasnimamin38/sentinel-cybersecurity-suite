import hashlib
import os
import stat
from pathlib import Path

import pytest

from scripts.backup_retention import RetentionError, main, prune_backups


def _archive(directory: Path, stamp: str, content: bytes, mtime: int) -> Path:
    name = f"sentinel-{stamp}.dump.enc"
    archive = directory / name
    archive.write_bytes(content)
    archive.chmod(stat.S_IRUSR | stat.S_IWUSR)
    digest = hashlib.sha256(content).hexdigest()
    sidecar = directory / f"{name}.sha256"
    sidecar.write_text(f"{digest}  {name}\n", encoding="ascii")
    sidecar.chmod(stat.S_IRUSR | stat.S_IWUSR)
    os.utime(archive, (mtime, mtime))
    return archive


def _private_directory(path: Path) -> Path:
    path.mkdir(mode=0o700)
    path.chmod(0o700)
    return path


def test_retention_defaults_to_dry_run_and_keeps_newest_verified_archives(tmp_path, capsys):
    directory = _private_directory(tmp_path / "backups")
    older = _archive(directory, "20261101T000000Z", b"one", 100)
    middle = _archive(directory, "20261102T000000Z", b"two", 200)
    newest = _archive(directory, "20261103T000000Z", b"three", 300)

    verified, retained, deleted = prune_backups(directory, keep_last=2, apply=False)

    assert (verified, retained, deleted) == (3, 2, 0)
    assert older.exists()
    assert middle.exists()
    assert newest.exists()
    assert "DRY-RUN DELETE" in capsys.readouterr().out


def test_apply_deletes_only_older_verified_archive_and_checksum(tmp_path):
    directory = _private_directory(tmp_path / "backups")
    older = _archive(directory, "20261101T000000Z", b"one", 100)
    newest = _archive(directory, "20261102T000000Z", b"two", 200)

    verified, retained, deleted = prune_backups(directory, keep_last=1, apply=True)

    assert (verified, retained, deleted) == (2, 1, 1)
    assert not older.exists()
    assert not Path(f"{older}.sha256").exists()
    assert newest.exists()
    assert Path(f"{newest}.sha256").exists()


def test_retention_uses_filename_timestamp_not_mutable_mtime(tmp_path, capsys):
    directory = _private_directory(tmp_path / "backups")
    older_name = _archive(directory, "20261101T000000Z", b"older", 300)
    newer_name = _archive(directory, "20261102T000000Z", b"newer", 100)

    verified, retained, deleted = prune_backups(directory, keep_last=1, apply=False)

    output = capsys.readouterr().out
    assert (verified, retained, deleted) == (2, 1, 0)
    assert f"KEEP {newer_name.name}" in output
    assert f"DRY-RUN DELETE {older_name.name}" in output


def test_invalid_calendar_timestamp_is_never_deleted(tmp_path, capsys):
    directory = _private_directory(tmp_path / "backups")
    invalid = _archive(directory, "20261301T000000Z", b"invalid-date", 300)
    valid = _archive(directory, "20261102T000000Z", b"valid", 100)

    verified, retained, deleted = prune_backups(directory, keep_last=1, apply=True)

    assert (verified, retained, deleted) == (1, 1, 0)
    assert invalid.exists()
    assert valid.exists()
    assert "valid UTC date/time" in capsys.readouterr().err


def test_backup_directory_must_be_owned_by_invoking_user(tmp_path, monkeypatch):
    directory = _private_directory(tmp_path / "backups")
    actual_uid = os.geteuid()
    monkeypatch.setattr(os, "geteuid", lambda: actual_uid + 1)

    with pytest.raises(RetentionError, match="owned by the invoking user"):
        prune_backups(directory)


def test_hard_linked_archive_is_never_deleted(tmp_path, capsys):
    directory = _private_directory(tmp_path / "backups")
    target = tmp_path / "outside.enc"
    target.write_bytes(b"shared-backup")
    target.chmod(stat.S_IRUSR | stat.S_IWUSR)
    archive = directory / "sentinel-20261101T000000Z.dump.enc"
    os.link(target, archive)
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    sidecar = directory / f"{archive.name}.sha256"
    sidecar.write_text(f"{digest}  {archive.name}" + chr(10), encoding="ascii")
    sidecar.chmod(stat.S_IRUSR | stat.S_IWUSR)

    verified, retained, deleted = prune_backups(directory, keep_last=1, apply=True)

    assert (verified, retained, deleted) == (0, 0, 0)
    assert archive.exists()
    assert target.exists()
    assert "hard-linked files" in capsys.readouterr().err


def test_fifo_archive_is_skipped_without_blocking(tmp_path, capsys):
    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFO creation is unavailable on this platform.")
    directory = _private_directory(tmp_path / "backups")
    archive = directory / "sentinel-20261101T000000Z.dump.enc"
    os.mkfifo(archive, 0o600)

    verified, retained, deleted = prune_backups(directory, keep_last=1, apply=True)

    assert (verified, retained, deleted) == (0, 0, 0)
    assert archive.exists()
    assert "private regular file" in capsys.readouterr().err


def test_invalid_checksum_is_never_deleted_or_counted_as_verified(tmp_path, capsys):
    directory = _private_directory(tmp_path / "backups")
    valid = _archive(directory, "20261102T000000Z", b"valid", 200)
    invalid = _archive(directory, "20261101T000000Z", b"invalid", 100)
    Path(f"{invalid}.sha256").write_text("0" * 64 + f"  {invalid.name}\n", encoding="ascii")
    Path(f"{invalid}.sha256").chmod(stat.S_IRUSR | stat.S_IWUSR)

    verified, retained, deleted = prune_backups(directory, keep_last=1, apply=True)

    assert (verified, retained, deleted) == (1, 1, 0)
    assert valid.exists()
    assert invalid.exists()
    assert "mismatched" in capsys.readouterr().err


def test_symlink_archive_is_skipped_without_following_target(tmp_path, capsys):
    directory = _private_directory(tmp_path / "backups")
    target = tmp_path / "outside.enc"
    target.write_bytes(b"outside")
    link = directory / "sentinel-20261101T000000Z.dump.enc"
    link.symlink_to(target)
    sidecar = Path(f"{link}.sha256")
    sidecar.write_text(
        hashlib.sha256(b"outside").hexdigest() + f"  {link.name}\n",
        encoding="ascii",
    )
    sidecar.chmod(stat.S_IRUSR | stat.S_IWUSR)

    verified, retained, deleted = prune_backups(directory, keep_last=1, apply=True)

    assert (verified, retained, deleted) == (0, 0, 0)
    assert target.read_bytes() == b"outside"
    assert link.is_symlink()
    assert "SKIP" in capsys.readouterr().err


def test_private_directory_permissions_are_required(tmp_path):
    directory = tmp_path / "public-backups"
    directory.mkdir(mode=0o755)
    directory.chmod(0o755)

    with pytest.raises(RetentionError, match="private"):
        prune_backups(directory)


def test_missing_sidecar_is_never_deleted(tmp_path, capsys):
    directory = _private_directory(tmp_path / "backups")
    archive = _archive(directory, "20261101T000000Z", b"one", 100)
    Path(f"{archive}.sha256").unlink()

    verified, retained, deleted = prune_backups(directory, keep_last=1, apply=True)

    assert (verified, retained, deleted) == (0, 0, 0)
    assert archive.exists()
    assert "SKIP" in capsys.readouterr().err


def test_symlink_sidecar_is_never_followed_or_deleted(tmp_path, capsys):
    directory = _private_directory(tmp_path / "backups")
    archive = _archive(directory, "20261101T000000Z", b"one", 100)
    sidecar = Path(f"{archive}.sha256")
    outside = tmp_path / "outside.sha256"
    outside.write_bytes(sidecar.read_bytes())
    sidecar.unlink()
    sidecar.symlink_to(outside)

    verified, retained, deleted = prune_backups(directory, keep_last=1, apply=True)

    assert (verified, retained, deleted) == (0, 0, 0)
    assert archive.exists()
    assert sidecar.is_symlink()
    assert outside.exists()
    assert "SKIP" in capsys.readouterr().err


def test_empty_archive_is_never_deleted(tmp_path, capsys):
    directory = _private_directory(tmp_path / "backups")
    archive = _archive(directory, "20261101T000000Z", b"", 100)

    verified, retained, deleted = prune_backups(directory, keep_last=1, apply=True)

    assert (verified, retained, deleted) == (0, 0, 0)
    assert archive.exists()
    assert "empty encrypted archives" in capsys.readouterr().err


def test_keep_last_must_never_be_zero(tmp_path):
    directory = _private_directory(tmp_path / "backups")

    with pytest.raises(RetentionError, match="at least 1"):
        prune_backups(directory, keep_last=0)


def test_cli_requires_explicit_apply_for_deletion(tmp_path, capsys):
    directory = _private_directory(tmp_path / "backups")
    older = _archive(directory, "20261101T000000Z", b"one", 100)
    _archive(directory, "20261102T000000Z", b"two", 200)

    assert main(["--directory", str(directory), "--keep-last", "1"]) == 0
    assert older.exists()
    assert "dry-run" in capsys.readouterr().out

    assert main(["--directory", str(directory), "--keep-last", "1", "--apply"]) == 0
    assert not older.exists()
    assert "deleted=1" in capsys.readouterr().out


def test_archive_and_sidecar_must_be_private(tmp_path, capsys):
    directory = _private_directory(tmp_path / "backups")
    archive = _archive(directory, "20261101T000000Z", b"one", 100)
    archive.chmod(0o644)

    verified, retained, deleted = prune_backups(directory, keep_last=1, apply=True)

    assert (verified, retained, deleted) == (0, 0, 0)
    assert archive.exists()
    assert "private regular file" in capsys.readouterr().err
