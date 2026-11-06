# SENTINEL encrypted backup retention

## Safety model

The retention utility only considers archives named `sentinel-YYYYMMDDTHHMMSSZ.dump.enc`
with a matching SHA-256 sidecar. A missing, malformed, mismatched or symlinked archive/sidecar
is skipped and never deleted.

The backup directory must be owned by the invoking POSIX user and be private with mode `0700` or
stricter. Candidate files must be owned by that user, be private regular files with mode `0600` or
stricter, and have exactly one hard link. The utility rejects symlinks and hard links, validates
the UTC timestamp embedded in each archive name, opens the directory without following symlinks,
opens candidate files with `O_NOFOLLOW`, verifies the checksum, and re-checks file identity
immediately before deletion. Retention ordering uses the UTC timestamp in the archive name, not
mutable filesystem modification times.

## Dry-run first

From the backend directory (Linux or WSL):

```bash
python -m scripts.backup_retention --directory ./backups --keep-last 7
```

The default is always a dry-run. Review every `KEEP`, `DRY-RUN DELETE` and `SKIP` line.
Unverified archives are deliberately retained for operator investigation.

## Apply deletion

Only after reviewing the dry-run output:

```bash
python -m scripts.backup_retention --directory ./backups --keep-last 7 --apply
```

This keeps the seven newest verified archives and removes older verified archives plus their
checksum sidecars. At least one verified backup is always retained.

## Operational requirements

- Keep encryption keys and key-version records in a separate approved secret manager.
- Replicate backups off-host before pruning local copies when the recovery policy requires it.
- Do not treat checksum verification as a substitute for AES-GCM authentication or restore tests.
- Run a restore drill on a separate disposable PostgreSQL target before approving retention changes.
- This tool does not perform secure erasure and does not delete unverified files.
- Windows users should run this utility from WSL/Linux because it intentionally requires POSIX
  no-follow and directory-file-descriptor semantics.
