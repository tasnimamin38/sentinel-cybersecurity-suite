# SENTINEL encrypted backup and restore verification

## Purpose

SENTINEL PostgreSQL backups are encrypted before they are published to the backup directory. The archive uses streaming AES-256-GCM authenticated encryption with a random 96-bit nonce. The header contains a format marker and a non-secret key ID. The key is never written into the archive.

The existing SHA-256 sidecar remains as an early corruption check. AES-GCM independently authenticates the encrypted content and rejects tampering or a wrong key.

## Operator key setup

Use an organization-approved secret manager or protected environment injection to provide both variables to the shell that runs backup or restore:

- `SENTINEL_BACKUP_ENCRYPTION_KEY`: standard Base64 encoding of exactly 32 random bytes.
- `SENTINEL_BACKUP_ENCRYPTION_KEY_ID`: a non-secret identifier for the key version, 1–64 characters from letters, digits, dot, underscore and hyphen.

Generate a new key with:

```sh
python3 -c 'import base64,secrets; print(base64.b64encode(secrets.token_bytes(32)).decode("ascii"))'
```

Store the result in the approved secret manager. Record the matching key ID there as well. Do not commit the key, put it in issue comments, shell scripts, workflow files, screenshots, logs or the repository's `.env.example`.

For a short local test only, an operator may export the values into the current shell from a protected secret store. Do not paste the actual key into chat.

## Create an encrypted backup

From the repository root, with Docker Compose running and both key variables present:

```sh
bash backend/scripts/backup_postgres.sh
```

The script creates `backups/sentinel-<UTC timestamp>.dump.enc` and a matching `.sha256` sidecar. The backup directory is restricted to mode 700 and both published files to mode 600 on POSIX systems. Plaintext is held in a private temporary directory only long enough to encrypt it; the temporary directory is removed on exit.

The script refuses to overwrite a timestamp collision and fails closed when the encryption key or key ID is missing or invalid.

## Verify and restore into a disposable database

Provide the exact matching key and key ID, then run:

```sh
bash backend/scripts/restore_check_postgres.sh backups/sentinel-<UTC timestamp>.dump.enc
```

The verifier checks the SHA-256 sidecar, authenticates/decrypts the archive into a private temporary directory, and restores it into a disposable PostgreSQL 16 container with networking disabled, no-new-privileges, all Linux capabilities dropped, CPU/memory/PID limits, and an ephemeral password. It then checks the Alembic revision and seven core tables. The disposable container and plaintext restore file are removed on exit. The source encrypted archive is not changed.

Set `TMPDIR` to an approved encrypted or memory-backed temporary filesystem for stricter host-at-rest requirements. Deleting a temporary file does not guarantee secure erasure from SSDs or copy-on-write filesystems.

## Key lifecycle and recovery boundaries

- The key and key ID must be retained separately from the backup archive. Losing the key makes the backup unrecoverable.
- Keep a protected mapping from each key ID to its secret-manager version and retention period.
- Rotate keys according to organizational policy. Do not delete an old key version while backups encrypted with that key are still within the required retention period.
- SHA-256 detects accidental corruption; AES-GCM verifies authenticity of encrypted data. Neither protects a backup if an attacker can replace both the archive and its checksum and also obtain the encryption key.
- The script does not configure off-site replication, a KMS/HSM, automatic rotation, scheduled backups, retention, RPO/RTO targets or recurring restore drills.
- Backup encryption at rest is one control, not a complete disaster-recovery plan.

## CI coverage

GitHub Actions generates an ephemeral test key and key ID for the backup/restore integration test. CI verifies that a valid encrypted backup restores, a modified ciphertext is rejected, the wrong key fails authentication, the disposable database is cleaned up, and no plaintext archive remains in the backup directory.
