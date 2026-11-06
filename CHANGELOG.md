# Changelog

All notable changes to SENTINEL are documented here.

## 0.18.0-pre — 2026-11-06

### Added
- Streaming AES-256-GCM encryption for PostgreSQL custom-format backups before publication.
- Versioned backup envelope with fresh random nonce, authenticated header and non-secret key ID binding.
- Restore verification authenticates and decrypts into a private temporary file before passing the archive to a network-isolated disposable PostgreSQL container.
- Required operator-managed 32-byte encryption key and key-version identifier; the key is never embedded in the archive or repository.
- Regression coverage for multi-chunk round trips, wrong-key rejection, key-ID mismatch, tamper detection, malformed archives and no-overwrite behavior.
- Encrypted-backup and restore runbook with key custody and recovery limitations.

### Security and operational boundaries
- Backup encryption uses AES-256-GCM; SHA-256 remains an early corruption check, not an authenticity guarantee.
- The encryption key and key-ID mapping must be retained separately. Losing the key makes backups unrecoverable.
- Temporary plaintext is permission-restricted and removed on exit, but file deletion is not certified secure erasure; use an approved encrypted or memory-backed temporary filesystem where required.
- KMS/HSM integration, off-site replication, automated rotation, scheduled retention, RPO/RTO targets and recurring restore drills remain operator/deployment responsibilities.
- No merge, release, tag or production deployment is implied by this pre-release branch.

## 0.17.0-pre — 2026-11-06

### Added
- Finding-linked incident audit timeline and bounded event trace in the operator console.
- Filterable per-incident event history for identities with `audit.read`.

### Boundaries
- The timeline displays recorded audit metadata and does not claim external immutable storage or SIEM delivery.

