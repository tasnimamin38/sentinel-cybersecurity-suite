#!/usr/bin/env bash
set -Eeuo pipefail

if [[ $# -gt 1 ]]; then
  printf 'Usage: %s [backup-directory]\n' "$0" >&2
  exit 2
fi

command -v docker >/dev/null 2>&1 || { echo "Docker CLI is required." >&2; exit 1; }
command -v sha256sum >/dev/null 2>&1 || { echo "sha256sum is required." >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "Python 3 is required for backup encryption." >&2; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "Docker Compose v2 is required." >&2; exit 1; }
: "${SENTINEL_BACKUP_ENCRYPTION_KEY:?Set SENTINEL_BACKUP_ENCRYPTION_KEY from an operator-managed secret store.}"
: "${SENTINEL_BACKUP_ENCRYPTION_KEY_ID:?Set SENTINEL_BACKUP_ENCRYPTION_KEY_ID to the non-secret key version identifier.}"

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
backend_dir="$(cd -- "$script_dir/.." && pwd)"
backup_dir="./backups"
if [[ $# -eq 1 ]]; then backup_dir="$1"; fi
mkdir -p -- "$backup_dir"
chmod 700 -- "$backup_dir"
umask 077

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
backup_file="$backup_dir/sentinel-$timestamp.dump.enc"
checksum_file="$backup_file.sha256"
if [[ -e "$backup_file" || -e "$checksum_file" ]]; then
  echo "A backup with this timestamp already exists; refusing to overwrite it." >&2
  exit 1
fi

temporary_dir="$(mktemp -d "$backup_dir/.sentinel-backup.XXXXXX")"
temporary_encrypted="$temporary_dir/archive.dump.enc"
temporary_checksum="$temporary_dir/archive.dump.enc.sha256"
cleanup() {
  rm -rf -- "$temporary_dir"
}
trap cleanup EXIT
chmod 700 -- "$temporary_dir"

echo "Creating and encrypting PostgreSQL custom-format backup directly from the database stream..."
docker compose exec -T db pg_dump \
  --username=sentinel \
  --dbname=sentinel \
  --format=custom \
  --no-owner \
  --no-acl \
  | PYTHONPATH="$backend_dir${PYTHONPATH:+:$PYTHONPATH}" python3 -m app.services.backup_crypto \
      encrypt-stdin "$temporary_encrypted"

if [[ ! -s "$temporary_encrypted" ]]; then
  echo "Encrypted backup is missing or empty; refusing to publish it." >&2
  exit 1
fi
chmod 600 -- "$temporary_encrypted"

digest="$(sha256sum "$temporary_encrypted" | awk '{print $1}')"
printf '%s  %s\n' "$digest" "$(basename -- "$backup_file")" > "$temporary_checksum"

mv -- "$temporary_encrypted" "$backup_file"
if ! mv -- "$temporary_checksum" "$checksum_file"; then
  rm -f -- "$backup_file"
  echo "Could not publish the checksum sidecar; removed the incomplete backup." >&2
  exit 1
fi
chmod 600 -- "$backup_file" "$checksum_file"

printf 'Encrypted backup created: %s\n' "$backup_file"
printf 'SHA-256 sidecar: %s\n' "$checksum_file"
printf 'Encryption: AES-256-GCM; key ID: %s (key material not stored in the archive).\n' "$SENTINEL_BACKUP_ENCRYPTION_KEY_ID"
