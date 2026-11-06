#!/usr/bin/env bash
set -Eeuo pipefail

if [[ $# -gt 1 ]]; then
  printf 'Usage: %s [backup-directory]\n' "$0" >&2
  exit 2
fi

command -v docker >/dev/null 2>&1 || { echo "Docker CLI is required." >&2; exit 1; }
command -v sha256sum >/dev/null 2>&1 || { echo "sha256sum is required." >&2; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "Docker Compose v2 is required." >&2; exit 1; }

backup_dir="./backups"
if [[ $# -eq 1 ]]; then backup_dir="$1"; fi
mkdir -p -- "$backup_dir"
chmod 700 -- "$backup_dir"
umask 077

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
backup_file="$backup_dir/sentinel-$timestamp.dump"
checksum_file="$backup_file.sha256"
if [[ -e "$backup_file" || -e "$checksum_file" ]]; then
  echo "A backup with this timestamp already exists; refusing to overwrite it." >&2
  exit 1
fi

temporary_backup="$(mktemp "$backup_dir/.sentinel-backup.XXXXXX")"
temporary_checksum="$temporary_backup.sha256"
cleanup() {
  rm -f -- "$temporary_backup" "$temporary_checksum"
}
trap cleanup EXIT

echo "Creating PostgreSQL custom-format backup from the Compose db service..."
docker compose exec -T db pg_dump \
  --username=sentinel \
  --dbname=sentinel \
  --format=custom \
  --no-owner \
  --no-acl > "$temporary_backup"

if [[ ! -s "$temporary_backup" ]]; then
  echo "Backup command returned an empty archive; refusing to publish it." >&2
  exit 1
fi

digest="$(sha256sum "$temporary_backup" | awk '{print $1}')"
printf '%s  %s\n' "$digest" "$(basename -- "$backup_file")" > "$temporary_checksum"

mv -- "$temporary_backup" "$backup_file"
if ! mv -- "$temporary_checksum" "$checksum_file"; then
  rm -f -- "$backup_file"
  echo "Could not publish the checksum sidecar; removed the incomplete backup." >&2
  exit 1
fi

printf 'Backup created: %s\n' "$backup_file"
printf 'SHA-256 sidecar: %s\n' "$checksum_file"
echo "The archive is not encrypted. Encrypt it before off-host transfer or production retention."
