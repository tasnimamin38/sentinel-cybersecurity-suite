#!/usr/bin/env bash
set -Eeuo pipefail

if [[ $# -ne 1 ]]; then
  printf 'Usage: %s /path/to/sentinel-backup.dump\n' "$0" >&2
  exit 2
fi

command -v docker >/dev/null 2>&1 || { echo "Docker CLI is required." >&2; exit 1; }
command -v sha256sum >/dev/null 2>&1 || { echo "sha256sum is required." >&2; exit 1; }

backup_file="$1"
[[ -f "$backup_file" ]] || { echo "Backup archive not found." >&2; exit 1; }
backup_dir="$(cd -- "$(dirname -- "$backup_file")" && pwd)"
backup_base="$(basename -- "$backup_file")"
checksum_base="$backup_base.sha256"
[[ -f "$backup_dir/$checksum_base" ]] || { echo "SHA-256 sidecar is missing." >&2; exit 1; }

(
  cd -- "$backup_dir"
  sha256sum --check -- "$checksum_base"
)

# Pull before creating the isolated container; the container itself has no network.
postgres_image="postgres:16-alpine"
docker image inspect "$postgres_image" >/dev/null 2>&1 || docker pull "$postgres_image"

container_name="sentinel-restore-check-$$-$RANDOM"
temporary_password="$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
[[ -n "$temporary_password" ]] || { echo "Could not generate an ephemeral password." >&2; exit 1; }

cleanup() {
  if docker container inspect "$container_name" >/dev/null 2>&1; then
    docker stop "$container_name" >/dev/null 2>&1 || docker rm -f "$container_name" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

echo "Starting a disposable PostgreSQL 16 restore target (network disabled)..."
docker run --detach --rm \
  --name "$container_name" \
  --user postgres \
  --network none \
  --memory 1g \
  --cpus 2 \
  --pids-limit 256 \
  --security-opt no-new-privileges:true \
  --cap-drop ALL \
  --env "POSTGRES_PASSWORD=$temporary_password" \
  "$postgres_image" >/dev/null

ready=0
for ((attempt=0; attempt<45; attempt++)); do
  if docker exec "$container_name" pg_isready --quiet --username=postgres --dbname=postgres; then
    ready=1
    break
  fi
  sleep 1
done
if [[ "$ready" -ne 1 ]]; then
  echo "Disposable PostgreSQL did not become ready." >&2
  docker logs "$container_name" >&2 || true
  exit 1
fi

echo "Restoring the archive into the disposable database..."
docker exec -i "$container_name" pg_restore \
  --exit-on-error \
  --single-transaction \
  --no-owner \
  --no-acl \
  --username=postgres \
  --dbname=postgres < "$backup_file"

revision="$(docker exec "$container_name" psql -X -v ON_ERROR_STOP=1 -U postgres -d postgres -Atqc \
  'SELECT version_num FROM public.alembic_version LIMIT 1')"
[[ -n "$revision" ]] || { echo "Restore check failed: Alembic revision is missing." >&2; exit 1; }

table_count="$(docker exec "$container_name" psql -X -v ON_ERROR_STOP=1 -U postgres -d postgres -Atqc \
  "SELECT count(*) FROM unnest(ARRAY['assets','assessments','remediation_tasks','audit_events','assessment_jobs','api_credentials','api_credential_usage']) AS required(name) WHERE to_regclass('public.' || required.name) IS NOT NULL")"
if [[ "$table_count" -ne 7 ]]; then
  echo "Restore check failed: expected core SENTINEL tables are missing." >&2
  exit 1
fi

printf 'Restore verification passed. Alembic revision: %s; core tables: %s/7.\n' "$revision" "$table_count"
echo "The disposable database will now be stopped and deleted; the source archive is unchanged."
