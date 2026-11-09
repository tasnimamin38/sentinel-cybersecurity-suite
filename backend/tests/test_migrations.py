import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]


class LegacyMigrationTests(unittest.TestCase):
    def test_v02_database_upgrades_without_losing_assessment_or_audit_rows(self):
        with tempfile.TemporaryDirectory(prefix="sentinel-migration-") as temp_dir:
            database_path = Path(temp_dir) / "legacy-v02.sqlite"
            connection = sqlite3.connect(database_path)
            connection.executescript(
                """
                CREATE TABLE assessments (
                    id VARCHAR(36) NOT NULL PRIMARY KEY,
                    target VARCHAR(253) NOT NULL,
                    status VARCHAR(24) NOT NULL,
                    score INTEGER NOT NULL,
                    risk_level VARCHAR(24) NOT NULL,
                    findings JSON NOT NULL,
                    evidence JSON NOT NULL,
                    created_at DATETIME NOT NULL
                );
                CREATE INDEX ix_assessments_target ON assessments (target);
                CREATE TABLE audit_events (
                    id VARCHAR(36) NOT NULL PRIMARY KEY,
                    event_type VARCHAR(80) NOT NULL,
                    subject VARCHAR(253) NOT NULL,
                    result VARCHAR(24) NOT NULL,
                    details TEXT NOT NULL,
                    created_at DATETIME NOT NULL
                );
                CREATE INDEX ix_audit_events_event_type ON audit_events (event_type);
                INSERT INTO assessments
                    (id, target, status, score, risk_level, findings, evidence, created_at)
                VALUES
                    ('legacy-assessment-1', 'app.example.com', 'completed', 42, 'moderate',
                     '[]', '{}', '2026-11-05 12:00:00');
                INSERT INTO audit_events
                    (id, event_type, subject, result, details, created_at)
                VALUES
                    ('legacy-audit-1', 'assessment.completed', 'app.example.com', 'success',
                     'legacy event must be preserved', '2026-11-05 12:01:00');
                """
            )
            connection.commit()
            connection.close()

            env = os.environ.copy()
            env["SENTINEL_ENVIRONMENT"] = "test"
            env["SENTINEL_DATABASE_URL"] = "sqlite:///" + database_path.as_posix()
            env["SENTINEL_API_KEY"] = "M" * 40
            env["SENTINEL_ALLOWED_DOMAINS"] = "example.com"
            run = subprocess.run(
                [sys.executable, "-m", "alembic", "upgrade", "head"],
                cwd=BACKEND,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(run.returncode, 0, msg=run.stdout + run.stderr)

            connection = sqlite3.connect(database_path)
            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
            self.assertIn("assets", tables)
            self.assertIn("remediation_tasks", tables)
            self.assertIn("alembic_version", tables)
            self.assertIn("api_credentials", tables)
            self.assertIn("assessment_jobs", tables)

            assessment_columns = {
                row[1] for row in connection.execute("PRAGMA table_info(assessments)").fetchall()
            }
            audit_columns = {
                row[1] for row in connection.execute("PRAGMA table_info(audit_events)").fetchall()
            }
            self.assertIn("asset_id", assessment_columns)
            self.assertIn("event_hash", audit_columns)
            self.assertIn("previous_hash", audit_columns)
            self.assertIn("sequence_no", audit_columns)

            assessment = connection.execute(
                "SELECT target, score FROM assessments WHERE id='legacy-assessment-1'"
            ).fetchone()
            audit = connection.execute(
                "SELECT details, event_hash, sequence_no FROM audit_events WHERE id='legacy-audit-1'"
            ).fetchone()
            self.assertEqual(assessment, ("app.example.com", 42))
            self.assertEqual(audit[0], "legacy event must be preserved")
            self.assertIsNone(audit[1])
            self.assertEqual(audit[2], 1)
            revision = connection.execute("SELECT version_num FROM alembic_version").fetchone()
            self.assertEqual(revision[0], "0005_tenant_registry")
            connection.close()


LEGACY_TENANT_ID = "00000000-0000-4000-8000-000000000001"


def _migration_environment(database_path: Path) -> dict[str, str]:
    env = os.environ.copy()
    env["SENTINEL_ENVIRONMENT"] = "test"
    env["SENTINEL_DATABASE_URL"] = "sqlite:///" + database_path.as_posix()
    env["SENTINEL_API_KEY"] = "M" * 40
    env["SENTINEL_ALLOWED_DOMAINS"] = "example.com"
    return env


def _run_migration(
    database_path: Path,
    command: str,
    revision: str,
) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "alembic", command, revision],
        cwd=BACKEND,
        env=_migration_environment(database_path),
        capture_output=True,
        text=True,
        check=False,
    )

def _seed_legacy_operational_rows(database_path: Path) -> None:
    connection = sqlite3.connect(database_path)
    # The legacy tenant row is seeded by revision 0005, so old rows are
    # inserted before enabling FK enforcement in this pre-migration fixture.
    connection.execute("PRAGMA foreign_keys = OFF")
    connection.executescript(
        """
        INSERT INTO assets
            (id, hostname, name, owner, environment, criticality,
             authorization_expires_at, authorization_reference, status,
             tags, created_at, updated_at)
        VALUES
            ('legacy-asset-1', 'app.example.com', 'Legacy application', 'Security',
             'production', 1.0, '2030-01-01 00:00:00', 'legacy-approval',
             'active', '[]', '2026-11-05 12:00:00', '2026-11-05 12:00:00');

        INSERT INTO assessments
            (id, asset_id, target, status, score, risk_level, findings, evidence, created_at)
        VALUES
            ('legacy-assessment-1', 'legacy-asset-1', 'app.example.com',
             'completed', 42, 'moderate', '[]', '{}', '2026-11-05 12:01:00');

        INSERT INTO remediation_tasks
            (id, assessment_id, asset_id, finding_code, title, severity, assignee,
             status, due_at, notes, created_at, updated_at)
        VALUES
            ('legacy-remediation-1', 'legacy-assessment-1', 'legacy-asset-1',
             'TLS-001', 'Review TLS policy', 'medium', 'Security',
             'open', NULL, 'Preserve legacy task', '2026-11-05 12:02:00',
             '2026-11-05 12:02:00');

        INSERT INTO audit_events
            (id, event_type, subject, result, details, sequence_no,
             previous_hash, event_hash, created_at)
        VALUES
            ('legacy-audit-1', 'assessment.completed', 'app.example.com',
             'success', 'legacy audit record', 1, NULL, NULL, '2026-11-05 12:03:00');

        INSERT INTO assessment_jobs
            (id, asset_id, target, status, available_at, attempts, max_attempts,
             manual_retries, worker_id, lease_expires_at, heartbeat_at,
             cancel_requested_at, started_at, completed_at, assessment_id,
             idempotency_key_hash, last_error, created_at, updated_at)
        VALUES
            ('legacy-job-1', 'legacy-asset-1', 'app.example.com', 'succeeded',
             '2026-11-05 12:04:00', 1, 3, 0, NULL, NULL, NULL, NULL,
             '2026-11-05 12:04:00', '2026-11-05 12:05:00',
             'legacy-assessment-1', 'legacy-idempotency-hash', NULL,
             '2026-11-05 12:04:00', '2026-11-05 12:05:00');

        INSERT INTO api_credentials
            (id, label, role, key_hash, key_prefix, expires_at, revoked_at,
             created_by, created_at, last_used_at)
        VALUES
            ('legacy-credential-1', 'Legacy integration', 'admin',
             'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
             'legacy-prefix', NULL, NULL, 'bootstrap', '2026-11-05 12:06:00', NULL);
        """
    )
    connection.executescript(
        """
        CREATE UNIQUE INDEX legacy_global_hostname_unique ON assets (hostname);
        CREATE UNIQUE INDEX legacy_global_idempotency_unique
            ON assessment_jobs (idempotency_key_hash);
        CREATE UNIQUE INDEX legacy_global_audit_sequence_unique
            ON audit_events (sequence_no);
        """
    )
    connection.commit()
    connection.close()


class TenantRegistryMigrationTests(unittest.TestCase):
    def _create_legacy_database(self, database_path: Path) -> None:
        run = _run_migration(database_path, "upgrade", "0004_api_credentials")
        self.assertEqual(run.returncode, 0, msg=run.stdout + run.stderr)
        _seed_legacy_operational_rows(database_path)

    def test_tenant_upgrade_backfills_all_legacy_rows_and_preserves_history(self):
        with tempfile.TemporaryDirectory(prefix="sentinel-tenant-migration-") as temp_dir:
            database_path = Path(temp_dir) / "legacy.sqlite"
            self._create_legacy_database(database_path)

            run = _run_migration(database_path, "upgrade", "head")
            self.assertEqual(run.returncode, 0, msg=run.stdout + run.stderr)

            connection = sqlite3.connect(database_path)
            connection.execute("PRAGMA foreign_keys = ON")
            tenant = connection.execute(
                "SELECT id, slug, name, workspace_type FROM tenants WHERE id = ?",
                (LEGACY_TENANT_ID,),
            ).fetchone()
            self.assertEqual(
                tenant,
                (LEGACY_TENANT_ID, "legacy-installation", "Legacy Installation", "legacy"),
            )

            expected_tables = (
                "assets",
                "assessments",
                "remediation_tasks",
                "audit_events",
                "assessment_jobs",
                "api_credentials",
            )
            for table in expected_tables:
                columns = {
                    row[1] for row in connection.execute(f"PRAGMA table_info({table})").fetchall()
                }
                self.assertIn("tenant_id", columns, msg=f"{table} is missing tenant_id")
                count = connection.execute(
                    f"SELECT COUNT(*) FROM {table} WHERE tenant_id != ? OR tenant_id IS NULL",
                    (LEGACY_TENANT_ID,),
                ).fetchone()[0]
                self.assertEqual(count, 0, msg=f"{table} has rows outside the legacy tenant")

            self.assertEqual(
                connection.execute(
                    "SELECT hostname FROM assets WHERE id = 'legacy-asset-1'"
                ).fetchone()[0],
                "app.example.com",
            )
            self.assertEqual(
                connection.execute(
                    "SELECT details FROM audit_events WHERE id = 'legacy-audit-1'"
                ).fetchone()[0],
                "legacy audit record",
            )
            self.assertEqual(
                connection.execute(
                    "SELECT key_hash FROM api_credentials WHERE id = 'legacy-credential-1'"
                ).fetchone()[0],
                "a" * 64,
            )
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM tenant_memberships").fetchone()[0],
                0,
            )
            revision = connection.execute("SELECT version_num FROM alembic_version").fetchone()
            self.assertEqual(revision[0], "0005_tenant_registry")
            connection.close()

    def test_tenant_scoped_hostname_and_idempotency_constraints_prevent_cross_tenant_links(self):
        with tempfile.TemporaryDirectory(prefix="sentinel-tenant-isolation-") as temp_dir:
            database_path = Path(temp_dir) / "legacy.sqlite"
            self._create_legacy_database(database_path)
            run = _run_migration(database_path, "upgrade", "head")
            self.assertEqual(run.returncode, 0, msg=run.stdout + run.stderr)

            connection = sqlite3.connect(database_path)
            connection.execute("PRAGMA foreign_keys = ON")
            second_tenant = "00000000-0000-4000-8000-000000000002"
            connection.execute(
                """
                INSERT INTO tenants (id, slug, name, workspace_type, status, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    second_tenant,
                    "second-company",
                    "Second Company",
                    "company",
                    "active",
                    "2026-11-09 00:00:00",
                    "2026-11-09 00:00:00",
                ),
            )
            connection.execute(
                """
                INSERT INTO assets
                    (id, tenant_id, hostname, name, owner, environment, criticality,
                     authorization_expires_at, authorization_reference, status,
                     tags, created_at, updated_at)
                VALUES
                    (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "asset-company-2",
                    second_tenant,
                    "app.example.com",
                    "Company copy",
                    "Security",
                    "production",
                    1.0,
                    "2030-01-01 00:00:00",
                    "approved",
                    "active",
                    "[]",
                    "2026-11-09 00:00:00",
                    "2026-11-09 00:00:00",
                ),
            )
            connection.execute(
                """
                INSERT INTO audit_events
                    (id, tenant_id, event_type, subject, result, details,
                     sequence_no, previous_hash, event_hash, created_at)
                VALUES
                    (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "company-2-audit-1",
                    second_tenant,
                    "workspace.created",
                    "second company",
                    "success",
                    "first event for tenant two",
                    1,
                    "0" * 64,
                    "b" * 64,
                    "2026-11-09 00:00:01",
                ),
            )
            connection.commit()

            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM audit_events WHERE sequence_no = 1"
                ).fetchone()[0],
                2,
            )

            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    """
                    INSERT INTO assets
                        (id, tenant_id, hostname, name, owner, environment, criticality,
                         authorization_expires_at, authorization_reference, status,
                         tags, created_at, updated_at)
                    VALUES
                        (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "asset-company-2-duplicate",
                        second_tenant,
                        "app.example.com",
                        "Duplicate",
                        "Security",
                        "production",
                        1.0,
                        "2030-01-01 00:00:00",
                        "approved",
                        "active",
                        "[]",
                        "2026-11-09 00:00:02",
                        "2026-11-09 00:00:02",
                    ),
                )
            connection.rollback()
            connection.commit()

            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    """
                    INSERT INTO assessments
                        (id, tenant_id, asset_id, target, status, score, risk_level,
                         findings, evidence, created_at)
                    VALUES
                        (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "cross-tenant-assessment",
                        second_tenant,
                        "legacy-asset-1",
                        "app.example.com",
                        "completed",
                        0,
                        "informational",
                        "[]",
                        "{}",
                        "2026-11-09 00:01:00",
                    ),
                )
            connection.rollback()

            connection.execute(
                """
                INSERT INTO assessment_jobs
                    (id, tenant_id, asset_id, target, status, available_at,
                     attempts, max_attempts, manual_retries, worker_id,
                     lease_expires_at, heartbeat_at, cancel_requested_at,
                     started_at, completed_at, assessment_id, idempotency_key_hash,
                     last_error, created_at, updated_at)
                VALUES
                    (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "job-company-2",
                    second_tenant,
                    "asset-company-2",
                    "app.example.com",
                    "succeeded",
                    "2026-11-09 00:02:00",
                    1,
                    3,
                    0,
                    None,
                    None,
                    None,
                    None,
                    "2026-11-09 00:02:00",
                    "2026-11-09 00:03:00",
                    None,
                    "legacy-idempotency-hash",
                    None,
                    "2026-11-09 00:02:00",
                    "2026-11-09 00:03:00",
                ),
            )
            connection.commit()

            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    """
                    INSERT INTO assessment_jobs
                        (id, tenant_id, asset_id, target, status, available_at,
                         attempts, max_attempts, manual_retries, worker_id,
                         lease_expires_at, heartbeat_at, cancel_requested_at,
                         started_at, completed_at, assessment_id, idempotency_key_hash,
                         last_error, created_at, updated_at)
                    VALUES
                        (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "job-company-2-duplicate",
                        second_tenant,
                        "asset-company-2",
                        "app.example.com",
                        "succeeded",
                        "2026-11-09 00:02:10",
                        1,
                        3,
                        0,
                        None,
                        None,
                        None,
                        None,
                        "2026-11-09 00:02:10",
                        "2026-11-09 00:02:11",
                        None,
                        "legacy-idempotency-hash",
                        None,
                        "2026-11-09 00:02:10",
                        "2026-11-09 00:02:11",
                    ),
                )
            connection.rollback()
            connection.close()

    def test_tenant_migration_downgrade_refuses_to_remove_customer_workspaces(self):
        with tempfile.TemporaryDirectory(prefix="sentinel-tenant-downgrade-") as temp_dir:
            database_path = Path(temp_dir) / "legacy.sqlite"
            self._create_legacy_database(database_path)
            run = _run_migration(database_path, "upgrade", "head")
            self.assertEqual(run.returncode, 0, msg=run.stdout + run.stderr)

            connection = sqlite3.connect(database_path)
            connection.execute(
                """
                INSERT INTO tenants (id, slug, name, workspace_type, status, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "00000000-0000-4000-8000-000000000002",
                    "customer-company",
                    "Customer Company",
                    "company",
                    "active",
                    "2026-11-09 00:00:00",
                    "2026-11-09 00:00:00",
                ),
            )
            connection.commit()
            connection.close()

            run = _run_migration(database_path, "downgrade", "0004_api_credentials")
            self.assertNotEqual(
                run.returncode, 0, msg="downgrade must refuse customer tenant data"
            )
            connection = sqlite3.connect(database_path)
            tenant_count = connection.execute("SELECT COUNT(*) FROM tenants").fetchone()[0]
            self.assertEqual(tenant_count, 2)
            revision = connection.execute("SELECT version_num FROM alembic_version").fetchone()
            self.assertEqual(revision[0], "0005_tenant_registry")
            connection.close()

    def test_tenant_migration_downgrade_without_customer_workspaces_preserves_legacy_rows(self):
        with tempfile.TemporaryDirectory(prefix="sentinel-tenant-safe-downgrade-") as temp_dir:
            database_path = Path(temp_dir) / "legacy.sqlite"
            self._create_legacy_database(database_path)
            run = _run_migration(database_path, "upgrade", "head")
            self.assertEqual(run.returncode, 0, msg=run.stdout + run.stderr)

            run = _run_migration(database_path, "downgrade", "0004_api_credentials")
            self.assertEqual(run.returncode, 0, msg=run.stdout + run.stderr)

            connection = sqlite3.connect(database_path)
            self.assertEqual(
                connection.execute(
                    "SELECT target, score FROM assessments WHERE id = 'legacy-assessment-1'"
                ).fetchone(),
                ("app.example.com", 42),
            )
            self.assertEqual(
                connection.execute(
                    "SELECT details FROM audit_events WHERE id = 'legacy-audit-1'"
                ).fetchone()[0],
                "legacy audit record",
            )
            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
            self.assertNotIn("tenants", tables)
            revision = connection.execute("SELECT version_num FROM alembic_version").fetchone()
            self.assertEqual(revision[0], "0004_api_credentials")
            connection.close()


if __name__ == "__main__":
    unittest.main()
