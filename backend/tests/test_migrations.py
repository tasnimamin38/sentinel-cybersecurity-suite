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
            self.assertIn("api_credential_usage", tables)
            self.assertIn("security_incidents", tables)
            self.assertIn("tenants", tables)

            expected_tenant_tables = (
                "assets",
                "assessments",
                "remediation_tasks",
                "audit_events",
                "assessment_jobs",
                "api_credentials",
                "api_credential_usage",
                "security_incidents",
            )
            for table_name in expected_tenant_tables:
                columns = {
                    row[1]
                    for row in connection.execute(
                        f"PRAGMA table_info({table_name})"
                    ).fetchall()
                }
                self.assertIn("tenant_id", columns, msg=table_name)
                tenant_foreign_keys = connection.execute(
                    f"PRAGMA foreign_key_list({table_name})"
                ).fetchall()
                self.assertTrue(
                    any(
                        row[2] == "tenants" and row[3] == "tenant_id" and row[4] == "id"
                        for row in tenant_foreign_keys
                    ),
                    msg=f"{table_name} must reference tenants.id",
                )
                tenant_id = connection.execute(
                    f"SELECT DISTINCT tenant_id FROM {table_name}"
                ).fetchall()
                self.assertTrue(
                    all(item[0] == "00000000-0000-4000-8000-000000000001" for item in tenant_id),
                    msg=table_name,
                )

            legacy_tenant = connection.execute(
                "SELECT slug, name, status FROM tenants "
                "WHERE id='00000000-0000-4000-8000-000000000001'"
            ).fetchone()
            self.assertEqual(
                legacy_tenant,
                ("legacy-default", "Legacy Installation", "active"),
            )
            usage_columns = {
                row[1]
                for row in connection.execute("PRAGMA table_info(api_credential_usage)").fetchall()
            }
            self.assertIn("minute_window_start", usage_columns)
            self.assertIn("minute_requests", usage_columns)
            self.assertIn("day_window_start", usage_columns)
            self.assertIn("day_requests", usage_columns)

            assessment_columns = {
                row[1] for row in connection.execute("PRAGMA table_info(assessments)").fetchall()
            }
            credential_columns = {
                row[1]
                for row in connection.execute("PRAGMA table_info(api_credentials)").fetchall()
            }
            audit_columns = {
                row[1] for row in connection.execute("PRAGMA table_info(audit_events)").fetchall()
            }
            self.assertIn("asset_id", assessment_columns)
            self.assertIn("event_hash", audit_columns)
            self.assertIn("previous_hash", audit_columns)
            self.assertIn("sequence_no", audit_columns)
            self.assertIn("rate_limit_per_minute", credential_columns)
            self.assertIn("daily_request_limit", credential_columns)
            self.assertIn("rotated_to_id", credential_columns)
            self.assertIn("rotation_grace_expires_at", credential_columns)

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
            incident_columns = {
                row[1]
                for row in connection.execute("PRAGMA table_info(security_incidents)").fetchall()
            }
            self.assertIn("assessment_id", incident_columns)
            self.assertIn("finding_code", incident_columns)
            incident_indexes = {
                row[1]
                for row in connection.execute("PRAGMA index_list(security_incidents)").fetchall()
            }
            self.assertIn("ix_security_incidents_status_severity", incident_indexes)
            revision = connection.execute("SELECT version_num FROM alembic_version").fetchone()
            self.assertEqual(revision[0], "0008_tenant_registry_and_ownership")
            self.assertIn("asset_scope_mode", credential_columns)
            self.assertIn("asset_scope_ids", credential_columns)
            connection.close()


if __name__ == "__main__":
    unittest.main()
