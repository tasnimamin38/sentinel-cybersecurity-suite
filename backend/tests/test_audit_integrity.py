import unittest
from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.database import Base
from app.models import AuditEvent
from app.services.audit import record_audit_event, verify_audit_chain


class AuditIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(self.engine)

    def tearDown(self):
        self.engine.dispose()

    def test_audit_helper_uses_the_authenticated_session_tenant_by_default(self):
        from app.models import Tenant

        tenant_id = "00000000-0000-4000-8000-00000000000c"
        with Session(self.engine) as db:
            db.add(
                Tenant(
                    id=tenant_id,
                    slug="audit-company",
                    name="Audit Company",
                    workspace_type="company",
                    status="active",
                )
            )
            db.commit()
            db.info["tenant_id"] = tenant_id
            item = record_audit_event(
                db,
                event_type="workspace.activity",
                subject="company-only",
            )
            db.commit()

            self.assertEqual(item.tenant_id, tenant_id)
            result = verify_audit_chain(db)
            self.assertTrue(result["integrity_valid"])
            self.assertEqual(result["total_events"], 1)

    def test_new_hash_linked_events_verify(self):
        with Session(self.engine) as db:
            db.add(record_audit_event(db, event_type="test.created", subject="unit-test"))
            db.commit()
            db.add(record_audit_event(db, event_type="test.updated", subject="unit-test"))
            db.commit()

            result = verify_audit_chain(db)
            self.assertTrue(result["integrity_valid"])
            self.assertEqual(result["verification_status"], "verified")
            self.assertEqual(result["sealed_events"], 2)

    def test_tampered_event_payload_is_detected(self):
        with Session(self.engine) as db:
            event = record_audit_event(db, event_type="test.created", subject="unit-test")
            db.commit()
            event.details = "modified after sealing"
            db.commit()

            result = verify_audit_chain(db)
            self.assertFalse(result["integrity_valid"])
            self.assertEqual(result["verification_status"], "invalid")
            self.assertTrue(any("Event-hash mismatch" in item for item in result["errors"]))

    def test_legacy_unsealed_events_are_not_reported_as_verified(self):
        with Session(self.engine) as db:
            db.add(
                AuditEvent(
                    id=str(uuid4()),
                    event_type="legacy.event",
                    subject="migration",
                    result="success",
                    details="pre-hash-chain record",
                    previous_hash=None,
                    event_hash=None,
                    created_at=datetime.now(UTC),
                )
            )
            db.commit()

            result = verify_audit_chain(db)
            self.assertFalse(result["integrity_valid"])
            self.assertEqual(result["verification_status"], "incomplete_legacy")
            self.assertEqual(result["legacy_unsealed_events"], 1)

    def test_empty_journal_is_not_claimed_as_verified(self):
        with Session(self.engine) as db:
            result = verify_audit_chain(db)
            self.assertFalse(result["integrity_valid"])
            self.assertEqual(result["verification_status"], "empty")

    def test_each_tenant_has_an_independent_hash_chain_and_sequence(self):
        from app.models import LEGACY_TENANT_ID

        second_tenant_id = "00000000-0000-4000-8000-000000000002"
        with Session(self.engine) as db:
            for tenant_id, label in (
                (LEGACY_TENANT_ID, "legacy"),
                (second_tenant_id, "company"),
            ):
                db.add(
                    record_audit_event(
                        db,
                        tenant_id=tenant_id,
                        event_type="workspace.created",
                        subject=label,
                    )
                )
                db.commit()
                db.add(
                    record_audit_event(
                        db,
                        tenant_id=tenant_id,
                        event_type="workspace.updated",
                        subject=label,
                    )
                )
                db.commit()

            legacy_events = (
                db.query(AuditEvent)
                .filter(AuditEvent.tenant_id == LEGACY_TENANT_ID)
                .order_by(AuditEvent.sequence_no)
                .all()
            )
            company_events = (
                db.query(AuditEvent)
                .filter(AuditEvent.tenant_id == second_tenant_id)
                .order_by(AuditEvent.sequence_no)
                .all()
            )
            self.assertEqual([event.sequence_no for event in legacy_events], [1, 2])
            self.assertEqual([event.sequence_no for event in company_events], [1, 2])

            legacy_result = verify_audit_chain(db, tenant_id=LEGACY_TENANT_ID)
            company_result = verify_audit_chain(db, tenant_id=second_tenant_id)
            self.assertTrue(legacy_result["integrity_valid"])
            self.assertTrue(company_result["integrity_valid"])
            self.assertEqual(legacy_result["total_events"], 2)
            self.assertEqual(company_result["total_events"], 2)
            self.assertEqual(
                legacy_events[0].previous_hash,
                company_events[0].previous_hash,
            )
            self.assertNotEqual(legacy_events[0].event_hash, company_events[0].event_hash)


if __name__ == "__main__":
    unittest.main()
