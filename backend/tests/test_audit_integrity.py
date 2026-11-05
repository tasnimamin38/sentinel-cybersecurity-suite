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


if __name__ == "__main__":
    unittest.main()
