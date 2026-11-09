import hashlib
import json
from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import desc, select, text
from sqlalchemy.orm import Session

from app.models import LEGACY_TENANT_ID, AuditEvent

_GENESIS = "0" * 64
_POSTGRES_AUDIT_LOCK_NAMESPACE = 7812340912345


def _tenant_lock_key(tenant_id: str) -> int:
    digest = hashlib.sha256(tenant_id.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], byteorder="big", signed=True)


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _event_payload(event: AuditEvent, previous_hash: str) -> bytes:
    payload = {
        "id": event.id,
        "sequence_no": event.sequence_no,
        "event_type": event.event_type,
        "subject": event.subject,
        "result": event.result,
        "details": event.details,
        "created_at": _utc(event.created_at).isoformat(),
        "previous_hash": previous_hash,
    }
    # Preserve hashes from the original single-tenant journal during migration.
    # New non-legacy chains cryptographically bind each event to its tenant.
    if event.tenant_id != LEGACY_TENANT_ID:
        payload["tenant_id"] = event.tenant_id
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def record_audit_event(
    db: Session,
    *,
    event_type: str,
    subject: str = "",
    result: str = "success",
    details: str = "",
    tenant_id: str = LEGACY_TENANT_ID,
) -> AuditEvent:
    """Append a sequence-numbered, hash-linked event.

    PostgreSQL serializes writers independently per tenant. A tenant-scoped unique
    sequence constraint provides a second integrity guard at the storage boundary.
    """
    if not tenant_id:
        raise ValueError("tenant_id is required for audit events.")

    if db.bind is not None and db.bind.dialect.name == "postgresql":
        lock_key = _POSTGRES_AUDIT_LOCK_NAMESPACE ^ _tenant_lock_key(tenant_id)
        db.execute(text("SELECT pg_advisory_xact_lock(:lock_key)"), {"lock_key": lock_key})

    latest = db.scalar(
        select(AuditEvent)
        .where(AuditEvent.tenant_id == tenant_id, AuditEvent.sequence_no.is_not(None))
        .order_by(desc(AuditEvent.sequence_no))
        .limit(1)
    )
    next_sequence = (latest.sequence_no + 1) if latest and latest.sequence_no else 1
    previous_hash = latest.event_hash if latest and latest.event_hash else _GENESIS
    event = AuditEvent(
        id=str(uuid4()),
        tenant_id=tenant_id,
        sequence_no=next_sequence,
        event_type=event_type,
        subject=subject[:253],
        result=result[:24],
        details=details[:4000],
        previous_hash=previous_hash,
        created_at=datetime.now(UTC),
    )
    event.event_hash = hashlib.sha256(_event_payload(event, previous_hash)).hexdigest()
    db.add(event)
    return event


def verify_audit_chain(db: Session, *, tenant_id: str = LEGACY_TENANT_ID) -> dict:
    if not tenant_id:
        raise ValueError("tenant_id is required to verify an audit chain.")

    events = db.scalars(
        select(AuditEvent)
        .where(AuditEvent.tenant_id == tenant_id)
        .order_by(
            AuditEvent.sequence_no.asc().nullsfirst(),
            AuditEvent.created_at,
            AuditEvent.id,
        )
    ).all()
    expected_previous = _GENESIS
    expected_sequence = 1
    sealed = 0
    legacy_unsealed = 0
    errors: list[str] = []
    chain_started = False
    verified_until: str | None = None

    for event in events:
        if event.sequence_no is None:
            legacy_unsealed += 1
            if chain_started:
                errors.append(f"Unsequenced event appears inside the sealed chain: {event.id}")
            continue
        if event.sequence_no != expected_sequence:
            errors.append(
                f"Sequence discontinuity at event {event.id}: expected {expected_sequence}, found {event.sequence_no}"
            )
        expected_sequence = event.sequence_no + 1
        if not event.event_hash or not event.previous_hash:
            legacy_unsealed += 1
            if chain_started:
                errors.append(f"Unsealed event appears inside the sealed chain: {event.id}")
            continue
        chain_started = True
        if event.previous_hash != expected_previous:
            errors.append(f"Previous-hash mismatch at event {event.id}")
        computed = hashlib.sha256(_event_payload(event, event.previous_hash)).hexdigest()
        if computed != event.event_hash:
            errors.append(f"Event-hash mismatch at event {event.id}")
        expected_previous = event.event_hash
        verified_until = _utc(event.created_at).isoformat()
        sealed += 1

    integrity_valid = bool(events) and not errors and legacy_unsealed == 0 and sealed == len(events)
    if errors:
        verification_status = "invalid"
    elif legacy_unsealed:
        verification_status = "incomplete_legacy"
    elif not events:
        verification_status = "empty"
    else:
        verification_status = "verified"

    return {
        "integrity_valid": integrity_valid,
        "verification_status": verification_status,
        "total_events": len(events),
        "sealed_events": sealed,
        "legacy_unsealed_events": legacy_unsealed,
        "verified_until": verified_until,
        "errors": errors[:50],
        "assurance_note": (
            "Sequence numbers make event ordering explicit and hash chaining makes accidental or "
            "partial tampering detectable. This is not immutable storage and cannot defeat a "
            "privileged database operator who rewrites the full chain. Export signed checkpoints "
            "to independently controlled storage for stronger assurance."
        ),
    }
