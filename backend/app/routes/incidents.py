from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import desc, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.auth import require_api_key
from app.database import get_db
from app.models import Assessment, SecurityIncident
from app.schemas import (
    SecurityIncidentCreate,
    SecurityIncidentResponse,
    SecurityIncidentUpdate,
)
from app.services.audit import record_audit_event

router = APIRouter(prefix="/api/v1")
_ALLOWED_SEVERITIES = frozenset({"critical", "high", "medium", "low", "informational"})
_TRANSITIONS = {
    "open": frozenset({"acknowledged", "investigating", "accepted"}),
    "acknowledged": frozenset({"investigating", "contained", "resolved", "accepted"}),
    "investigating": frozenset({"contained", "resolved", "accepted"}),
    "contained": frozenset({"investigating", "resolved", "accepted"}),
}


def _record_incident_event(
    db: Session,
    incident: SecurityIncident,
    event_type: str,
    changed_fields: list[str] | None = None,
) -> None:
    fields = ",".join(sorted(set(changed_fields or [])))
    record_audit_event(
        db,
        event_type=event_type,
        subject=incident.id,
        details=(
            f"incident_id={incident.id}; assessment_id={incident.assessment_id}; "
            f"asset_id={incident.asset_id or 'unavailable'}; finding_code={incident.finding_code}; "
            f"severity={incident.severity}; status={incident.status}; changed_fields={fields}"
        ),
    )


def _get_incident_for_update(db: Session, incident_id: str) -> SecurityIncident:
    incident = db.scalar(
        select(SecurityIncident).where(SecurityIncident.id == incident_id).with_for_update()
    )
    if incident is None:
        raise HTTPException(status_code=404, detail="Security incident not found.")
    return incident


@router.get(
    "/incidents",
    response_model=list[SecurityIncidentResponse],
    dependencies=[Depends(require_api_key)],
)
def list_security_incidents(
    state: Literal["open", "acknowledged", "investigating", "contained", "resolved", "accepted"]
    | None = Query(default=None, alias="status"),
    severity: Literal["critical", "high", "medium", "low", "informational"] | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
):
    query = select(SecurityIncident).order_by(desc(SecurityIncident.updated_at)).limit(limit)
    if state:
        query = query.where(SecurityIncident.status == state)
    if severity:
        query = query.where(SecurityIncident.severity == severity)
    return db.scalars(query).all()


@router.post(
    "/incidents",
    response_model=SecurityIncidentResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_api_key)],
)
def create_security_incident(
    payload: SecurityIncidentCreate,
    db: Session = Depends(get_db),
):
    assessment = db.get(Assessment, payload.assessment_id)
    if assessment is None:
        raise HTTPException(status_code=404, detail="Source assessment not found.")
    if assessment.status != "completed":
        raise HTTPException(
            status_code=409, detail="An incident can only be created from a completed assessment."
        )

    finding = next(
        (
            item
            for item in assessment.findings
            if isinstance(item, dict) and str(item.get("code") or "") == payload.finding_code
        ),
        None,
    )
    if finding is None:
        raise HTTPException(
            status_code=404, detail="The specified finding does not exist in the source assessment."
        )

    severity_value = str(finding.get("severity", "medium")).lower()
    if severity_value == "info":
        severity_value = "informational"
    if severity_value not in _ALLOWED_SEVERITIES:
        raise HTTPException(
            status_code=422, detail="The source finding has an unsupported severity."
        )

    title = str(finding.get("title") or finding.get("name") or payload.finding_code).strip()
    if not title:
        title = payload.finding_code
    incident = SecurityIncident(
        assessment_id=assessment.id,
        asset_id=assessment.asset_id,
        finding_code=payload.finding_code,
        title=title[:200],
        severity=severity_value,
        status="open",
        assignee=payload.assignee,
        due_at=payload.due_at,
        notes=payload.notes,
    )
    db.add(incident)
    try:
        # Flush assigns the database-generated incident ID before audit references it.
        db.flush()
        _record_incident_event(db, incident, "security.incident.created", ["created"])
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail="An incident already exists for this finding in the source assessment.",
        ) from exc
    db.refresh(incident)
    return incident


@router.patch(
    "/incidents/{incident_id}",
    response_model=SecurityIncidentResponse,
    dependencies=[Depends(require_api_key)],
)
def update_security_incident(
    incident_id: str,
    payload: SecurityIncidentUpdate,
    db: Session = Depends(get_db),
):
    incident = _get_incident_for_update(db, incident_id)
    changes = payload.model_dump(exclude_unset=True)
    if not changes:
        return incident

    changed_fields: list[str] = []
    requested_status = changes.get("status")
    if requested_status is not None and requested_status != incident.status:
        if requested_status not in _TRANSITIONS.get(incident.status, frozenset()):
            raise HTTPException(
                status_code=409,
                detail=f"Incident status cannot transition from {incident.status} to {requested_status}.",
            )
        incident.status = requested_status
        changed_fields.append("status")
        now = datetime.now(UTC)
        if requested_status in {"acknowledged", "investigating", "contained"}:
            incident.acknowledged_at = incident.acknowledged_at or now
        if requested_status in {"resolved", "accepted"}:
            incident.closed_at = now

    if "assignee" in changes and changes["assignee"] is not None:
        incident.assignee = changes["assignee"]
        changed_fields.append("assignee")
    if "due_at" in changes:
        incident.due_at = changes["due_at"]
        changed_fields.append("due_at")
    if "notes" in changes and changes["notes"] is not None:
        incident.notes = changes["notes"]
        changed_fields.append("notes")

    if changed_fields:
        incident.updated_at = datetime.now(UTC)
        _record_incident_event(db, incident, "security.incident.updated", changed_fields)
        db.commit()
        db.refresh(incident)
    return incident
