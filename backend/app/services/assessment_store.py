from sqlalchemy import delete, desc, select
from sqlalchemy.orm import Session

from app.models import Assessment, Asset, RemediationTask
from app.services.assessment_integrity import assessment_evidence_digest
from app.services.audit import record_audit_event


def add_assessment_result(
    db: Session,
    result: dict,
    asset: Asset | None,
    max_records: int,
) -> Assessment:
    """Add assessment evidence and its audit event without committing the transaction."""
    item = Assessment(
        asset_id=asset.id if asset else None,
        target=result["target"],
        status=result["status"],
        score=result["score"],
        risk_level=result["risk_level"],
        findings=result["findings"],
        evidence={
            **result["evidence"],
            "risk_explanation": result["risk_explanation"],
        },
    )
    db.add(item)
    db.flush()
    db.add(
        record_audit_event(
            db,
            event_type="assessment.completed",
            subject=result["target"],
            details=(
                f"assessment_id={item.id}; evidence_sha256={assessment_evidence_digest(item)}; "
                f"asset_id={item.asset_id or 'unregistered'}; score={result['score']}; "
                f"findings={len(result['findings'])}"
            ),
        )
    )
    excess_ids = db.scalars(
        select(Assessment.id)
        .where(
            Assessment.id != item.id,
            Assessment.id.not_in(select(RemediationTask.assessment_id)),
        )
        .order_by(desc(Assessment.created_at), desc(Assessment.id))
        .offset(max_records - 1)
    ).all()
    if excess_ids:
        db.execute(delete(Assessment).where(Assessment.id.in_(excess_ids)))
    return item
