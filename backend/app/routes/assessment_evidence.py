from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.auth import ApiPrincipal, require_api_key
from app.database import get_db
from app.models import Assessment
from app.services.assessment_integrity import verify_assessment_evidence

router = APIRouter(prefix="/api/v1")


@router.get(
    "/assessments/{assessment_id}/evidence-integrity",
    dependencies=[Depends(require_api_key)],
)
def read_assessment_evidence_integrity(
    assessment_id: str,
    db: Session = Depends(get_db),
):
    """Verify the persisted assessment snapshot against its audit-chain digest."""
    assessment = db.get(Assessment, assessment_id)
    if assessment is None or not principal.can_access_asset(assessment.asset_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Assessment not found.",
        )
    return verify_assessment_evidence(db, assessment)
