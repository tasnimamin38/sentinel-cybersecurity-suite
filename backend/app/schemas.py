from datetime import datetime

from pydantic import BaseModel, Field


class AssessmentRequest(BaseModel):
    domain: str = Field(
        min_length=3, max_length=253, description="An authorized DNS hostname only."
    )


class AssessmentResponse(BaseModel):
    id: str
    target: str
    status: str
    score: int
    risk_level: str
    findings: list[dict]
    evidence: dict
    created_at: datetime


class OverviewResponse(BaseModel):
    assessment_count: int
    findings_count: int
    high_risk_count: int
    authorized_domains: list[str]
