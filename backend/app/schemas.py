from datetime import UTC, datetime, timedelta

from pydantic import BaseModel, ConfigDict, Field, field_validator


class AssessmentRequest(BaseModel):
    domain: str = Field(
        min_length=3, max_length=253, description="An authorized DNS hostname only."
    )


class AssessmentResponse(BaseModel):
    id: str
    asset_id: str | None = None
    target: str
    status: str
    score: int
    risk_level: str
    findings: list[dict]
    evidence: dict
    created_at: datetime


class AssessmentJobCreate(BaseModel):
    asset_id: str = Field(min_length=36, max_length=36)
    scheduled_for: datetime | None = None

    @field_validator("scheduled_for")
    @classmethod
    def validate_schedule(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return value
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Scheduled time must include a timezone.")
        current = datetime.now(UTC)
        if value <= current:
            raise ValueError("Scheduled time must be in the future.")
        if value > current + timedelta(days=30):
            raise ValueError("Scheduled time cannot be more than 30 days ahead.")
        return value


class AssessmentJobResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    asset_id: str | None
    target: str
    status: str
    available_at: datetime
    attempts: int
    max_attempts: int
    manual_retries: int
    worker_id: str | None
    lease_expires_at: datetime | None
    heartbeat_at: datetime | None
    cancel_requested_at: datetime | None
    started_at: datetime | None
    completed_at: datetime | None
    assessment_id: str | None
    last_error: str | None
    created_at: datetime
    updated_at: datetime


class OverviewResponse(BaseModel):
    assessment_count: int
    findings_count: int
    high_risk_count: int
    authorized_domains: list[str]
    asset_count: int = 0
    active_asset_count: int = 0
    open_remediation_count: int = 0


class AssetCreate(BaseModel):
    hostname: str = Field(min_length=3, max_length=253)
    name: str = Field(min_length=2, max_length=140)
    owner: str = Field(min_length=2, max_length=120)
    environment: str = Field(default="production", pattern="^(production|staging|development|lab)$")
    criticality: float = Field(default=1.0, ge=0.5, le=1.5)
    authorization_expires_at: datetime
    authorization_reference: str = Field(min_length=4, max_length=120)
    tags: list[str] = Field(default_factory=list, max_length=20)

    @field_validator("authorization_expires_at")
    @classmethod
    def authorization_must_be_timezone_aware_and_future(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Authorization expiry must include a timezone.")
        if value <= datetime.now(UTC):
            raise ValueError("Authorization expiry must be in the future.")
        return value

    @field_validator("tags")
    @classmethod
    def validate_tags(cls, values: list[str]) -> list[str]:
        clean = [value.strip() for value in values]
        if any(not value or len(value) > 32 for value in clean):
            raise ValueError("Tags must contain 1 to 32 characters.")
        return list(dict.fromkeys(clean))


class AssetUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=140)
    owner: str | None = Field(default=None, min_length=2, max_length=120)
    environment: str | None = Field(default=None, pattern="^(production|staging|development|lab)$")
    criticality: float | None = Field(default=None, ge=0.5, le=1.5)
    authorization_expires_at: datetime | None = None
    authorization_reference: str | None = Field(default=None, min_length=4, max_length=120)
    status: str | None = Field(default=None, pattern="^(active|paused|inactive)$")
    tags: list[str] | None = Field(default=None, max_length=20)

    @field_validator("authorization_expires_at")
    @classmethod
    def validate_expiry(cls, value: datetime | None) -> datetime | None:
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise ValueError("Authorization expiry must include a timezone.")
        if value is not None and value <= datetime.now(UTC):
            raise ValueError("Authorization expiry must be in the future.")
        return value


class AssetResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    hostname: str
    name: str
    owner: str
    environment: str
    criticality: float
    authorization_expires_at: datetime
    authorization_reference: str
    status: str
    tags: list[str]
    created_at: datetime
    updated_at: datetime


class RemediationCreate(BaseModel):
    assessment_id: str
    finding_code: str = Field(min_length=2, max_length=100)
    assignee: str = Field(default="", max_length=120)
    due_at: datetime | None = None
    notes: str = Field(default="", max_length=4000)

    @field_validator("due_at")
    @classmethod
    def validate_due_at(cls, value: datetime | None) -> datetime | None:
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise ValueError("Due date must include a timezone.")
        return value


class RemediationUpdate(BaseModel):
    assignee: str | None = Field(default=None, max_length=120)
    status: str | None = Field(default=None, pattern="^(open|in_progress|resolved|accepted)$")
    due_at: datetime | None = None
    notes: str | None = Field(default=None, max_length=4000)

    @field_validator("due_at")
    @classmethod
    def validate_update_due_at(cls, value: datetime | None) -> datetime | None:
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise ValueError("Due date must include a timezone.")
        return value


class RemediationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    assessment_id: str
    asset_id: str | None
    finding_code: str
    title: str
    severity: str
    assignee: str
    status: str
    due_at: datetime | None
    notes: str
    created_at: datetime
    updated_at: datetime


class SecretScanRequest(BaseModel):
    content: str = Field(min_length=1, max_length=262_144)
