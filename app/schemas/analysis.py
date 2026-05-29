from datetime import datetime

from pydantic import BaseModel, Field

from app.db.models import Severity


class AnalysisRequest(BaseModel):
    log_text: str = Field(min_length=1, description="Raw security log text")
    use_slm: bool = True


class MitreTechniqueOut(BaseModel):
    id: str
    name: str
    tactic: str


class ThreatResult(BaseModel):
    threat_type: str
    severity: Severity
    confidence: float
    explanation: str
    recommendations: list[str]
    rule_id: str | None = None
    mitre_techniques: list[MitreTechniqueOut] = []


class AnalysisResponse(BaseModel):
    threats: list[ThreatResult]
    slm_mode: str
    processing_ms: int


class AlertOut(BaseModel):
    id: int
    log_id: int
    threat_type: str
    severity: Severity
    confidence: float
    explanation: str | None
    recommendations: str | None
    slm_mode: str
    created_at: datetime
    raw_log: str | None = None

    model_config = {"from_attributes": True}


class ChatRequest(BaseModel):
    question: str = Field(min_length=1, max_length=2000)
    alert_id: int | None = None


class ChatResponse(BaseModel):
    answer: str
    alert_id: int | None = None
