from datetime import datetime

from pydantic import BaseModel, Field

from app.db.models import LogSource


class LogIngestRequest(BaseModel):
    raw_text: str = Field(min_length=1)
    source: LogSource = LogSource.UNKNOWN


class LogOut(BaseModel):
    id: int
    raw_text: str
    source: LogSource
    ip_address: str | None
    username: str | None
    event_timestamp: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}


class LogUploadResponse(BaseModel):
    ingested: int
    log_ids: list[int]
    message: str
