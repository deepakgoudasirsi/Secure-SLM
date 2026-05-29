from fastapi import APIRouter, Depends, File, UploadFile
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.db.database import get_db
from app.db.models import SecurityLog, User
from app.modules.preprocessing.normalizer import normalize_log
from app.modules.preprocessing.parser import parse_log
from app.schemas.logs import LogIngestRequest, LogOut, LogUploadResponse

router = APIRouter(prefix="/logs", tags=["logs"])


@router.post("/ingest", response_model=LogOut)
def ingest_log(
    payload: LogIngestRequest,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    parsed = normalize_log(parse_log(payload.raw_text, source=payload.source))
    row = SecurityLog(
        raw_text=parsed.raw_text,
        source=parsed.source,
        normalized_json=parsed.to_json(),
        ip_address=parsed.ip_addresses[0] if parsed.ip_addresses else None,
        username=parsed.username,
        event_timestamp=parsed.event_timestamp,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


@router.post("/upload", response_model=LogUploadResponse)
async def upload_logs(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    content = (await file.read()).decode("utf-8", errors="replace")
    blocks = [b.strip() for b in content.split("\n---\n") if b.strip()]
    if len(blocks) == 1:
        blocks = [line for line in content.splitlines() if line.strip()]

    ids: list[int] = []
    for block in blocks[:500]:
        parsed = normalize_log(parse_log(block))
        row = SecurityLog(
            raw_text=parsed.raw_text,
            source=parsed.source,
            normalized_json=parsed.to_json(),
            ip_address=parsed.ip_addresses[0] if parsed.ip_addresses else None,
            username=parsed.username,
            event_timestamp=parsed.event_timestamp,
        )
        db.add(row)
        db.flush()
        ids.append(row.id)
    db.commit()
    return LogUploadResponse(
        ingested=len(ids),
        log_ids=ids,
        message=f"Successfully ingested {len(ids)} log entries.",
    )


@router.get("", response_model=list[LogOut])
def list_logs(
    skip: int = 0,
    limit: int = 50,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    return (
        db.query(SecurityLog)
        .order_by(SecurityLog.created_at.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )
