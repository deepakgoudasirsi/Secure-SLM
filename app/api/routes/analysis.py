from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.db.database import get_db
from app.db.models import User
from app.schemas.analysis import AnalysisRequest, AnalysisResponse, ChatRequest, ChatResponse
from app.services.pipeline import chat_about_alert, run_full_pipeline

router = APIRouter(prefix="/analysis", tags=["analysis"])


@router.post("/analyze", response_model=AnalysisResponse)
def analyze_log(
    payload: AnalysisRequest,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    response, _ = run_full_pipeline(
        db,
        payload.log_text,
        persist=True,
        use_slm=payload.use_slm,
    )
    return response


@router.post("/analyze/ephemeral", response_model=AnalysisResponse)
def analyze_ephemeral(
    payload: AnalysisRequest,
    _: User = Depends(get_current_user),
):
    from app.db.database import SessionLocal

    db = SessionLocal()
    try:
        response, _ = run_full_pipeline(
            db,
            payload.log_text,
            persist=False,
            use_slm=payload.use_slm,
        )
        return response
    finally:
        db.close()


@router.post("/chat", response_model=ChatResponse)
def chat(
    payload: ChatRequest,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    if not payload.alert_id:
        return ChatResponse(
            answer="Provide alert_id to ask questions about a specific incident.",
            alert_id=None,
        )
    answer = chat_about_alert(db, payload.alert_id, payload.question)
    return ChatResponse(answer=answer, alert_id=payload.alert_id)
