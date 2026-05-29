from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.db.database import get_db
from app.db.models import SecurityLog, ThreatAlert, User
from app.schemas.analysis import AlertOut

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("", response_model=list[AlertOut])
def list_alerts(
    skip: int = 0,
    limit: int = 50,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    alerts = (
        db.query(ThreatAlert)
        .order_by(ThreatAlert.created_at.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )
    result: list[AlertOut] = []
    for alert in alerts:
        log = db.query(SecurityLog).filter(SecurityLog.id == alert.log_id).first()
        result.append(
            AlertOut(
                id=alert.id,
                log_id=alert.log_id,
                threat_type=alert.threat_type,
                severity=alert.severity,
                confidence=alert.confidence,
                explanation=alert.explanation,
                recommendations=alert.recommendations,
                slm_mode=alert.slm_mode,
                created_at=alert.created_at,
                raw_log=log.raw_text if log else None,
            )
        )
    return result


@router.get("/{alert_id}", response_model=AlertOut)
def get_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    alert = db.query(ThreatAlert).filter(ThreatAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    log = db.query(SecurityLog).filter(SecurityLog.id == alert.log_id).first()
    return AlertOut(
        id=alert.id,
        log_id=alert.log_id,
        threat_type=alert.threat_type,
        severity=alert.severity,
        confidence=alert.confidence,
        explanation=alert.explanation,
        recommendations=alert.recommendations,
        slm_mode=alert.slm_mode,
        created_at=alert.created_at,
        raw_log=log.raw_text if log else None,
    )


@router.get("/stats/summary")
def alert_stats(
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    alerts = db.query(ThreatAlert).all()
    by_severity: dict[str, int] = {}
    by_type: dict[str, int] = {}
    for a in alerts:
        by_severity[a.severity.value] = by_severity.get(a.severity.value, 0) + 1
        by_type[a.threat_type] = by_type.get(a.threat_type, 0) + 1
    return {
        "total_alerts": len(alerts),
        "by_severity": by_severity,
        "by_threat_type": by_type,
    }
