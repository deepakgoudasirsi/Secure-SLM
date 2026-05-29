import json

from sqlalchemy.orm import Session

from app.db.models import SecurityLog, Severity, ThreatAlert
from app.modules.slm.engine import analyze_with_timing, get_slm_engine
from app.modules.threat_detection.engine import detect_threats
from app.schemas.analysis import AnalysisResponse, ThreatResult


def run_full_pipeline(
    db: Session,
    raw_text: str,
    source=None,
    persist: bool = True,
    use_slm: bool = True,
) -> tuple[AnalysisResponse, int | None]:
    parsed, matches = detect_threats(raw_text, source=source)
    log_id: int | None = None

    if persist:
        log_row = SecurityLog(
            raw_text=parsed.raw_text,
            source=parsed.source,
            normalized_json=parsed.to_json(),
            ip_address=parsed.ip_addresses[0] if parsed.ip_addresses else None,
            username=parsed.username,
            event_timestamp=parsed.event_timestamp,
        )
        db.add(log_row)
        db.flush()
        log_id = log_row.id

    threats: list[ThreatResult] = []
    total_ms = 0
    slm_mode = "none"

    if not matches:
        return AnalysisResponse(threats=[], slm_mode="none", processing_ms=0), log_id

    for match in matches:
        slm_out: dict = {}
        if use_slm:
            slm_out, ms = analyze_with_timing(match, parsed.raw_text)
            total_ms += ms
            slm_mode = slm_out.get("slm_mode", "template")
            explanation = slm_out.get("explanation", "")
            recommendations = slm_out.get("recommendations", [])
        else:
            slm_mode = "rules_only"
            explanation = f"Rule {match.rule_id} triggered."
            recommendations = []

        from app.schemas.analysis import MitreTechniqueOut

        mitre_raw = slm_out.get("mitre_techniques", [])
        mitre = [MitreTechniqueOut(**t) for t in mitre_raw] if mitre_raw else []

        threat = ThreatResult(
            threat_type=match.threat_type,
            severity=match.severity,
            confidence=match.confidence,
            explanation=explanation,
            recommendations=recommendations if isinstance(recommendations, list) else [str(recommendations)],
            rule_id=match.rule_id,
            mitre_techniques=mitre,
        )
        threats.append(threat)

        if persist and log_id:
            db.add(
                ThreatAlert(
                    log_id=log_id,
                    threat_type=match.threat_type,
                    severity=match.severity,
                    confidence=match.confidence,
                    rule_id=match.rule_id,
                    explanation=explanation,
                    recommendations=json.dumps(threat.recommendations),
                    slm_mode=slm_mode,
                )
            )

    if persist:
        db.commit()

    return AnalysisResponse(threats=threats, slm_mode=slm_mode, processing_ms=total_ms), log_id


def chat_about_alert(db: Session, alert_id: int, question: str) -> str:
    alert = db.query(ThreatAlert).filter(ThreatAlert.id == alert_id).first()
    if not alert:
        return "Alert not found."
    log = db.query(SecurityLog).filter(SecurityLog.id == alert.log_id).first()
    context = (
        f"Threat: {alert.threat_type}\n"
        f"Severity: {alert.severity.value}\n"
        f"Explanation: {alert.explanation}\n"
        f"Log: {log.raw_text if log else 'N/A'}"
    )
    return get_slm_engine().chat(question, context)
