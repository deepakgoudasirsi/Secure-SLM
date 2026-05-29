from dataclasses import dataclass

from app.db.models import Severity
from app.modules.preprocessing.parser import ParsedLog

BRUTE_FORCE_THRESHOLD = 5


@dataclass
class RuleMatch:
    rule_id: str
    threat_type: str
    severity: Severity
    confidence: float
    context: dict


def rule_brute_force(parsed: ParsedLog) -> RuleMatch | None:
    count = parsed.failed_login_count or 0
    if parsed.indicators["failed_login"] and (count >= BRUTE_FORCE_THRESHOLD or count == 0):
        confidence = min(0.95, 0.7 + (count / 100) if count else 0.75)
        return RuleMatch(
            rule_id="RULE-BF-001",
            threat_type="Brute Force Attack",
            severity=Severity.HIGH if count >= 20 or "admin" in parsed.raw_text.lower() else Severity.MEDIUM,
            confidence=confidence,
            context={"failed_attempts": count, "target_user": parsed.username},
        )
    return None


def rule_port_scan(parsed: ParsedLog) -> RuleMatch | None:
    if parsed.indicators["port_scan"]:
        return RuleMatch(
            rule_id="RULE-PS-001",
            threat_type="Port Scan / Reconnaissance",
            severity=Severity.MEDIUM,
            confidence=0.82,
            context={"ips": parsed.ip_addresses},
        )
    return None


def rule_privilege_escalation(parsed: ParsedLog) -> RuleMatch | None:
    if parsed.indicators["privilege_escalation"]:
        return RuleMatch(
            rule_id="RULE-PE-001",
            threat_type="Privilege Escalation Attempt",
            severity=Severity.HIGH,
            confidence=0.88,
            context={"user": parsed.username},
        )
    return None


def rule_malware(parsed: ParsedLog) -> RuleMatch | None:
    if parsed.indicators["malware"]:
        return RuleMatch(
            rule_id="RULE-MW-001",
            threat_type="Malware Indicator",
            severity=Severity.CRITICAL,
            confidence=0.9,
            context={},
        )
    return None


def rule_suspicious_external_ip(parsed: ParsedLog) -> RuleMatch | None:
    for ip in parsed.ip_addresses:
        if ip.startswith(("10.", "192.168.", "172.")):
            continue
        if parsed.indicators["failed_login"]:
            return RuleMatch(
                rule_id="RULE-AUTH-002",
                threat_type="Suspicious External Authentication",
                severity=Severity.HIGH,
                confidence=0.78,
                context={"ip": ip},
            )
    return None


ALL_RULES = [
    rule_brute_force,
    rule_port_scan,
    rule_privilege_escalation,
    rule_malware,
    rule_suspicious_external_ip,
]


def run_rule_engine(parsed: ParsedLog) -> list[RuleMatch]:
    matches: list[RuleMatch] = []
    for rule_fn in ALL_RULES:
        result = rule_fn(parsed)
        if result:
            matches.append(result)
    return matches
