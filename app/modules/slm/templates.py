from app.db.models import Severity
from app.modules.threat_detection.rules import RuleMatch


MITIGATION = {
    "Brute Force Attack": [
        "Temporarily block the source IP at the firewall or WAF",
        "Enable MFA for targeted accounts",
        "Review authentication logs for successful logins after failures",
        "Reset credentials if compromise is suspected",
    ],
    "Port Scan / Reconnaissance": [
        "Block or rate-limit the scanning IP",
        "Verify exposed services and patch vulnerabilities",
        "Enable IDS/IPS signatures for reconnaissance activity",
        "Correlate with threat intelligence feeds",
    ],
    "Privilege Escalation Attempt": [
        "Isolate affected host from sensitive segments",
        "Audit privileged group membership and sudoers",
        "Collect endpoint forensic artifacts",
        "Escalate to incident response per playbook",
    ],
    "Malware Indicator": [
        "Isolate endpoint immediately",
        "Run EDR scan and block known IOC hashes",
        "Preserve memory and disk images for analysis",
        "Notify SOC lead and follow malware IR playbook",
    ],
    "Suspicious External Authentication": [
        "Geo-block or challenge authentication from unexpected regions",
        "Force password reset for affected accounts",
        "Review VPN and remote access policies",
        "Enable adaptive authentication policies",
    ],
}


def _severity_label(severity: Severity) -> str:
    return severity.value.capitalize()


def build_explanation(match: RuleMatch, parsed_raw: str) -> str:
    threat = match.threat_type
    ctx = match.context

    if threat == "Brute Force Attack":
        user = ctx.get("target_user") or "a privileged account"
        attempts = ctx.get("failed_attempts") or "multiple"
        return (
            f"Multiple failed login attempts ({attempts}) suggest a brute-force password "
            f"attack targeting {user}. Source IPs and timing patterns match credential-stuffing TTPs."
        )
    if threat == "Port Scan / Reconnaissance":
        ips = ", ".join(ctx.get("ips") or []) or "unknown hosts"
        return (
            f"Log content indicates network reconnaissance or port scanning activity "
            f"involving {ips}. Attackers often scan before exploitation."
        )
    if threat == "Privilege Escalation Attempt":
        return (
            "Events consistent with privilege escalation were detected. "
            "An actor may be attempting to obtain administrative rights on the system."
        )
    if threat == "Malware Indicator":
        return (
            "Indicators of malware execution or command-and-control behavior were found. "
            "Immediate containment is recommended."
        )
    if threat == "Suspicious External Authentication":
        ip = ctx.get("ip", "external host")
        return (
            f"Authentication failures originated from an external or untrusted address ({ip}), "
            f"which may indicate credential attacks from outside the organization."
        )

    return f"Rule {match.rule_id} matched patterns associated with {threat}."


def build_recommendations(match: RuleMatch) -> list[str]:
    return MITIGATION.get(match.threat_type, [
        "Review correlated logs in your SIEM",
        "Document findings in the incident ticket",
        "Apply vendor-specific hardening guidance",
    ])


def format_incident_report(
    match: RuleMatch,
    parsed_raw: str,
) -> dict[str, str | list[str]]:
    return {
        "threat_type": match.threat_type,
        "severity": _severity_label(match.severity),
        "explanation": build_explanation(match, parsed_raw),
        "recommendations": build_recommendations(match),
    }
