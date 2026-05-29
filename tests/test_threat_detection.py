from app.db.models import Severity
from app.modules.threat_detection.engine import detect_threats


def test_brute_force_detection():
    raw = (
        "Failed login attempt from IP 192.168.1.20 repeated 45 times in 2 minutes. "
        "User: admin"
    )
    _, matches = detect_threats(raw)
    assert len(matches) >= 1
    assert matches[0].threat_type == "Brute Force Attack"
    assert matches[0].severity == Severity.HIGH


def test_port_scan_detection():
    raw = "Port scan detected nmap from external host"
    _, matches = detect_threats(raw)
    assert any(m.threat_type == "Port Scan / Reconnaissance" for m in matches)
