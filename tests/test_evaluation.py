from app.modules.threat_detection.engine import detect_threats


def test_labeled_brute_force():
    raw = "Failed login attempt from IP 192.168.1.20 repeated 45 times. User: admin"
    _, matches = detect_threats(raw)
    assert matches
    assert matches[0].threat_type == "Brute Force Attack"


def test_benign_log():
    raw = "User john.doe logged in successfully from workstation WS-101"
    _, matches = detect_threats(raw)
    assert not matches or matches[0].threat_type == "Benign"
