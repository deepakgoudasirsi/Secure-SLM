from app.modules.preprocessing.parser import parse_log
from app.modules.preprocessing.normalizer import normalize_log


def test_parse_brute_force_log():
    raw = (
        "Failed login attempt from IP 192.168.1.20 repeated 45 times in 2 minutes. "
        "User: admin"
    )
    parsed = normalize_log(parse_log(raw))
    assert parsed.ip_addresses == ["192.168.1.20"]
    assert parsed.username == "admin"
    assert parsed.failed_login_count == 45
    assert parsed.indicators["failed_login"] is True


def test_parse_port_scan():
    raw = "suricata port scan nmap from 10.0.0.5"
    parsed = parse_log(raw)
    assert parsed.indicators["port_scan"] is True
