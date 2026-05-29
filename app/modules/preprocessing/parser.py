import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any

from app.db.models import LogSource

IP_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
USER_PATTERN = re.compile(r"(?:user|username|account)[:\s=]+([A-Za-z0-9_.@-]+)", re.IGNORECASE)
FAILED_LOGIN_PATTERN = re.compile(r"failed\s+(?:login|logon|authentication)", re.IGNORECASE)
PORT_SCAN_PATTERN = re.compile(r"(?:port\s+scan|nmap|syn\s+flood|masscan)", re.IGNORECASE)
PRIV_ESC_PATTERN = re.compile(
    r"(?:privilege\s+escalation|sudo\s+without|unauthorized\s+elevation|SeDebugPrivilege)",
    re.IGNORECASE,
)
MALWARE_PATTERN = re.compile(
    r"(?:malware|ransomware|trojan|backdoor|C2\s+beacon|powershell\s+-enc)",
    re.IGNORECASE,
)
TIMESTAMP_PATTERNS = [
    re.compile(r"\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}"),
    re.compile(r"\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"),
]


@dataclass
class ParsedLog:
    raw_text: str
    source: LogSource
    ip_addresses: list[str]
    username: str | None
    event_timestamp: datetime | None
    failed_login_count: int | None
    indicators: dict[str, bool]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["source"] = self.source.value
        d["event_timestamp"] = self.event_timestamp.isoformat() if self.event_timestamp else None
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict())


def infer_source(text: str) -> LogSource:
    lower = text.lower()
    if "eventid" in lower or "winlog" in lower or "powershell" in lower:
        return LogSource.WINDOWS
    if "suricata" in lower or "snort" in lower or "[**]" in text:
        return LogSource.IDS
    if "iptables" in lower or "deny inbound" in lower or "firewall" in lower:
        return LogSource.FIREWALL
    if "sshd" in lower or "syslog" in lower or "kernel:" in lower:
        return LogSource.SYSLOG
    if "login" in lower or "authentication" in lower or "auth" in lower:
        return LogSource.AUTH
    return LogSource.UNKNOWN


def extract_timestamp(text: str) -> datetime | None:
    for pattern in TIMESTAMP_PATTERNS:
        match = pattern.search(text)
        if match:
            raw = match.group(0).replace("T", " ")
            for fmt in ("%Y-%m-%d %H:%M:%S", "%b %d %H:%M:%S"):
                try:
                    return datetime.strptime(raw.strip(), fmt)
                except ValueError:
                    continue
    return None


def extract_failed_login_count(text: str) -> int | None:
    match = re.search(r"(\d+)\s+times?", text, re.IGNORECASE)
    if match and FAILED_LOGIN_PATTERN.search(text):
        return int(match.group(1))
    repeated = re.search(r"repeated\s+(\d+)", text, re.IGNORECASE)
    if repeated:
        return int(repeated.group(1))
    return None


def parse_log(raw_text: str, source: LogSource | None = None) -> ParsedLog:
    text = raw_text.strip()
    resolved_source = source or infer_source(text)
    ips = list(dict.fromkeys(IP_PATTERN.findall(text)))
    user_match = USER_PATTERN.search(text)

    return ParsedLog(
        raw_text=text,
        source=resolved_source,
        ip_addresses=ips,
        username=user_match.group(1) if user_match else None,
        event_timestamp=extract_timestamp(text),
        failed_login_count=extract_failed_login_count(text),
        indicators={
            "failed_login": bool(FAILED_LOGIN_PATTERN.search(text)),
            "port_scan": bool(PORT_SCAN_PATTERN.search(text)),
            "privilege_escalation": bool(PRIV_ESC_PATTERN.search(text)),
            "malware": bool(MALWARE_PATTERN.search(text)),
        },
    )
