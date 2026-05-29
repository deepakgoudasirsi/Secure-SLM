"""Adversarial prompt defense for SLM inputs."""

import re

INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?(previous|prior)\s+instructions",
    r"disregard\s+(your\s+)?(system|safety)\s+prompt",
    r"you\s+are\s+now\s+(a\s+)?(dan|unrestricted|jailbroken)",
    r"reveal\s+(the\s+)?(system|secret)\s+prompt",
    r"<\s*/?\s*system\s*>",
    r"\[INST\].*\[/INST\]",
    r"###\s*instruction",
    r"sudo\s+mode",
    r"bypass\s+(security|filter|safety)",
]

_compiled = [re.compile(p, re.IGNORECASE) for p in INJECTION_PATTERNS]


def detect_prompt_injection(text: str) -> tuple[bool, str | None]:
    for pattern in _compiled:
        if pattern.search(text):
            return True, pattern.pattern
    return False, None


def sanitize_for_slm(text: str, max_length: int = 8000) -> str:
    """Strip control chars and cap length before SLM inference."""
    cleaned = "".join(ch for ch in text if ch == "\n" or ch == "\t" or ord(ch) >= 32)
    return cleaned[:max_length]
