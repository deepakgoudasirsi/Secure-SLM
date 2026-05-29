import re

from app.modules.preprocessing.parser import ParsedLog


def normalize_whitespace(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def remove_noise_lines(text: str) -> str:
    """Drop empty lines and common heartbeat/noise patterns."""
    noise = re.compile(r"^(heartbeat|healthcheck|keepalive)\b", re.IGNORECASE)
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return "\n".join(line for line in lines if not noise.match(line))


def normalize_log(parsed: ParsedLog) -> ParsedLog:
    cleaned = remove_noise_lines(parsed.raw_text)
    parsed.raw_text = normalize_whitespace(cleaned) if "\n" not in cleaned else cleaned
    return parsed
