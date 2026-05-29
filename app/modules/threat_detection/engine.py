from app.config import get_settings
from app.modules.preprocessing.normalizer import normalize_log
from app.modules.preprocessing.parser import ParsedLog, parse_log
from app.modules.threat_detection.rules import RuleMatch, run_rule_engine


def _merge_matches(matches: list[RuleMatch]) -> list[RuleMatch]:
    by_type: dict[str, RuleMatch] = {}
    for m in matches:
        existing = by_type.get(m.threat_type)
        if not existing or m.confidence > existing.confidence:
            by_type[m.threat_type] = m
    return list(by_type.values())


def detect_threats(raw_text: str, source=None) -> tuple[ParsedLog, list[RuleMatch]]:
    parsed = normalize_log(parse_log(raw_text, source=source))
    matches = run_rule_engine(parsed)

    settings = get_settings()
    if settings.enable_ml_classifier:
        try:
            from app.modules.threat_detection.classifier import classify_log

            ml_match = classify_log(parsed.raw_text, threshold=settings.threat_confidence_threshold)
            if ml_match:
                matches.append(ml_match)
        except ImportError:
            pass

    matches = _merge_matches(matches)
    threshold = settings.threat_confidence_threshold
    filtered = [m for m in matches if m.confidence >= threshold]

    if not filtered and matches:
        filtered = [max(matches, key=lambda m: m.confidence)]

    return parsed, filtered
