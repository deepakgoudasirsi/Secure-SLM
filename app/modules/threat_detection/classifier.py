"""Lightweight TF-IDF + logistic regression threat classifier (offline, no GPU)."""

from __future__ import annotations

import re
from pathlib import Path

from app.db.models import Severity
from app.modules.threat_detection.rules import RuleMatch

_MODEL_PATH = Path(__file__).resolve().parents[3] / "data" / "models" / "threat_classifier.joblib"

_TRAINING_SAMPLES: list[tuple[str, str, Severity, float]] = [
    ("failed login admin password 45 times brute force", "Brute Force Attack", Severity.HIGH, 0.9),
    ("authentication failure repeated invalid credentials", "Brute Force Attack", Severity.MEDIUM, 0.85),
    ("nmap port scan syn probe 50 ports reconnaissance", "Port Scan / Reconnaissance", Severity.MEDIUM, 0.88),
    ("suricata port scan detected external host", "Port Scan / Reconnaissance", Severity.MEDIUM, 0.82),
    ("privilege escalation SeDebugPrivilege sudo unauthorized", "Privilege Escalation Attempt", Severity.HIGH, 0.9),
    ("special privileges assigned suspicious elevation", "Privilege Escalation Attempt", Severity.HIGH, 0.87),
    ("powershell enc malware trojan C2 beacon ransomware", "Malware Indicator", Severity.CRITICAL, 0.92),
    ("backdoor execution detected endpoint", "Malware Indicator", Severity.CRITICAL, 0.91),
    ("ddos syn flood deny inbound mass traffic", "Network Denial of Service", Severity.HIGH, 0.86),
    ("normal user login success workstation", "Benign", Severity.LOW, 0.1),
    ("scheduled backup completed successfully", "Benign", Severity.LOW, 0.05),
]

_classifier = None
_vectorizer = None


def _tokenize(text: str) -> str:
    return re.sub(r"\s+", " ", text.lower()).strip()


def _train_classifier():
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline

    texts = [s[0] for s in _TRAINING_SAMPLES]
    labels = [s[1] for s in _TRAINING_SAMPLES]
    pipe = Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1, 2), max_features=500)),
        ("clf", LogisticRegression(max_iter=500)),
    ])
    pipe.fit(texts, labels)
    return pipe


def get_classifier():
    global _classifier
    if _classifier is not None:
        return _classifier

    try:
        import joblib
    except ImportError:
        joblib = None  # type: ignore

    if joblib and _MODEL_PATH.exists():
        try:
            _classifier = joblib.load(_MODEL_PATH)
            return _classifier
        except Exception:
            _MODEL_PATH.unlink(missing_ok=True)

    _classifier = _train_classifier()
    if joblib:
        _MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(_classifier, _MODEL_PATH)
    return _classifier


def classify_log(text: str, threshold: float = 0.55) -> RuleMatch | None:
    try:
        clf = get_classifier()
    except ImportError:
        return None

    proba = clf.predict_proba([_tokenize(text)])[0]
    classes = list(clf.classes_)
    best_idx = int(proba.argmax())
    label = classes[best_idx]
    confidence = float(proba[best_idx])

    if label == "Benign" or confidence < threshold:
        return None

    severity_map = {
        "Brute Force Attack": Severity.HIGH,
        "Port Scan / Reconnaissance": Severity.MEDIUM,
        "Privilege Escalation Attempt": Severity.HIGH,
        "Malware Indicator": Severity.CRITICAL,
        "Network Denial of Service": Severity.HIGH,
    }
    return RuleMatch(
        rule_id="ML-CLF-001",
        threat_type=label,
        severity=severity_map.get(label, Severity.MEDIUM),
        confidence=confidence,
        context={"model": "tfidf_logistic"},
    )
