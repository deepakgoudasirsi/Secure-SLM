import json
from pathlib import Path

from fastapi import APIRouter, Depends

from app.api.deps import get_current_user
from app.db.models import User
from app.modules.threat_detection.engine import detect_threats

router = APIRouter(prefix="/evaluation", tags=["evaluation"])

_LABELED = Path(__file__).resolve().parents[3] / "data" / "evaluation" / "labeled_logs.json"


@router.post("/run")
def run_evaluation(_: User = Depends(get_current_user)):
    samples = json.loads(_LABELED.read_text())
    results = []
    correct = 0

    for sample in samples:
        expected = sample["expected_type"]
        _, matches = detect_threats(sample["log"])
        predicted = matches[0].threat_type if matches else "Benign"
        is_correct = predicted == expected
        correct += int(is_correct)
        results.append({
            "log_preview": sample["log"][:80] + "...",
            "expected": expected,
            "predicted": predicted,
            "correct": is_correct,
            "confidence": matches[0].confidence if matches else 0.0,
        })

    total = len(samples)
    return {
        "accuracy": round(correct / total, 4) if total else 0.0,
        "samples": total,
        "correct": correct,
        "results": results,
    }


@router.get("/report")
def last_report(_: User = Depends(get_current_user)):
    report_path = _LABELED.parent / "last_report.json"
    if not report_path.exists():
        return {"message": "Run scripts/evaluate.py or POST /evaluation/run first"}
    return json.loads(report_path.read_text())
