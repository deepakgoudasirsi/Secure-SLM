#!/usr/bin/env python3
"""Evaluate threat detection accuracy on labeled sample logs."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.modules.threat_detection.engine import detect_threats


def main() -> None:
    data_path = Path(__file__).parents[1] / "data" / "evaluation" / "labeled_logs.json"
    samples = json.loads(data_path.read_text())

    tp = fp = fn = tn = 0
    results: list[dict] = []

    for sample in samples:
        expected = sample["expected_type"]
        _, matches = detect_threats(sample["log"])
        predicted = matches[0].threat_type if matches else "Benign"

        correct = predicted == expected
        results.append({
            "expected": expected,
            "predicted": predicted,
            "correct": correct,
            "confidence": matches[0].confidence if matches else 0.0,
        })

        is_attack_expected = expected != "Benign"
        is_attack_predicted = predicted != "Benign"

        if is_attack_expected and is_attack_predicted and predicted == expected:
            tp += 1
        elif not is_attack_expected and not is_attack_predicted:
            tn += 1
        elif not is_attack_expected and is_attack_predicted:
            fp += 1
        elif is_attack_expected and (not is_attack_predicted or predicted != expected):
            fn += 1

    total = len(samples)
    accuracy = sum(1 for r in results if r["correct"]) / total
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    report = {
        "samples": total,
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "confusion": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
        "details": results,
    }

    print(json.dumps(report, indent=2))
    out_path = Path(__file__).parents[1] / "data" / "evaluation" / "last_report.json"
    out_path.write_text(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
