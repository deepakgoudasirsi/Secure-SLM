#!/usr/bin/env python3
"""Ingest sample logs and run analysis pipeline."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.db.database import SessionLocal, init_db
from app.services.pipeline import run_full_pipeline


def main():
    init_db()
    sample_file = Path(__file__).parents[1] / "data" / "samples" / "sample_logs.txt"
    blocks = sample_file.read_text().split("\n---\n")
    db = SessionLocal()
    try:
        for block in blocks:
            block = block.strip()
            if not block:
                continue
            response, log_id = run_full_pipeline(db, block, persist=True, use_slm=True)
            print(f"Log #{log_id}: {len(response.threats)} threat(s)")
            for t in response.threats:
                print(f"  - {t.threat_type} ({t.severity.value}) conf={t.confidence:.2f}")
    finally:
        db.close()


if __name__ == "__main__":
    main()
