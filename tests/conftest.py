from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.db.database import DATA_DIR, init_db
from app.main import app
from app.startup import seed_admin_user


@pytest.fixture(scope="session", autouse=True)
def setup_database():
    db_path = DATA_DIR / "secure_slm.db"
    for pattern in ("secure_slm.db", "secure_slm.db-journal", "secure_slm.db-wal", "secure_slm.db-shm"):
        p = DATA_DIR / pattern
        if p.exists():
            p.unlink()
    # Legacy path from older versions
    legacy = Path("secure_slm.db")
    if legacy.exists():
        legacy.unlink()
    init_db()
    seed_admin_user()


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as test_client:
        yield test_client
