from collections.abc import Generator
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, declarative_base, sessionmaker

from app.config import get_settings

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = PROJECT_ROOT / "data"


def resolve_database_url(url: str) -> str:
    """Resolve relative SQLite paths to an absolute path under data/."""
    if not url.startswith("sqlite"):
        return url

    if url in ("sqlite:///./secure_slm.db", "sqlite:///secure_slm.db"):
        path = DATA_DIR / "secure_slm.db"
    elif url.startswith("sqlite:///./"):
        path = (PROJECT_ROOT / url.removeprefix("sqlite:///./")).resolve()
    elif url.startswith("sqlite:///") and not url.startswith("sqlite:////"):
        raw = url.removeprefix("sqlite:///")
        path = Path(raw) if Path(raw).is_absolute() else (PROJECT_ROOT / raw).resolve()
    else:
        return url

    path.parent.mkdir(parents=True, exist_ok=True)
    _cleanup_stale_sqlite_files(path)
    return f"sqlite:///{path.as_posix()}"


def _cleanup_stale_sqlite_files(db_path: Path) -> None:
    """Remove empty journal files left by interrupted writes (common with --reload)."""
    journal = Path(f"{db_path}-journal")
    if journal.exists() and journal.stat().st_size == 0:
        journal.unlink(missing_ok=True)


settings = get_settings()
database_url = resolve_database_url(settings.database_url)

connect_args = {"check_same_thread": False} if database_url.startswith("sqlite") else {}
engine = create_engine(database_url, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    from app.db import models  # noqa: F401

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    Base.metadata.create_all(bind=engine)
