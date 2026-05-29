from app.config import get_settings
from app.core.security import hash_password
from app.db.database import SessionLocal
from app.db.models import User


def seed_admin_user() -> None:
    settings = get_settings()
    db = SessionLocal()
    try:
        if db.query(User).filter(User.username == settings.admin_username).first():
            return
        admin = User(
            username=settings.admin_username,
            hashed_password=hash_password(settings.admin_password),
            role="admin",
        )
        db.add(admin)
        db.commit()
    finally:
        db.close()
