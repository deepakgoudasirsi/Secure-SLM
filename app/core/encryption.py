import base64
import json
from typing import Any

from cryptography.fernet import Fernet

from app.config import get_settings

_fernet: Fernet | None = None


def _get_fernet() -> Fernet:
    global _fernet
    if _fernet is not None:
        return _fernet

    settings = get_settings()
    key = settings.encryption_key.strip()
    if not key:
        key = Fernet.generate_key().decode()
    elif len(key) != 44:
        key = base64.urlsafe_b64encode(key.encode()[:32].ljust(32, b"0")).decode()

    _fernet = Fernet(key.encode() if isinstance(key, str) else key)
    return _fernet


def encrypt_text(plain: str) -> str:
    return _get_fernet().encrypt(plain.encode()).decode()


def decrypt_text(cipher: str) -> str:
    return _get_fernet().decrypt(cipher.encode()).decode()


def encrypt_json(data: dict[str, Any]) -> str:
    return encrypt_text(json.dumps(data))


def decrypt_json(cipher: str) -> dict[str, Any]:
    return json.loads(decrypt_text(cipher))
