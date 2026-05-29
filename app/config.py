from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "Secure-SLM"
    debug: bool = False
    api_prefix: str = "/api/v1"

    database_url: str = "sqlite:///./secure_slm.db"

    secret_key: str = "dev-secret-change-in-production"
    access_token_expire_minutes: int = 60
    encryption_key: str = ""

    slm_mode: Literal["template", "huggingface"] = "template"
    slm_model_name: str = "microsoft/Phi-3-mini-4k-instruct"
    slm_max_tokens: int = 512
    slm_device: str = "cpu"

    threat_confidence_threshold: float = 0.6
    enable_ml_classifier: bool = True
    enable_mitre_rag: bool = True

    admin_username: str = "admin"
    admin_password: str = "changeme"

    upload_dir: str = "uploads"
    max_upload_mb: int = 10


@lru_cache
def get_settings() -> Settings:
    return Settings()
