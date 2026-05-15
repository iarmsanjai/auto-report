from pydantic_settings import BaseSettings
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    APP_NAME: str = "VAPT Report Automation System"
    APP_VERSION: str = "2.0.0"
    DEBUG: bool = True

    # ── Auth ──────────────────────────────────────────────────────────────────
    SECRET_KEY: str = "vapt-secret-key-CHANGE-IN-PRODUCTION-abc123xyz"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 480  # 8 hours

    CORS_ORIGINS: list = [
        "http://localhost:5173",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:3000",
    ]

    TEMPLATES_DIR: Path = BASE_DIR / "templates"
    UPLOAD_DIR: Path = BASE_DIR / "uploads"
    MAX_UPLOAD_MB: int = 50

    SEVERITY_ORDER: dict = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "info": 4,
    }

    SEVERITY_COLORS: dict = {
        "critical": "#e60000",
        "high": "#ff7a00",
        "medium": "#ffcc00",
        "low": "#6b1c4f",
        "info": "#6e6e6e",
    }

    model_config = {"env_file": ".env", "extra": "ignore"}


settings = Settings()
settings.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
