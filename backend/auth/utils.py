"""
auth/utils.py — JWT creation/decoding & bcrypt password hashing.
User accounts are stored in users.json (auto-created on first run).
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from jose import JWTError, jwt
from passlib.context import CryptContext

from config.settings import settings

log = logging.getLogger(__name__)

pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")

USERS_FILE: Path = Path(__file__).resolve().parent.parent / "users.json"

# Default admin account (password: admin123) — created on first run
_DEFAULT_USERS: dict = {
    "admin": {
        "username": "admin",
        "hashed_password": "",   # filled at startup
        "role": "admin",
    }
}

DEFAULT_PASSWORD = "admin123"


# ─── User store ───────────────────────────────────────────────────────────────

def _ensure_users_file() -> None:
    """Create users.json with default admin if it does not exist."""
    if USERS_FILE.exists():
        return
    users = {
        "admin": {
            "username": "admin",
            "hashed_password": pwd_ctx.hash(DEFAULT_PASSWORD),
            "role": "admin",
        }
    }
    USERS_FILE.write_text(json.dumps(users, indent=2))
    log.info("Created default users.json  →  admin / %s", DEFAULT_PASSWORD)


def load_users() -> dict:
    _ensure_users_file()
    try:
        return json.loads(USERS_FILE.read_text())
    except Exception as exc:
        log.error("Could not load users.json: %s", exc)
        return {}


def save_users(users: dict) -> None:
    USERS_FILE.write_text(json.dumps(users, indent=2))


# ─── Password helpers ─────────────────────────────────────────────────────────

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_ctx.verify(plain, hashed)


def hash_password(plain: str) -> str:
    return pwd_ctx.hash(plain)


# ─── JWT helpers ──────────────────────────────────────────────────────────────

def create_access_token(username: str) -> str:
    expire = datetime.utcnow() + timedelta(minutes=settings.JWT_EXPIRE_MINUTES)
    payload = {"sub": username, "exp": expire}
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def decode_token(token: str) -> Optional[str]:
    """Return username from token, or None if invalid/expired."""
    try:
        payload = jwt.decode(
            token, settings.SECRET_KEY, algorithms=[settings.JWT_ALGORITHM]
        )
        return payload.get("sub")
    except JWTError:
        return None
