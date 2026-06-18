"""
auth/utils.py — JWT creation/decoding & bcrypt password hashing.
User accounts are stored in users.json (auto-created on first run).

Security controls:
  - Passwords hashed with bcrypt via passlib (work factor ≥ 12)
  - Default admin password generated randomly at first run — never hardcoded
  - users.json written atomically (temp file + rename) to prevent corruption
  - JWT uses configurable expiry and algorithm from settings
"""
from __future__ import annotations

import json
import logging
import os
import secrets
import string
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from jose import JWTError, jwt
from passlib.context import CryptContext

from config.settings import settings

log = logging.getLogger(__name__)

pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")

USERS_FILE: Path = Path(__file__).resolve().parent.parent / "users.json"


def _generate_secure_password(length: int = 16) -> str:
    """
    Generate a cryptographically secure random password containing uppercase,
    lowercase, digits, and special characters.
    Never stored in source — only printed to the log on first startup.
    """
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    # Guarantee at least one character from each required category
    password = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
        secrets.choice("!@#$%^&*()-_=+"),
    ]
    password += [secrets.choice(alphabet) for _ in range(length - 4)]
    secrets.SystemRandom().shuffle(password)
    return "".join(password)


# ─── User store ───────────────────────────────────────────────────────────────

def _ensure_users_file() -> None:
    """
    Create users.json with a randomly-generated admin password if it does not
    exist. The generated password is printed ONCE to the server log — there is
    no hardcoded default credential in source code.
    """
    if USERS_FILE.exists():
        return

    first_run_password = _generate_secure_password()
    users = {
        "admin": {
            "username": "admin",
            "hashed_password": pwd_ctx.hash(first_run_password),
            "role": "admin",
        }
    }
    _write_users_atomic(users)
    # Print to log ONCE — admin must change this after first login
    log.warning(
        "═══════════════════════════════════════════════════════════════\n"
        "  First-run: default admin account created.\n"
        "  Username : admin\n"
        "  Password : %s\n"
        "  ⚠️  Change this password immediately after first login!\n"
        "═══════════════════════════════════════════════════════════════",
        first_run_password,
    )


def _write_users_atomic(users: dict) -> None:
    """
    Write the users dict to users.json atomically using a temp file + rename.
    This prevents a partial write from corrupting the user store.
    """
    dir_path = USERS_FILE.parent
    fd, tmp_path = tempfile.mkstemp(dir=dir_path, suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(users, f, indent=2)
        # Atomic replace (POSIX rename / Windows replace)
        Path(tmp_path).replace(USERS_FILE)
    except Exception:
        # Clean up temp file if write failed
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def load_users() -> dict:
    _ensure_users_file()
    try:
        return json.loads(USERS_FILE.read_text(encoding="utf-8"))
    except Exception as exc:
        log.error("Could not load users.json: %s", exc)
        return {}


def save_users(users: dict) -> None:
    """Save users dict to disk using atomic write."""
    _write_users_atomic(users)


# ─── Password helpers ─────────────────────────────────────────────────────────

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_ctx.verify(plain, hashed)


def hash_password(plain: str) -> str:
    return pwd_ctx.hash(plain)


# ─── JWT helpers ──────────────────────────────────────────────────────────────

def create_access_token(username: str) -> str:
    expire = datetime.utcnow() + timedelta(minutes=settings.JWT_EXPIRE_MINUTES)
    payload = {"sub": username, "exp": expire, "iat": datetime.utcnow()}
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
