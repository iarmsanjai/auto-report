"""
api/auth_routes.py — Login, logout, and user-profile endpoints.
These routes are PUBLIC (no auth required on the router level).

Security controls:
  - Rate limiting on /login: 10 requests/minute per IP (brute-force protection)
  - Generic error messages on login failure (prevents username enumeration)
  - Password minimum 12 chars + complexity (uppercase, lowercase, digit, special char)
  - Username allow-list validation (alphanumeric + underscore, 2-32 chars)
  - Role allow-list validation (admin | editor | viewer only)
  - Authentication events logged for SIEM/audit (no passwords ever logged)
  - Passwords never appear in logs or error responses
"""
from __future__ import annotations

import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, Field

from api.deps import require_user
from auth.utils import (
    create_access_token, hash_password,
    load_users, save_users, verify_password,
)
from config.settings import settings
from security.middleware import check_rate_limit, get_client_ip, rate_limit_response
from security.validators import InputValidator

log = logging.getLogger(__name__)
auth_router = APIRouter(tags=["auth"])


# ─── Schemas ───────────────────────────────────────────────────────────────────

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str
    role: str


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(..., min_length=1, max_length=128)
    new_password: str = Field(..., min_length=12, max_length=128)

    model_config = {"extra": "ignore"}


class CreateUserRequest(BaseModel):
    username: str = Field(..., min_length=2, max_length=32)
    password: str = Field(..., min_length=12, max_length=128)
    role: str = Field(default="viewer", max_length=16)

    model_config = {"extra": "ignore"}


class UpdateUserRequest(BaseModel):
    role: Optional[str] = Field(default=None, max_length=16)
    new_password: Optional[str] = Field(default=None, max_length=128)

    model_config = {"extra": "ignore"}


class UserOut(BaseModel):
    username: str
    role: str


# ─── Admin dependency ─────────────────────────────────────────────────────────

async def require_admin(username: str = Depends(require_user)) -> str:
    users = load_users()
    if users.get(username, {}).get("role") != "admin":
        log.warning("Authorization failure: '%s' attempted admin action", username)
        raise HTTPException(status_code=403, detail="Admin access required")
    return username


# ─── Endpoints ────────────────────────────────────────────────────────────────

@auth_router.post("/login", response_model=TokenResponse)
async def login(request: Request, form: OAuth2PasswordRequestForm = Depends()):
    """
    Authenticate with username + password.
    Returns a JWT Bearer token (valid for JWT_EXPIRE_MINUTES).

    Rate limited to 10/minute per IP to prevent brute-force attacks.
    Error message is intentionally generic to prevent username enumeration.
    """
    # Rate limiting: 10 login attempts per minute per IP
    client_ip = get_client_ip(request)
    if not check_rate_limit(client_ip, "login", limit=10, window_seconds=60):
        log.warning("Rate limit exceeded on /login from IP: %s", client_ip)
        return rate_limit_response()
    users = load_users()
    user = users.get(form.username)

    # Constant-time comparison — always call verify_password to prevent timing attacks.
    # If user doesn't exist, verify against a pre-computed valid bcrypt dummy hash so
    # timing is consistent (prevents username enumeration via response time).
    # IMPORTANT: this hash MUST be a valid bcrypt string or passlib raises UnknownHashError.
    _dummy_hash = "$2b$12$9jBNdsW2kPtsCC50Va1LYOwy9Q11bOGpncM6EInatErlQggFSfZXS"
    stored_hash = user["hashed_password"] if user else _dummy_hash

    try:
        password_ok = verify_password(form.password, stored_hash)
    except Exception:
        # Treat any hash verification error as a failed login (never 500)
        password_ok = False

    if not user or not password_ok:
        # Log with username for SIEM but return generic message to client
        log.warning("Failed login attempt for username: '%s'", form.username)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",  # Generic — does not confirm if user exists
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = create_access_token(form.username)
    log.info("Successful login: '%s'", form.username)
    return TokenResponse(
        access_token=token,
        username=form.username,
        role=user.get("role", "viewer"),
    )


@auth_router.get("/me")
async def me(username: str = Depends(require_user)):
    """Return current user profile (validates token on the way)."""
    users = load_users()
    user = users.get(username, {})
    return {
        "username": username,
        "role": user.get("role", "viewer"),
    }


@auth_router.post("/change-password")
async def change_password(
    req: ChangePasswordRequest,
    username: str = Depends(require_user),
):
    """Change password for the currently authenticated user."""
    # Validate new password complexity
    InputValidator.password(req.new_password, field_label="New password")

    users = load_users()
    user = users.get(username)
    if not user or not verify_password(req.current_password, user["hashed_password"]):
        raise HTTPException(status_code=400, detail="Current password is incorrect")

    users[username]["hashed_password"] = hash_password(req.new_password)
    save_users(users)
    log.info("Password changed for user: '%s'", username)
    return {"message": "Password changed successfully"}


# ─── Admin — User Management ───────────────────────────────────────────────────

@auth_router.get("/admin/users", response_model=List[UserOut])
async def list_users(_: str = Depends(require_admin)):
    """[Admin] List all users."""
    users = load_users()
    return [UserOut(username=k, role=v.get("role", "viewer")) for k, v in users.items()]


@auth_router.post("/admin/users", response_model=UserOut, status_code=201)
async def create_user(req: CreateUserRequest, _: str = Depends(require_admin)):
    """[Admin] Create a new user."""
    # Validate username format (allow-list: alphanumeric + underscore, 2-32 chars)
    InputValidator.username(req.username)

    # Validate password complexity
    InputValidator.password(req.password)

    # Validate role allow-list
    InputValidator.role(req.role)

    users = load_users()
    if req.username in users:
        raise HTTPException(status_code=409, detail="Username already exists")

    users[req.username] = {
        "username": req.username,
        "hashed_password": hash_password(req.password),
        "role": req.role,
    }
    save_users(users)
    log.info("User created: '%s' (role=%s)", req.username, req.role)
    return UserOut(username=req.username, role=req.role)


@auth_router.put("/admin/users/{username}", response_model=UserOut)
async def update_user(
    username: str,
    req: UpdateUserRequest,
    admin: str = Depends(require_admin),
):
    """[Admin] Update a user's role and/or password."""
    # Validate the target username path parameter
    InputValidator.username(username)

    users = load_users()
    if username not in users:
        raise HTTPException(status_code=404, detail="User not found")

    if req.role is not None:
        InputValidator.role(req.role)
        users[username]["role"] = req.role

    if req.new_password is not None:
        InputValidator.password(req.new_password, field_label="New password")
        users[username]["hashed_password"] = hash_password(req.new_password)

    save_users(users)
    log.info("User updated: '%s' by admin '%s'", username, admin)
    return UserOut(username=username, role=users[username]["role"])


@auth_router.delete("/admin/users/{username}")
async def delete_user(username: str, admin: str = Depends(require_admin)):
    """[Admin] Delete a user. Cannot delete yourself or the last admin."""
    # Validate path parameter
    InputValidator.username(username)

    if username == admin:
        raise HTTPException(status_code=400, detail="You cannot delete your own account")

    users = load_users()
    if username not in users:
        raise HTTPException(status_code=404, detail="User not found")

    # Prevent deleting the last admin
    admins = [u for u, d in users.items() if d.get("role") == "admin"]
    if users[username].get("role") == "admin" and len(admins) <= 1:
        raise HTTPException(status_code=400, detail="Cannot delete the last admin account")

    del users[username]
    save_users(users)
    log.info("User deleted: '%s' by admin '%s'", username, admin)
    return {"message": "User deleted successfully"}
