"""
api/auth_routes.py — Login, logout, and user-profile endpoints.
These routes are PUBLIC (no auth required on the router level).
"""
from __future__ import annotations

import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel

from api.deps import require_user
from auth.utils import (
    create_access_token, hash_password,
    load_users, save_users, verify_password,
)

log = logging.getLogger(__name__)
auth_router = APIRouter(tags=["auth"])


# ─── Schemas ────────────────────────────────────────────────────────────────────
class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str
    role: str


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


class CreateUserRequest(BaseModel):
    username: str
    password: str
    role: str = "viewer"  # admin | editor | viewer


class UpdateUserRequest(BaseModel):
    role: Optional[str] = None
    new_password: Optional[str] = None


class UserOut(BaseModel):
    username: str
    role: str


# ─── Admin dependency ─────────────────────────────────────────────────────────────────
async def require_admin(username: str = Depends(require_user)) -> str:
    users = load_users()
    if users.get(username, {}).get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return username


# ─── Endpoints ────────────────────────────────────────────────────────────────

@auth_router.post("/login", response_model=TokenResponse)
async def login(form: OAuth2PasswordRequestForm = Depends()):
    """
    Authenticate with username + password.
    Returns a JWT Bearer token (valid for JWT_EXPIRE_MINUTES).
    """
    users = load_users()
    user = users.get(form.username)
    if not user or not verify_password(form.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = create_access_token(form.username)
    log.info("Login: %s", form.username)
    return TokenResponse(
        access_token=token,
        username=form.username,
        role=user.get("role", "user"),
    )


@auth_router.get("/me")
async def me(username: str = Depends(require_user)):
    """Return current user profile (validates token on the way)."""
    users = load_users()
    user = users.get(username, {})
    return {
        "username": username,
        "role": user.get("role", "user"),
    }


@auth_router.post("/change-password")
async def change_password(
    req: ChangePasswordRequest,
    username: str = Depends(require_user),
):
    """Change password for the currently authenticated user."""
    users = load_users()
    user = users.get(username)
    if not user or not verify_password(req.current_password, user["hashed_password"]):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    if len(req.new_password) < 6:
        raise HTTPException(status_code=400, detail="New password must be at least 6 characters")
    users[username]["hashed_password"] = hash_password(req.new_password)
    save_users(users)
    log.info("Password changed: %s", username)
    return {"message": "Password changed successfully"}


# ─── Admin — User Management ───────────────────────────────────────────────────────────────
@auth_router.get("/admin/users", response_model=List[UserOut])
async def list_users(_: str = Depends(require_admin)):
    """[Admin] List all users."""
    users = load_users()
    return [UserOut(username=k, role=v.get("role", "viewer")) for k, v in users.items()]


@auth_router.post("/admin/users", response_model=UserOut, status_code=201)
async def create_user(req: CreateUserRequest, _: str = Depends(require_admin)):
    """[Admin] Create a new user."""
    users = load_users()
    if req.username in users:
        raise HTTPException(status_code=409, detail=f"User '{req.username}' already exists")
    if len(req.username.strip()) < 2:
        raise HTTPException(status_code=400, detail="Username must be at least 2 characters")
    if len(req.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")
    if req.role not in ("admin", "editor", "viewer"):
        raise HTTPException(status_code=400, detail="Role must be admin, editor, or viewer")
    users[req.username] = {
        "username": req.username,
        "hashed_password": hash_password(req.password),
        "role": req.role,
    }
    save_users(users)
    log.info("User created: %s (%s)", req.username, req.role)
    return UserOut(username=req.username, role=req.role)


@auth_router.put("/admin/users/{username}", response_model=UserOut)
async def update_user(
    username: str,
    req: UpdateUserRequest,
    admin: str = Depends(require_admin),
):
    """[Admin] Update a user's role and/or password."""
    users = load_users()
    if username not in users:
        raise HTTPException(status_code=404, detail=f"User '{username}' not found")
    if req.role:
        if req.role not in ("admin", "editor", "viewer"):
            raise HTTPException(status_code=400, detail="Role must be admin, editor, or viewer")
        users[username]["role"] = req.role
    if req.new_password:
        if len(req.new_password) < 6:
            raise HTTPException(status_code=400, detail="Password must be at least 6 characters")
        users[username]["hashed_password"] = hash_password(req.new_password)
    save_users(users)
    log.info("User updated: %s by %s", username, admin)
    return UserOut(username=username, role=users[username]["role"])


@auth_router.delete("/admin/users/{username}")
async def delete_user(username: str, admin: str = Depends(require_admin)):
    """[Admin] Delete a user. Cannot delete yourself."""
    if username == admin:
        raise HTTPException(status_code=400, detail="You cannot delete your own account")
    users = load_users()
    if username not in users:
        raise HTTPException(status_code=404, detail=f"User '{username}' not found")
    # Prevent deleting the last admin
    admins = [u for u, d in users.items() if d.get("role") == "admin"]
    if users[username].get("role") == "admin" and len(admins) <= 1:
        raise HTTPException(status_code=400, detail="Cannot delete the last admin account")
    del users[username]
    save_users(users)
    log.info("User deleted: %s by %s", username, admin)
    return {"message": f"User '{username}' deleted"}
