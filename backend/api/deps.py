"""
api/deps.py — reusable FastAPI dependencies (auth guard).
"""
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

from auth.utils import decode_token, load_users

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


async def require_user(token: str = Depends(oauth2_scheme)) -> str:
    """
    Dependency injected into protected routers.
    Validates the Bearer JWT and returns the username.
    Raises 401 if the token is missing, expired, or the user no longer exists.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Token invalid or expired — please log in again",
        headers={"WWW-Authenticate": "Bearer"},
    )
    username = decode_token(token)
    if not username:
        raise credentials_exception

    users = load_users()
    if username not in users:
        raise credentials_exception

    return username
