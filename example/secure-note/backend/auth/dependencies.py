"""FastAPI dependency injection for authentication.

Demonstrates ch25 — Security Framework Integration:
  - OAuth2PasswordBearer scheme for Swagger UI integration
  - Layered dependencies: token → user → active user
  - Token blacklist check for revocation support (ch09)
  - Optional MFA enforcement (ch10)
"""

from datetime import datetime, timezone

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth.jwt_handler import decode_token
from models.database import get_db
from models.user import User, RevokedToken

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Extract and validate the current user from the JWT access token.

    Checks:
      1. Token signature and expiration (RS256)
      2. Token type is "access" (not refresh)
      3. Token is not in the revocation blacklist
      4. User exists and is active
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    # 1. Decode and verify JWT
    try:
        payload = decode_token(token)
    except JWTError:
        raise credentials_exception

    # 2. Check token type
    if payload.get("type") != "access":
        raise credentials_exception

    # 3. Check revocation blacklist
    jti = payload.get("jti")
    if jti:
        result = await db.execute(select(RevokedToken).where(RevokedToken.jti == jti))
        if result.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has been revoked",
                headers={"WWW-Authenticate": "Bearer"},
            )

    # 4. Load user
    user_id = payload.get("sub")
    if not user_id:
        raise credentials_exception

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise credentials_exception

    return user


async def get_current_active_user(
    user: User = Depends(get_current_user),
) -> User:
    """Ensure the current user is active (not disabled/banned)."""
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is disabled",
        )
    return user


async def require_mfa_verified(
    user: User = Depends(get_current_active_user),
    token: str = Depends(oauth2_scheme),
) -> User:
    """Ensure the user has completed MFA verification (if MFA is enabled).

    The JWT should contain an 'mfa_verified' claim set to True
    after successful TOTP verification.
    """
    if not user.totp_enabled:
        return user  # MFA not enabled, skip check

    try:
        payload = decode_token(token)
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

    if not payload.get("mfa_verified"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="MFA verification required",
        )
    return user
