"""JWT token management with RS256 asymmetric signing.

Demonstrates ch09 — JSON Web Token:
  - RS256 (RSA + SHA-256): private key signs, public key verifies
  - Access Token (short-lived, 15 min) + Refresh Token (long-lived, 7 days)
  - JTI (JWT ID) for token revocation / blacklist
  - Claims: sub, exp, iat, jti, type

Security notes:
  - Asymmetric signing allows microservices to verify without the signing key
  - Refresh tokens should be stored securely (httpOnly cookie or encrypted DB)
  - Token blacklist is checked on every request for revoked tokens
"""

import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from jose import JWTError, jwt

from config import settings


def _load_key(path: str) -> str:
    """Load a PEM key from file."""
    return Path(path).read_text()


def _get_private_key() -> str:
    return _load_key(settings.jwt_private_key_path)


def _get_public_key() -> str:
    return _load_key(settings.jwt_public_key_path)


def create_access_token(subject: str, extra_claims: dict | None = None) -> str:
    """Create a short-lived access token.

    Args:
        subject: User ID (stored in 'sub' claim)
        extra_claims: Additional claims (e.g., roles, permissions)

    Returns:
        Encoded JWT string
    """
    now = datetime.now(timezone.utc)
    claims = {
        "sub": subject,
        "type": "access",
        "iat": now,
        "exp": now + timedelta(minutes=settings.access_token_expire_minutes),
        "jti": str(uuid.uuid4()),
    }
    if extra_claims:
        claims.update(extra_claims)

    return jwt.encode(claims, _get_private_key(), algorithm=settings.jwt_algorithm)


def create_refresh_token(subject: str) -> str:
    """Create a long-lived refresh token.

    Refresh tokens are used to obtain new access tokens without re-authentication.
    They should be stored securely and can be revoked via the blacklist.
    """
    now = datetime.now(timezone.utc)
    claims = {
        "sub": subject,
        "type": "refresh",
        "iat": now,
        "exp": now + timedelta(days=settings.refresh_token_expire_days),
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(claims, _get_private_key(), algorithm=settings.jwt_algorithm)


def decode_token(token: str) -> dict:
    """Decode and verify a JWT token.

    Raises:
        JWTError: If the token is invalid, expired, or signature verification fails.

    Returns:
        Decoded claims dictionary
    """
    return jwt.decode(
        token,
        _get_public_key(),
        algorithms=[settings.jwt_algorithm],
        options={"require_exp": True, "require_sub": True},
    )


def create_token_pair(subject: str, extra_claims: dict | None = None) -> dict:
    """Create both access and refresh tokens.

    Returns:
        {"access_token": "...", "refresh_token": "...", "token_type": "bearer"}
    """
    return {
        "access_token": create_access_token(subject, extra_claims),
        "refresh_token": create_refresh_token(subject),
        "token_type": "bearer",
        "expires_in": settings.access_token_expire_minutes * 60,
    }
