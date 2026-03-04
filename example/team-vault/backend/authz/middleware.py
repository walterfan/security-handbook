"""Authorization middleware — PEP (Policy Enforcement Point).

Demonstrates ch17 — Authorization Architecture:
  - PEP intercepts every request
  - Layer 1: OPA evaluates coarse-grained API policy
  - Layer 2: OpenFGA evaluates fine-grained resource permissions
  - Fail-closed: deny by default if any check fails

Request flow:
  Request → [PEP Middleware] → [OPA: API policy] → [Route Handler] → [OpenFGA: resource check] → Response
"""

import logging
from datetime import datetime, timezone

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt

from authz.opa_client import OPAClient, OPAInput, get_opa_client
from authz.openfga_client import OpenFGAClient, get_fga_client
from config import settings
from models.database import get_db

logger = logging.getLogger(__name__)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login", auto_error=False)


# ── JWT Decoding ────────────────────────────────────────

def decode_jwt(token: str) -> dict:
    """Decode and verify JWT token."""
    return jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])


# ── Layer 1: OPA API Policy Check ──────────────────────

async def check_api_policy(
    request: Request,
    token: str | None = Depends(oauth2_scheme),
) -> dict | None:
    """PEP Layer 1: Check OPA API-level policy.

    Evaluates:
      - Is this endpoint public or protected?
      - Is the source IP allowed for admin endpoints?
      - What rate limit tier applies?

    Returns the decoded user dict if authenticated, None for public endpoints.
    """
    # Decode user from token (if present)
    user_info = None
    if token:
        try:
            payload = decode_jwt(token)
            user_info = {
                "id": payload.get("sub"),
                "role": payload.get("role", "member"),
                "username": payload.get("username"),
            }
        except JWTError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
                headers={"WWW-Authenticate": "Bearer"},
            )

    # Build OPA input
    opa_input = OPAInput(
        path=request.url.path,
        method=request.method,
        source_ip=request.client.host if request.client else "0.0.0.0",
        user=user_info,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )

    # Evaluate OPA policy
    opa = get_opa_client()
    decision = await opa.evaluate(opa_input)

    if not decision.allow:
        logger.warning(
            f"OPA DENY: {request.method} {request.url.path} "
            f"from {opa_input.source_ip} (reasons: {decision.reasons})"
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access denied by policy: {', '.join(decision.reasons)}",
        )

    # Store rate limit tier in request state for downstream use
    request.state.rate_limit_tier = decision.rate_limit_tier

    return user_info


# ── Layer 2: OpenFGA Resource Check ────────────────────

async def check_resource_permission(
    user_id: str,
    relation: str,
    resource_type: str,
    resource_id: str,
) -> bool:
    """PEP Layer 2: Check OpenFGA fine-grained permission.

    Example:
        check_resource_permission("alice", "can_edit", "document", "readme")
        → Checks: (user:alice, can_edit, document:readme)

    Returns True if allowed, raises 403 if denied.
    """
    fga = get_fga_client()
    allowed = await fga.check(
        user=f"user:{user_id}",
        relation=relation,
        object=f"{resource_type}:{resource_id}",
    )

    if not allowed:
        logger.warning(
            f"OpenFGA DENY: user:{user_id} {relation} {resource_type}:{resource_id}"
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"You don't have '{relation}' permission on this {resource_type}",
        )

    return True


# ── Convenience Dependencies ────────────────────────────

async def require_authenticated(
    user: dict | None = Depends(check_api_policy),
) -> dict:
    """Require an authenticated user (after OPA check)."""
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


async def require_org_admin(
    user: dict = Depends(require_authenticated),
) -> dict:
    """Require the user to have admin or owner role."""
    if user.get("role") not in ("admin", "owner"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin or owner role required",
        )
    return user
