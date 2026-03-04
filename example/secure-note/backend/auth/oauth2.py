"""OAuth2 Authorization Code Flow with PKCE + OIDC integration.

Demonstrates ch07 (OAuth 2.0) and ch08 (OpenID Connect):
  - Authorization Code Flow (most secure for server-side apps)
  - PKCE (Proof Key for Code Exchange) — prevents authorization code interception
  - State parameter — prevents CSRF attacks
  - OIDC: ID Token validation, userinfo endpoint

Security notes:
  - PKCE is mandatory for public clients, recommended for all clients
  - State must be cryptographically random and bound to the user's session
  - ID tokens must be validated: issuer, audience, expiration, nonce
"""

import hashlib
import secrets
import base64
from dataclasses import dataclass
from urllib.parse import urlencode

import httpx

from config import settings


# ── PKCE helpers (ch07) ─────────────────────────────────

def generate_code_verifier() -> str:
    """Generate a PKCE code_verifier (43-128 chars, URL-safe).

    The code_verifier is a high-entropy random string created by the client.
    It is sent to the token endpoint to prove possession.
    """
    return secrets.token_urlsafe(64)[:128]


def generate_code_challenge(verifier: str) -> str:
    """Derive code_challenge from code_verifier using S256.

    code_challenge = BASE64URL(SHA256(code_verifier))

    The authorization server stores this and verifies it when the
    client exchanges the authorization code for tokens.
    """
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def generate_state() -> str:
    """Generate a random state parameter for CSRF protection."""
    return secrets.token_urlsafe(32)


def generate_nonce() -> str:
    """Generate a nonce for OIDC ID token replay protection."""
    return secrets.token_urlsafe(32)


# ── OAuth2 Provider Configuration ───────────────────────

@dataclass
class OAuthProvider:
    """Configuration for an OAuth2/OIDC provider."""
    name: str
    client_id: str
    client_secret: str
    authorize_url: str
    token_url: str
    userinfo_url: str
    scopes: list[str]


PROVIDERS: dict[str, OAuthProvider] = {}

if settings.google_client_id:
    PROVIDERS["google"] = OAuthProvider(
        name="google",
        client_id=settings.google_client_id,
        client_secret=settings.google_client_secret,
        authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
        token_url="https://oauth2.googleapis.com/token",
        userinfo_url="https://openidconnect.googleapis.com/v1/userinfo",
        scopes=["openid", "email", "profile"],
    )

if settings.github_client_id:
    PROVIDERS["github"] = OAuthProvider(
        name="github",
        client_id=settings.github_client_id,
        client_secret=settings.github_client_secret,
        authorize_url="https://github.com/login/oauth/authorize",
        token_url="https://github.com/login/oauth/access_token",
        userinfo_url="https://api.github.com/user",
        scopes=["read:user", "user:email"],
    )


def build_authorization_url(
    provider: OAuthProvider,
    state: str,
    code_challenge: str,
    nonce: str | None = None,
) -> str:
    """Build the authorization URL to redirect the user to the IdP.

    Includes PKCE code_challenge and state for security.
    """
    params = {
        "client_id": provider.client_id,
        "redirect_uri": settings.oauth2_redirect_uri,
        "response_type": "code",
        "scope": " ".join(provider.scopes),
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    if nonce:
        params["nonce"] = nonce
    return f"{provider.authorize_url}?{urlencode(params)}"


async def exchange_code_for_tokens(
    provider: OAuthProvider,
    code: str,
    code_verifier: str,
) -> dict:
    """Exchange authorization code for tokens at the token endpoint.

    Sends the code_verifier to prove PKCE possession.

    Returns:
        Token response dict with access_token, id_token (if OIDC), etc.
    """
    async with httpx.AsyncClient() as client:
        response = await client.post(
            provider.token_url,
            data={
                "grant_type": "authorization_code",
                "client_id": provider.client_id,
                "client_secret": provider.client_secret,
                "code": code,
                "redirect_uri": settings.oauth2_redirect_uri,
                "code_verifier": code_verifier,
            },
            headers={"Accept": "application/json"},
        )
        response.raise_for_status()
        return response.json()


async def fetch_userinfo(provider: OAuthProvider, access_token: str) -> dict:
    """Fetch user profile from the provider's userinfo endpoint.

    Returns:
        User info dict (fields vary by provider)
    """
    async with httpx.AsyncClient() as client:
        response = await client.get(
            provider.userinfo_url,
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json",
            },
        )
        response.raise_for_status()
        return response.json()
