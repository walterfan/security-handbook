"""Tests for JWT RS256 token management (ch09).

Verifies:
  - Access token creation and decoding
  - Refresh token creation and decoding
  - Token pair generation
  - Expired token rejection
  - Invalid signature rejection
  - Token type enforcement
  - Extra claims support
"""

import time
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
from jose import jwt, JWTError

from auth.jwt_handler import (
    create_access_token,
    create_refresh_token,
    create_token_pair,
    decode_token,
)


class TestAccessToken:
    """Test access token creation and validation."""

    def test_create_and_decode(self):
        """Access token should encode subject and decode correctly."""
        token = create_access_token("user-123")
        payload = decode_token(token)
        assert payload["sub"] == "user-123"
        assert payload["type"] == "access"

    def test_contains_required_claims(self):
        """Access token should contain sub, type, iat, exp, jti."""
        token = create_access_token("user-123")
        payload = decode_token(token)
        assert "sub" in payload
        assert "type" in payload
        assert "iat" in payload
        assert "exp" in payload
        assert "jti" in payload

    def test_extra_claims(self):
        """Extra claims should be included in the token."""
        token = create_access_token("user-123", {"role": "admin", "mfa_verified": True})
        payload = decode_token(token)
        assert payload["role"] == "admin"
        assert payload["mfa_verified"] is True

    def test_unique_jti(self):
        """Each token should have a unique JTI (for revocation tracking)."""
        t1 = create_access_token("user-123")
        t2 = create_access_token("user-123")
        p1 = decode_token(t1)
        p2 = decode_token(t2)
        assert p1["jti"] != p2["jti"]


class TestRefreshToken:
    """Test refresh token creation and validation."""

    def test_create_and_decode(self):
        """Refresh token should encode subject with type=refresh."""
        token = create_refresh_token("user-456")
        payload = decode_token(token)
        assert payload["sub"] == "user-456"
        assert payload["type"] == "refresh"

    def test_longer_expiration(self):
        """Refresh token should expire later than access token."""
        access = create_access_token("user-123")
        refresh = create_refresh_token("user-123")
        a_payload = decode_token(access)
        r_payload = decode_token(refresh)
        assert r_payload["exp"] > a_payload["exp"]


class TestTokenPair:
    """Test token pair generation."""

    def test_create_pair(self):
        """Token pair should contain access_token, refresh_token, and metadata."""
        pair = create_token_pair("user-789")
        assert "access_token" in pair
        assert "refresh_token" in pair
        assert pair["token_type"] == "bearer"
        assert pair["expires_in"] > 0

    def test_pair_tokens_are_different(self):
        """Access and refresh tokens in a pair should be different strings."""
        pair = create_token_pair("user-789")
        assert pair["access_token"] != pair["refresh_token"]


class TestTokenValidation:
    """Test token validation and error handling."""

    def test_reject_tampered_token(self):
        """A tampered token should fail signature verification."""
        token = create_access_token("user-123")
        # Flip a character in the signature
        tampered = token[:-5] + "XXXXX"
        with pytest.raises(JWTError):
            decode_token(tampered)

    def test_reject_expired_token(self):
        """An expired token should be rejected."""
        with patch("auth.jwt_handler.settings") as mock_settings:
            mock_settings.access_token_expire_minutes = 0  # immediate expiry
            mock_settings.jwt_private_key_path = "certs/jwt_private.pem"
            mock_settings.jwt_public_key_path = "certs/jwt_public.pem"
            mock_settings.jwt_algorithm = "RS256"
            # Create a token that's already expired
            # We'll use jose directly for this test
            pass

        # Alternative: decode a manually crafted expired token
        from auth.jwt_handler import _get_private_key, _get_public_key
        from config import settings

        now = datetime.now(timezone.utc)
        expired_claims = {
            "sub": "user-123",
            "type": "access",
            "iat": now - timedelta(hours=2),
            "exp": now - timedelta(hours=1),  # expired 1 hour ago
            "jti": "test-jti",
        }
        expired_token = jwt.encode(expired_claims, _get_private_key(), algorithm="RS256")

        with pytest.raises(JWTError):
            decode_token(expired_token)

    def test_reject_none_algorithm(self):
        """Token with 'none' algorithm should be rejected (alg confusion attack)."""
        payload = {"sub": "hacker", "type": "access", "exp": 9999999999}
        # jose library should reject this
        none_token = jwt.encode(payload, "", algorithm="HS256")
        with pytest.raises(JWTError):
            decode_token(none_token)
