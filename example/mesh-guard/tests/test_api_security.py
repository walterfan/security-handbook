"""API Security tests (ch12: API Auth, ch26: API Security).

Tests:
  - HMAC signature verification
  - Replay attack protection (timestamp validation)
  - Rate limit headers
  - Input validation
"""

import hashlib
import hmac
import os
import time
from datetime import datetime, timezone

import pytest
import httpx

INTEGRATION = os.getenv("INTEGRATION_TEST", "false").lower() == "true"
BASE_URL = os.getenv("API_GATEWAY_URL", "http://localhost:8080")

pytestmark = pytest.mark.skipif(not INTEGRATION, reason="Integration tests disabled")


def compute_hmac(message: str, secret: str) -> str:
    """Compute HMAC-SHA256 signature (mirrors Go implementation)."""
    return hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()


class TestHMACAuthentication:
    """Test HMAC API signature verification (ch12)."""

    @pytest.mark.asyncio
    async def test_valid_hmac_signature(self):
        """Request with valid HMAC should succeed."""
        secret = os.getenv("HMAC_SECRET", "demo-secret-change-me")
        api_key = "test-api-key"
        timestamp = datetime.now(timezone.utc).isoformat()
        signature = compute_hmac(api_key + timestamp, secret)

        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{BASE_URL}/api/orders",
                headers={
                    "X-API-Key": api_key,
                    "X-Timestamp": timestamp,
                    "X-Signature": signature,
                },
            )
            assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_invalid_hmac_signature(self):
        """Request with invalid HMAC should be rejected."""
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{BASE_URL}/api/orders",
                headers={
                    "X-API-Key": "test-key",
                    "X-Timestamp": datetime.now(timezone.utc).isoformat(),
                    "X-Signature": "invalid-signature",
                },
            )
            assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_expired_timestamp_rejected(self):
        """Request with old timestamp should be rejected (replay protection)."""
        secret = os.getenv("HMAC_SECRET", "demo-secret-change-me")
        api_key = "test-key"
        # 10 minutes ago
        old_time = datetime(2020, 1, 1, tzinfo=timezone.utc).isoformat()
        signature = compute_hmac(api_key + old_time, secret)

        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{BASE_URL}/api/orders",
                headers={
                    "X-API-Key": api_key,
                    "X-Timestamp": old_time,
                    "X-Signature": signature,
                },
            )
            assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_missing_headers_rejected(self):
        """Request with partial auth headers should be rejected."""
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{BASE_URL}/api/orders",
                headers={"X-API-Key": "test-key"},  # missing timestamp & signature
            )
            assert resp.status_code == 401


class TestRateLimiting:
    """Test rate limiting headers (ch26)."""

    @pytest.mark.asyncio
    async def test_rate_limit_headers_present(self):
        """Response should include rate limit headers."""
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{BASE_URL}/api/orders")
            assert "X-RateLimit-Limit" in resp.headers
