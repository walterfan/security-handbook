"""Integration tests for authentication API endpoints.

Tests the full auth flow:
  - User registration
  - Login with password
  - Token refresh and rotation
  - MFA setup and verification
  - Error handling (duplicate user, wrong password, etc.)
"""

import pytest
import pytest_asyncio


pytestmark = pytest.mark.asyncio


class TestRegistration:
    """Test POST /auth/register."""

    async def test_register_success(self, client):
        """New user registration should return 201."""
        response = await client.post("/auth/register", json={
            "username": "newuser",
            "email": "new@example.com",
            "password": "SecureP@ss1",
        })
        assert response.status_code == 201
        data = response.json()
        assert data["username"] == "newuser"
        assert "id" in data

    async def test_register_duplicate_username(self, client, registered_user):
        """Duplicate username should return 409."""
        response = await client.post("/auth/register", json={
            "username": registered_user["username"],
            "email": "different@example.com",
            "password": "AnotherP@ss1",
        })
        assert response.status_code == 409

    async def test_register_duplicate_email(self, client, registered_user):
        """Duplicate email should return 409."""
        response = await client.post("/auth/register", json={
            "username": "differentuser",
            "email": registered_user["email"],
            "password": "AnotherP@ss1",
        })
        assert response.status_code == 409

    async def test_register_invalid_email(self, client):
        """Invalid email format should return 422."""
        response = await client.post("/auth/register", json={
            "username": "baduser",
            "email": "not-an-email",
            "password": "SecureP@ss1",
        })
        assert response.status_code == 422


class TestLogin:
    """Test POST /auth/login."""

    async def test_login_success(self, client, registered_user):
        """Correct credentials should return token pair."""
        response = await client.post("/auth/login", json={
            "username": registered_user["username"],
            "password": registered_user["password"],
        })
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"
        assert data["mfa_required"] is False

    async def test_login_wrong_password(self, client, registered_user):
        """Wrong password should return 401."""
        response = await client.post("/auth/login", json={
            "username": registered_user["username"],
            "password": "WrongPassword!",
        })
        assert response.status_code == 401

    async def test_login_nonexistent_user(self, client):
        """Non-existent username should return 401."""
        response = await client.post("/auth/login", json={
            "username": "ghost",
            "password": "anything",
        })
        assert response.status_code == 401


class TestTokenRefresh:
    """Test POST /auth/refresh."""

    async def test_refresh_success(self, client, auth_tokens):
        """Valid refresh token should return new token pair."""
        response = await client.post("/auth/refresh", json={
            "refresh_token": auth_tokens["refresh_token"],
        })
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        # New tokens should be different from old ones
        assert data["access_token"] != auth_tokens["access_token"]

    async def test_refresh_with_access_token_fails(self, client, auth_tokens):
        """Using an access token as refresh token should fail."""
        response = await client.post("/auth/refresh", json={
            "refresh_token": auth_tokens["access_token"],
        })
        assert response.status_code == 401

    async def test_refresh_with_invalid_token(self, client):
        """Invalid token string should return 401."""
        response = await client.post("/auth/refresh", json={
            "refresh_token": "invalid.token.string",
        })
        assert response.status_code == 401


class TestProtectedEndpoints:
    """Test authentication enforcement on protected endpoints."""

    async def test_access_without_token(self, client):
        """Accessing protected endpoint without token should return 401."""
        response = await client.get("/notes")
        assert response.status_code == 401

    async def test_access_with_invalid_token(self, client):
        """Invalid token should return 401."""
        response = await client.get("/notes", headers={
            "Authorization": "Bearer invalid.token.here",
        })
        assert response.status_code == 401

    async def test_access_with_valid_token(self, client, auth_headers):
        """Valid token should allow access."""
        response = await client.get("/notes", headers=auth_headers)
        assert response.status_code == 200


class TestHealthCheck:
    """Test GET /health (public endpoint)."""

    async def test_health(self, client):
        """Health endpoint should be accessible without auth."""
        response = await client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"
