"""Shared test fixtures for SecureNote.

Sets up:
  - In-memory SQLite database
  - JWT key pair (generated fresh for each test session)
  - FastAPI test client
  - Pre-registered test user
"""

import os
import tempfile
from pathlib import Path

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

# Generate temporary JWT keys before importing app modules
_tmpdir = tempfile.mkdtemp()
_private_key_path = os.path.join(_tmpdir, "jwt_private.pem")
_public_key_path = os.path.join(_tmpdir, "jwt_public.pem")


def _generate_test_keys():
    """Generate RSA key pair for JWT testing."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    with open(_private_key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    with open(_public_key_path, "wb") as f:
        f.write(private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))


_generate_test_keys()

# Set environment before importing config
os.environ["SECURENOTE_JWT_PRIVATE_KEY_PATH"] = _private_key_path
os.environ["SECURENOTE_JWT_PUBLIC_KEY_PATH"] = _public_key_path
os.environ["SECURENOTE_DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"
os.environ["SECURENOTE_MASTER_KEY_ENV"] = "a" * 64  # 256-bit hex key for testing

from models.database import Base, get_db, engine
from main import app


# ── Database fixtures ───────────────────────────────────

@pytest_asyncio.fixture
async def db_session():
    """Create a fresh in-memory database for each test."""
    test_engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)
    async with session_factory() as session:
        yield session

    await test_engine.dispose()


@pytest_asyncio.fixture
async def client(db_session):
    """FastAPI test client with overridden DB dependency."""
    async def _override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

    app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def registered_user(client):
    """Register a test user and return credentials."""
    user_data = {
        "username": "testuser",
        "email": "test@example.com",
        "password": "StrongP@ssw0rd!",
    }
    response = await client.post("/auth/register", json=user_data)
    assert response.status_code == 201
    return {**user_data, "id": response.json()["id"]}


@pytest_asyncio.fixture
async def auth_tokens(client, registered_user):
    """Login and return token pair."""
    response = await client.post("/auth/login", json={
        "username": registered_user["username"],
        "password": registered_user["password"],
    })
    assert response.status_code == 200
    data = response.json()
    assert data["mfa_required"] is False
    return data


@pytest_asyncio.fixture
async def auth_headers(auth_tokens):
    """Authorization header dict for authenticated requests."""
    return {"Authorization": f"Bearer {auth_tokens['access_token']}"}
