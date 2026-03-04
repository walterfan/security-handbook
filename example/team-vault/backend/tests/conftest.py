"""Shared test fixtures for TeamVault.

Sets up:
  - In-memory SQLite database
  - FastAPI test client
  - Mock OpenFGA and OPA clients
  - Pre-registered test users
"""

import os
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

os.environ["TEAMVAULT_DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"
os.environ["TEAMVAULT_JWT_SECRET"] = "test-secret-key-for-testing"

from models.database import Base, get_db
from authz.openfga_client import OpenFGAClient, get_fga_client
from authz.opa_client import OPAClient, OPADecision, get_opa_client
from main import app
import authz.openfga_client as fga_module
import authz.opa_client as opa_module


# ── Mock OpenFGA Client ─────────────────────────────────

class MockOpenFGAClient:
    """In-memory mock of OpenFGA for testing without a running server.

    Stores tuples in a dict and evaluates simple check queries.
    Does NOT implement full ReBAC resolution (no inheritance).
    """

    def __init__(self):
        self.tuples: list[dict] = []
        self.store_id = "test-store"
        self.model_id = "test-model"

    async def write_tuples(self, tuples):
        for t in tuples:
            self.tuples.append({"user": t.user, "relation": t.relation, "object": t.object})

    async def delete_tuples(self, tuples):
        for t in tuples:
            self.tuples = [
                x for x in self.tuples
                if not (x["user"] == t.user and x["relation"] == t.relation and x["object"] == t.object)
            ]

    async def read_tuples(self, user=None, relation=None, object=None):
        results = []
        for t in self.tuples:
            if user and t["user"] != user:
                continue
            if relation and t["relation"] != relation:
                continue
            if object and t["object"] != object:
                continue
            results.append({"key": t})
        return results

    async def check(self, user, relation, object):
        """Simple direct check — no inheritance resolution."""
        for t in self.tuples:
            if t["user"] == user and t["relation"] == relation and t["object"] == object:
                return True
        # Check if user is owner (owner implies all relations)
        if relation in ("can_view", "can_edit", "can_share", "editor", "viewer", "admin"):
            for t in self.tuples:
                if t["user"] == user and t["relation"] == "owner" and t["object"] == object:
                    return True
        return False

    async def list_objects(self, user, relation, type):
        results = []
        for t in self.tuples:
            if t["user"] == user and t["relation"] == relation and t["object"].startswith(f"{type}:"):
                results.append(t["object"])
        return results

    async def expand(self, relation, object):
        return {"tree": {}}

    async def create_store(self, name):
        return {"id": self.store_id}

    async def write_model(self, model_json):
        return {"authorization_model_id": self.model_id}


# ── Mock OPA Client ─────────────────────────────────────

class MockOPAClient:
    """Mock OPA that always allows (for testing authorization logic separately)."""

    async def evaluate(self, input_data):
        return OPADecision(
            allow=True,
            rate_limit_tier="standard",
            reasons=["test_allow"],
        )

    async def check_health(self):
        return True


# ── Fixtures ────────────────────────────────────────────

@pytest.fixture(autouse=True)
def mock_authz_clients():
    """Replace real OpenFGA and OPA clients with mocks."""
    mock_fga = MockOpenFGAClient()
    mock_opa = MockOPAClient()

    fga_module._fga_client = mock_fga
    opa_module._opa_client = mock_opa

    yield mock_fga, mock_opa

    fga_module._fga_client = None
    opa_module._opa_client = None


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
    """Register a test user and return credentials + token."""
    resp = await client.post("/auth/register", json={
        "username": "alice",
        "email": "alice@example.com",
        "password": "AliceP@ss1",
    })
    assert resp.status_code == 201
    user_data = resp.json()

    login_resp = await client.post("/auth/login", json={
        "username": "alice",
        "password": "AliceP@ss1",
    })
    assert login_resp.status_code == 200
    token = login_resp.json()["access_token"]

    return {
        "id": user_data["id"],
        "username": "alice",
        "token": token,
        "headers": {"Authorization": f"Bearer {token}"},
    }


@pytest_asyncio.fixture
async def second_user(client):
    """Register a second test user."""
    resp = await client.post("/auth/register", json={
        "username": "bob",
        "email": "bob@example.com",
        "password": "BobP@ss123",
    })
    assert resp.status_code == 201
    user_data = resp.json()

    login_resp = await client.post("/auth/login", json={
        "username": "bob",
        "password": "BobP@ss123",
    })
    token = login_resp.json()["access_token"]

    return {
        "id": user_data["id"],
        "username": "bob",
        "token": token,
        "headers": {"Authorization": f"Bearer {token}"},
    }
