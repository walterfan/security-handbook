"""Tests for OpenFGA client wrapper (ch14, ch18).

Tests the mock OpenFGA client to verify:
  - Tuple write/read/delete operations
  - Authorization check queries
  - List objects queries
"""

import pytest
import pytest_asyncio

from authz.openfga_client import AuthzTuple, get_fga_client

pytestmark = pytest.mark.asyncio


class TestTupleOperations:
    """Test tuple CRUD operations."""

    async def test_write_and_read_tuples(self, mock_authz_clients):
        fga, _ = mock_authz_clients
        await fga.write_tuples([
            AuthzTuple("user:alice", "owner", "document:doc1"),
            AuthzTuple("user:bob", "viewer", "document:doc1"),
        ])

        tuples = await fga.read_tuples(object="document:doc1")
        assert len(tuples) == 2

    async def test_delete_tuples(self, mock_authz_clients):
        fga, _ = mock_authz_clients
        await fga.write_tuples([
            AuthzTuple("user:alice", "editor", "document:doc2"),
        ])
        assert len(await fga.read_tuples(object="document:doc2")) == 1

        await fga.delete_tuples([
            AuthzTuple("user:alice", "editor", "document:doc2"),
        ])
        assert len(await fga.read_tuples(object="document:doc2")) == 0

    async def test_read_with_user_filter(self, mock_authz_clients):
        fga, _ = mock_authz_clients
        await fga.write_tuples([
            AuthzTuple("user:alice", "owner", "document:doc1"),
            AuthzTuple("user:bob", "viewer", "document:doc1"),
            AuthzTuple("user:alice", "editor", "document:doc2"),
        ])

        alice_tuples = await fga.read_tuples(user="user:alice")
        assert len(alice_tuples) == 2

    async def test_read_with_relation_filter(self, mock_authz_clients):
        fga, _ = mock_authz_clients
        await fga.write_tuples([
            AuthzTuple("user:alice", "owner", "document:doc1"),
            AuthzTuple("user:bob", "owner", "document:doc2"),
            AuthzTuple("user:charlie", "viewer", "document:doc1"),
        ])

        owners = await fga.read_tuples(relation="owner")
        assert len(owners) == 2


class TestAuthorizationChecks:
    """Test authorization check queries."""

    async def test_direct_check_allowed(self, mock_authz_clients):
        fga, _ = mock_authz_clients
        await fga.write_tuples([
            AuthzTuple("user:alice", "editor", "document:doc1"),
        ])
        assert await fga.check("user:alice", "editor", "document:doc1") is True

    async def test_direct_check_denied(self, mock_authz_clients):
        fga, _ = mock_authz_clients
        assert await fga.check("user:alice", "editor", "document:doc1") is False

    async def test_owner_implies_permissions(self, mock_authz_clients):
        """Owner should have can_view, can_edit, can_share (mock simplification)."""
        fga, _ = mock_authz_clients
        await fga.write_tuples([
            AuthzTuple("user:alice", "owner", "document:doc1"),
        ])
        assert await fga.check("user:alice", "can_view", "document:doc1") is True
        assert await fga.check("user:alice", "can_edit", "document:doc1") is True
        assert await fga.check("user:alice", "can_share", "document:doc1") is True

    async def test_viewer_cannot_edit(self, mock_authz_clients):
        fga, _ = mock_authz_clients
        await fga.write_tuples([
            AuthzTuple("user:bob", "viewer", "document:doc1"),
        ])
        assert await fga.check("user:bob", "viewer", "document:doc1") is True
        assert await fga.check("user:bob", "can_edit", "document:doc1") is False


class TestListObjects:
    """Test list objects queries."""

    async def test_list_user_documents(self, mock_authz_clients):
        fga, _ = mock_authz_clients
        await fga.write_tuples([
            AuthzTuple("user:alice", "editor", "document:doc1"),
            AuthzTuple("user:alice", "editor", "document:doc2"),
            AuthzTuple("user:bob", "editor", "document:doc3"),
        ])

        objects = await fga.list_objects("user:alice", "editor", "document")
        assert len(objects) == 2
        assert "document:doc1" in objects
        assert "document:doc2" in objects
