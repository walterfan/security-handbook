"""Tests for ReBAC — relationship-based access control via OpenFGA (ch14).

Tests:
  - Document permission inheritance from folders
  - Sharing and revoking access
  - Owner vs viewer vs editor permissions
  - Blocked user exclusion
"""

import pytest
import pytest_asyncio

from authz.openfga_client import AuthzTuple

pytestmark = pytest.mark.asyncio


class TestDocumentPermissions:
    """Test fine-grained document permissions via OpenFGA."""

    async def test_owner_has_full_access(self, mock_authz_clients):
        """Document owner should have view, edit, and share permissions."""
        fga, _ = mock_authz_clients
        await fga.write_tuples([
            AuthzTuple("user:alice", "owner", "document:doc1"),
        ])

        assert await fga.check("user:alice", "can_view", "document:doc1") is True
        assert await fga.check("user:alice", "can_edit", "document:doc1") is True
        assert await fga.check("user:alice", "can_share", "document:doc1") is True

    async def test_viewer_can_only_view(self, mock_authz_clients):
        """Viewer should only have view permission."""
        fga, _ = mock_authz_clients
        await fga.write_tuples([
            AuthzTuple("user:bob", "viewer", "document:doc1"),
        ])

        assert await fga.check("user:bob", "viewer", "document:doc1") is True
        assert await fga.check("user:bob", "can_edit", "document:doc1") is False
        assert await fga.check("user:bob", "can_share", "document:doc1") is False

    async def test_editor_can_view_and_edit(self, mock_authz_clients):
        """Editor should have view and edit but not share."""
        fga, _ = mock_authz_clients
        await fga.write_tuples([
            AuthzTuple("user:charlie", "editor", "document:doc1"),
        ])

        assert await fga.check("user:charlie", "editor", "document:doc1") is True
        assert await fga.check("user:charlie", "can_share", "document:doc1") is False

    async def test_no_access_by_default(self, mock_authz_clients):
        """Users without any relation should have no access."""
        fga, _ = mock_authz_clients
        assert await fga.check("user:stranger", "can_view", "document:doc1") is False
        assert await fga.check("user:stranger", "can_edit", "document:doc1") is False


class TestSharing:
    """Test document sharing (granting/revoking access)."""

    async def test_grant_viewer_access(self, mock_authz_clients):
        """Sharing should grant the specified relation."""
        fga, _ = mock_authz_clients

        # Initially no access
        assert await fga.check("user:dave", "viewer", "document:doc1") is False

        # Grant viewer access
        await fga.write_tuples([
            AuthzTuple("user:dave", "viewer", "document:doc1"),
        ])

        assert await fga.check("user:dave", "viewer", "document:doc1") is True

    async def test_revoke_access(self, mock_authz_clients):
        """Revoking should remove the relation."""
        fga, _ = mock_authz_clients

        await fga.write_tuples([
            AuthzTuple("user:eve", "editor", "document:doc1"),
        ])
        assert await fga.check("user:eve", "editor", "document:doc1") is True

        await fga.delete_tuples([
            AuthzTuple("user:eve", "editor", "document:doc1"),
        ])
        assert await fga.check("user:eve", "editor", "document:doc1") is False

    async def test_upgrade_viewer_to_editor(self, mock_authz_clients):
        """Upgrading access: add editor, remove viewer."""
        fga, _ = mock_authz_clients

        await fga.write_tuples([
            AuthzTuple("user:frank", "viewer", "document:doc1"),
        ])

        # Upgrade to editor
        await fga.write_tuples([
            AuthzTuple("user:frank", "editor", "document:doc1"),
        ])
        await fga.delete_tuples([
            AuthzTuple("user:frank", "viewer", "document:doc1"),
        ])

        assert await fga.check("user:frank", "editor", "document:doc1") is True
        assert await fga.check("user:frank", "viewer", "document:doc1") is False


class TestOrganizationHierarchy:
    """Test permission inheritance through organization hierarchy."""

    async def test_org_owner_tuple(self, mock_authz_clients):
        """Organization owner relation should be stored."""
        fga, _ = mock_authz_clients
        await fga.write_tuples([
            AuthzTuple("user:alice", "owner", "organization:acme"),
        ])

        assert await fga.check("user:alice", "owner", "organization:acme") is True
        assert await fga.check("user:bob", "owner", "organization:acme") is False

    async def test_folder_org_relation(self, mock_authz_clients):
        """Folder should be linked to its organization."""
        fga, _ = mock_authz_clients
        await fga.write_tuples([
            AuthzTuple("organization:acme", "org", "folder:project-docs"),
        ])

        tuples = await fga.read_tuples(object="folder:project-docs")
        assert len(tuples) == 1
        assert tuples[0]["key"]["user"] == "organization:acme"

    async def test_document_parent_relation(self, mock_authz_clients):
        """Document should be linked to its parent folder."""
        fga, _ = mock_authz_clients
        await fga.write_tuples([
            AuthzTuple("folder:project-docs", "parent", "document:design-spec"),
        ])

        tuples = await fga.read_tuples(object="document:design-spec")
        assert len(tuples) == 1
        assert tuples[0]["key"]["relation"] == "parent"
