"""Integration tests for Documents API with authorization (ch14, ch18).

Tests the full document lifecycle with OpenFGA permission checks:
  - Create document (auto-grants owner)
  - Read document (requires can_view)
  - Update document (requires can_edit)
  - Delete document (requires owner)
  - Share / revoke access
"""

import pytest
import pytest_asyncio

pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture
async def org_and_folder(client, registered_user):
    """Create an organization and folder for document tests."""
    # Create org
    org_resp = await client.post("/organizations", json={
        "name": "Doc Test Org", "slug": "doc-test-org",
    }, headers=registered_user["headers"])
    org_id = org_resp.json()["id"]

    # Create folder
    folder_resp = await client.post("/documents/folders", json={
        "name": "Test Folder",
        "org_id": org_id,
    }, headers=registered_user["headers"])
    folder_id = folder_resp.json()["id"]

    return {"org_id": org_id, "folder_id": folder_id}


class TestDocumentCRUD:
    """Test document create/read/update/delete."""

    async def test_create_document(self, client, registered_user, org_and_folder):
        resp = await client.post("/documents", json={
            "title": "Design Spec",
            "content": "# Architecture\n\nThis is the design.",
            "folder_id": org_and_folder["folder_id"],
        }, headers=registered_user["headers"])
        assert resp.status_code == 201
        data = resp.json()
        assert data["title"] == "Design Spec"
        assert data["created_by"] == registered_user["id"]

    async def test_get_document_as_owner(self, client, registered_user, org_and_folder):
        """Owner should be able to read their document."""
        create_resp = await client.post("/documents", json={
            "title": "My Doc",
            "content": "Secret content",
            "folder_id": org_and_folder["folder_id"],
        }, headers=registered_user["headers"])
        doc_id = create_resp.json()["id"]

        resp = await client.get(f"/documents/{doc_id}", headers=registered_user["headers"])
        assert resp.status_code == 200
        assert resp.json()["content"] == "Secret content"

    async def test_update_document(self, client, registered_user, org_and_folder):
        create_resp = await client.post("/documents", json={
            "title": "Original",
            "content": "v1",
            "folder_id": org_and_folder["folder_id"],
        }, headers=registered_user["headers"])
        doc_id = create_resp.json()["id"]

        resp = await client.put(f"/documents/{doc_id}", json={
            "title": "Updated",
            "content": "v2",
        }, headers=registered_user["headers"])
        assert resp.status_code == 200
        assert resp.json()["title"] == "Updated"
        assert resp.json()["content"] == "v2"

    async def test_delete_document(self, client, registered_user, org_and_folder):
        create_resp = await client.post("/documents", json={
            "title": "Delete Me",
            "content": "bye",
            "folder_id": org_and_folder["folder_id"],
        }, headers=registered_user["headers"])
        doc_id = create_resp.json()["id"]

        resp = await client.delete(f"/documents/{doc_id}", headers=registered_user["headers"])
        assert resp.status_code == 204

        # Verify deleted
        resp = await client.get(f"/documents/{doc_id}", headers=registered_user["headers"])
        assert resp.status_code in (403, 404)

    async def test_get_nonexistent_document(self, client, registered_user):
        resp = await client.get("/documents/nonexistent", headers=registered_user["headers"])
        assert resp.status_code in (403, 404)


class TestDocumentSharing:
    """Test document sharing between users."""

    async def test_share_document_with_viewer(self, client, registered_user, second_user, org_and_folder):
        """Owner shares document with another user as viewer."""
        # Create document
        create_resp = await client.post("/documents", json={
            "title": "Shared Doc",
            "content": "Shared content",
            "folder_id": org_and_folder["folder_id"],
        }, headers=registered_user["headers"])
        doc_id = create_resp.json()["id"]

        # Share with second user
        resp = await client.post(f"/documents/{doc_id}/share", json={
            "user_id": second_user["id"],
            "relation": "viewer",
        }, headers=registered_user["headers"])
        assert resp.status_code == 201

    async def test_revoke_share(self, client, registered_user, second_user, org_and_folder):
        """Owner revokes shared access."""
        create_resp = await client.post("/documents", json={
            "title": "Revoke Doc",
            "content": "Will be unshared",
            "folder_id": org_and_folder["folder_id"],
        }, headers=registered_user["headers"])
        doc_id = create_resp.json()["id"]

        # Share then revoke
        await client.post(f"/documents/{doc_id}/share", json={
            "user_id": second_user["id"],
            "relation": "editor",
        }, headers=registered_user["headers"])

        resp = await client.delete(
            f"/documents/{doc_id}/share/{second_user['id']}",
            headers=registered_user["headers"],
        )
        assert resp.status_code == 200

    async def test_invalid_share_relation(self, client, registered_user, org_and_folder):
        """Sharing with invalid relation should fail."""
        create_resp = await client.post("/documents", json={
            "title": "Bad Share",
            "content": "test",
            "folder_id": org_and_folder["folder_id"],
        }, headers=registered_user["headers"])
        doc_id = create_resp.json()["id"]

        resp = await client.post(f"/documents/{doc_id}/share", json={
            "user_id": "some-user",
            "relation": "admin",  # invalid for documents
        }, headers=registered_user["headers"])
        assert resp.status_code == 400


class TestFolderCRUD:
    """Test folder operations."""

    async def test_create_folder(self, client, registered_user):
        org_resp = await client.post("/organizations", json={
            "name": "Folder Org", "slug": "folder-org",
        }, headers=registered_user["headers"])
        org_id = org_resp.json()["id"]

        resp = await client.post("/documents/folders", json={
            "name": "Engineering Docs",
            "org_id": org_id,
        }, headers=registered_user["headers"])
        assert resp.status_code == 201
        assert resp.json()["name"] == "Engineering Docs"

    async def test_list_folders(self, client, registered_user):
        org_resp = await client.post("/organizations", json={
            "name": "List Folder Org", "slug": "list-folder-org",
        }, headers=registered_user["headers"])
        org_id = org_resp.json()["id"]

        await client.post("/documents/folders", json={"name": "Folder A", "org_id": org_id}, headers=registered_user["headers"])
        await client.post("/documents/folders", json={"name": "Folder B", "org_id": org_id}, headers=registered_user["headers"])

        resp = await client.get(f"/documents/folders?org_id={org_id}", headers=registered_user["headers"])
        assert resp.status_code == 200
        assert len(resp.json()) == 2
