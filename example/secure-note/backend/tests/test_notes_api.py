"""Integration tests for Notes CRUD API (encrypted storage).

Tests the full note lifecycle:
  - Create note (encrypted at rest)
  - List notes (decrypted on read)
  - Get single note
  - Update note (re-encrypted)
  - Delete note
  - Access control (user isolation)
"""

import pytest
import pytest_asyncio


pytestmark = pytest.mark.asyncio


class TestCreateNote:
    """Test POST /notes."""

    async def test_create_note(self, client, auth_headers):
        """Creating a note should return the plaintext content."""
        response = await client.post("/notes", json={
            "title": "My Secret Note",
            "content": "This is encrypted at rest!",
        }, headers=auth_headers)
        assert response.status_code == 201
        data = response.json()
        assert data["title"] == "My Secret Note"
        assert data["content"] == "This is encrypted at rest!"
        assert "id" in data
        assert "created_at" in data

    async def test_create_note_unicode(self, client, auth_headers):
        """Unicode content should be handled correctly."""
        response = await client.post("/notes", json={
            "title": "加密笔记",
            "content": "这是一条中文加密笔记 🔐",
        }, headers=auth_headers)
        assert response.status_code == 201
        assert response.json()["content"] == "这是一条中文加密笔记 🔐"

    async def test_create_note_unauthenticated(self, client):
        """Creating a note without auth should return 401."""
        response = await client.post("/notes", json={
            "title": "Test",
            "content": "Test",
        })
        assert response.status_code == 401


class TestListNotes:
    """Test GET /notes."""

    async def test_list_empty(self, client, auth_headers):
        """New user should have no notes."""
        response = await client.get("/notes", headers=auth_headers)
        assert response.status_code == 200
        assert response.json() == []

    async def test_list_after_create(self, client, auth_headers):
        """Notes should appear in list after creation."""
        # Create two notes
        await client.post("/notes", json={"title": "Note 1", "content": "Content 1"}, headers=auth_headers)
        await client.post("/notes", json={"title": "Note 2", "content": "Content 2"}, headers=auth_headers)

        response = await client.get("/notes", headers=auth_headers)
        assert response.status_code == 200
        notes = response.json()
        assert len(notes) == 2
        titles = {n["title"] for n in notes}
        assert titles == {"Note 1", "Note 2"}


class TestGetNote:
    """Test GET /notes/{note_id}."""

    async def test_get_note(self, client, auth_headers):
        """Should return decrypted note content."""
        create_resp = await client.post("/notes", json={
            "title": "Fetch Me",
            "content": "Secret content here",
        }, headers=auth_headers)
        note_id = create_resp.json()["id"]

        response = await client.get(f"/notes/{note_id}", headers=auth_headers)
        assert response.status_code == 200
        assert response.json()["content"] == "Secret content here"

    async def test_get_nonexistent_note(self, client, auth_headers):
        """Non-existent note ID should return 404."""
        response = await client.get("/notes/nonexistent-id", headers=auth_headers)
        assert response.status_code == 404


class TestUpdateNote:
    """Test PUT /notes/{note_id}."""

    async def test_update_content(self, client, auth_headers):
        """Updating content should re-encrypt and return new plaintext."""
        create_resp = await client.post("/notes", json={
            "title": "Original",
            "content": "Original content",
        }, headers=auth_headers)
        note_id = create_resp.json()["id"]

        response = await client.put(f"/notes/{note_id}", json={
            "content": "Updated content",
        }, headers=auth_headers)
        assert response.status_code == 200
        assert response.json()["content"] == "Updated content"
        assert response.json()["title"] == "Original"  # title unchanged

    async def test_update_title_only(self, client, auth_headers):
        """Updating only title should preserve encrypted content."""
        create_resp = await client.post("/notes", json={
            "title": "Old Title",
            "content": "Keep this content",
        }, headers=auth_headers)
        note_id = create_resp.json()["id"]

        response = await client.put(f"/notes/{note_id}", json={
            "title": "New Title",
        }, headers=auth_headers)
        assert response.status_code == 200
        assert response.json()["title"] == "New Title"
        assert response.json()["content"] == "Keep this content"


class TestDeleteNote:
    """Test DELETE /notes/{note_id}."""

    async def test_delete_note(self, client, auth_headers):
        """Deleting a note should return 204 and remove it."""
        create_resp = await client.post("/notes", json={
            "title": "Delete Me",
            "content": "Goodbye",
        }, headers=auth_headers)
        note_id = create_resp.json()["id"]

        # Delete
        response = await client.delete(f"/notes/{note_id}", headers=auth_headers)
        assert response.status_code == 204

        # Verify gone
        response = await client.get(f"/notes/{note_id}", headers=auth_headers)
        assert response.status_code == 404

    async def test_delete_nonexistent(self, client, auth_headers):
        """Deleting non-existent note should return 404."""
        response = await client.delete("/notes/nonexistent-id", headers=auth_headers)
        assert response.status_code == 404


class TestUserIsolation:
    """Test that users cannot access each other's notes."""

    async def test_user_cannot_see_others_notes(self, client, auth_headers):
        """User A's notes should not be visible to User B."""
        # User A creates a note
        await client.post("/notes", json={
            "title": "User A's Secret",
            "content": "Private!",
        }, headers=auth_headers)

        # Register and login as User B
        await client.post("/auth/register", json={
            "username": "userb",
            "email": "b@example.com",
            "password": "UserBP@ss1",
        })
        login_resp = await client.post("/auth/login", json={
            "username": "userb",
            "password": "UserBP@ss1",
        })
        b_headers = {"Authorization": f"Bearer {login_resp.json()['access_token']}"}

        # User B should see empty list
        response = await client.get("/notes", headers=b_headers)
        assert response.status_code == 200
        assert response.json() == []
