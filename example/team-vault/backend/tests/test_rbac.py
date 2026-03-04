"""Tests for RBAC — organization role-based access control (ch13).

Tests:
  - Organization creation (creator becomes owner)
  - Member management (add with roles)
  - Role-based access enforcement
"""

import pytest
import pytest_asyncio

pytestmark = pytest.mark.asyncio


class TestOrganizationCRUD:
    """Test organization lifecycle."""

    async def test_create_organization(self, client, registered_user):
        resp = await client.post("/organizations", json={
            "name": "Acme Corp",
            "slug": "acme",
            "description": "Test organization",
        }, headers=registered_user["headers"])
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "Acme Corp"
        assert data["slug"] == "acme"

    async def test_duplicate_slug_rejected(self, client, registered_user):
        await client.post("/organizations", json={
            "name": "Org 1", "slug": "unique-slug",
        }, headers=registered_user["headers"])

        resp = await client.post("/organizations", json={
            "name": "Org 2", "slug": "unique-slug",
        }, headers=registered_user["headers"])
        assert resp.status_code == 409

    async def test_list_my_organizations(self, client, registered_user):
        await client.post("/organizations", json={
            "name": "Org A", "slug": "org-a",
        }, headers=registered_user["headers"])
        await client.post("/organizations", json={
            "name": "Org B", "slug": "org-b",
        }, headers=registered_user["headers"])

        resp = await client.get("/organizations", headers=registered_user["headers"])
        assert resp.status_code == 200
        assert len(resp.json()) == 2


class TestMemberManagement:
    """Test adding and listing organization members."""

    async def test_add_member(self, client, registered_user, second_user):
        # Create org
        org_resp = await client.post("/organizations", json={
            "name": "Test Org", "slug": "test-org",
        }, headers=registered_user["headers"])
        org_id = org_resp.json()["id"]

        # Add second user as member
        resp = await client.post(f"/organizations/{org_id}/members", json={
            "user_id": second_user["id"],
            "role": "member",
        }, headers=registered_user["headers"])
        assert resp.status_code == 201
        assert resp.json()["role"] == "member"

    async def test_add_duplicate_member_rejected(self, client, registered_user, second_user):
        org_resp = await client.post("/organizations", json={
            "name": "Dup Org", "slug": "dup-org",
        }, headers=registered_user["headers"])
        org_id = org_resp.json()["id"]

        await client.post(f"/organizations/{org_id}/members", json={
            "user_id": second_user["id"], "role": "member",
        }, headers=registered_user["headers"])

        resp = await client.post(f"/organizations/{org_id}/members", json={
            "user_id": second_user["id"], "role": "admin",
        }, headers=registered_user["headers"])
        assert resp.status_code == 409

    async def test_list_members(self, client, registered_user, second_user):
        org_resp = await client.post("/organizations", json={
            "name": "List Org", "slug": "list-org",
        }, headers=registered_user["headers"])
        org_id = org_resp.json()["id"]

        await client.post(f"/organizations/{org_id}/members", json={
            "user_id": second_user["id"], "role": "admin",
        }, headers=registered_user["headers"])

        resp = await client.get(f"/organizations/{org_id}/members", headers=registered_user["headers"])
        assert resp.status_code == 200
        members = resp.json()
        assert len(members) == 2  # owner + admin
        roles = {m["role"] for m in members}
        assert "owner" in roles
        assert "admin" in roles


class TestTeamCRUD:
    """Test team management."""

    async def test_create_team(self, client, registered_user):
        org_resp = await client.post("/organizations", json={
            "name": "Team Org", "slug": "team-org",
        }, headers=registered_user["headers"])
        org_id = org_resp.json()["id"]

        resp = await client.post("/teams", json={
            "name": "Engineering",
            "org_id": org_id,
        }, headers=registered_user["headers"])
        assert resp.status_code == 201
        assert resp.json()["name"] == "Engineering"

    async def test_list_teams(self, client, registered_user):
        org_resp = await client.post("/organizations", json={
            "name": "Teams Org", "slug": "teams-org",
        }, headers=registered_user["headers"])
        org_id = org_resp.json()["id"]

        await client.post("/teams", json={"name": "Frontend", "org_id": org_id}, headers=registered_user["headers"])
        await client.post("/teams", json={"name": "Backend", "org_id": org_id}, headers=registered_user["headers"])

        resp = await client.get(f"/teams?org_id={org_id}", headers=registered_user["headers"])
        assert resp.status_code == 200
        assert len(resp.json()) == 2
