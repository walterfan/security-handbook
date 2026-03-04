"""OpenFGA client wrapper for fine-grained authorization.

Demonstrates ch14 (OpenFGA) and ch18 (OpenFGA + FastAPI):
  - Relationship-Based Access Control (ReBAC)
  - Tuple management (write, read, delete)
  - Authorization checks (check, list_objects, expand)
  - Store and model initialization

The OpenFGA authorization model is defined in openfga/model.fga.
Relationship tuples are the "facts" that the engine evaluates.

Example tuple: (user:alice, editor, document:readme)
  → "Alice is an editor of the readme document"

Example check: check(user:alice, can_edit, document:readme)
  → True (because editor implies can_edit in the model)
"""

import logging
from dataclasses import dataclass

import httpx

from config import settings

logger = logging.getLogger(__name__)


@dataclass
class AuthzTuple:
    """A relationship tuple: (user, relation, object)."""
    user: str
    relation: str
    object: str


class OpenFGAClient:
    """Async client for OpenFGA REST API.

    Wraps the OpenFGA HTTP API for:
      - Writing relationship tuples
      - Checking authorization
      - Listing accessible objects
      - Expanding relation trees
    """

    def __init__(
        self,
        api_url: str | None = None,
        store_id: str | None = None,
        model_id: str | None = None,
    ):
        self.api_url = (api_url or settings.openfga_api_url).rstrip("/")
        self.store_id = store_id or settings.openfga_store_id
        self.model_id = model_id or settings.openfga_model_id

    @property
    def _base_url(self) -> str:
        return f"{self.api_url}/stores/{self.store_id}"

    # ── Store & Model Management ────────────────────────

    async def create_store(self, name: str) -> dict:
        """Create a new OpenFGA store."""
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self.api_url}/stores",
                json={"name": name},
            )
            resp.raise_for_status()
            data = resp.json()
            self.store_id = data["id"]
            logger.info(f"Created store: {data['id']} ({name})")
            return data

    async def write_model(self, model_json: dict) -> dict:
        """Write an authorization model to the store."""
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self._base_url}/authorization-models",
                json=model_json,
            )
            resp.raise_for_status()
            data = resp.json()
            self.model_id = data["authorization_model_id"]
            logger.info(f"Wrote model: {self.model_id}")
            return data

    # ── Tuple Operations ────────────────────────────────

    async def write_tuples(self, tuples: list[AuthzTuple]) -> None:
        """Write relationship tuples to the store.

        Example:
            await client.write_tuples([
                AuthzTuple("user:alice", "editor", "document:readme"),
                AuthzTuple("user:bob", "viewer", "document:readme"),
            ])
        """
        writes = [
            {
                "user": t.user,
                "relation": t.relation,
                "object": t.object,
            }
            for t in tuples
        ]
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self._base_url}/write",
                json={
                    "writes": {"tuple_keys": writes},
                    "authorization_model_id": self.model_id,
                },
            )
            resp.raise_for_status()
            logger.debug(f"Wrote {len(tuples)} tuples")

    async def delete_tuples(self, tuples: list[AuthzTuple]) -> None:
        """Delete relationship tuples from the store."""
        deletes = [
            {
                "user": t.user,
                "relation": t.relation,
                "object": t.object,
            }
            for t in tuples
        ]
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self._base_url}/write",
                json={
                    "deletes": {"tuple_keys": deletes},
                    "authorization_model_id": self.model_id,
                },
            )
            resp.raise_for_status()

    async def read_tuples(
        self,
        user: str | None = None,
        relation: str | None = None,
        object: str | None = None,
    ) -> list[dict]:
        """Read tuples matching the given filter."""
        body: dict = {}
        tuple_key = {}
        if user:
            tuple_key["user"] = user
        if relation:
            tuple_key["relation"] = relation
        if object:
            tuple_key["object"] = object
        if tuple_key:
            body["tuple_key"] = tuple_key

        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self._base_url}/read",
                json=body,
            )
            resp.raise_for_status()
            return resp.json().get("tuples", [])

    # ── Authorization Checks ────────────────────────────

    async def check(self, user: str, relation: str, object: str) -> bool:
        """Check if a user has a specific relation to an object.

        This is the core authorization query:
            check("user:alice", "can_edit", "document:readme") → True/False

        The engine evaluates the authorization model, following
        inheritance chains and computed relations.
        """
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self._base_url}/check",
                json={
                    "tuple_key": {
                        "user": user,
                        "relation": relation,
                        "object": object,
                    },
                    "authorization_model_id": self.model_id,
                },
            )
            resp.raise_for_status()
            result = resp.json()
            allowed = result.get("allowed", False)
            logger.debug(f"Check ({user}, {relation}, {object}) → {allowed}")
            return allowed

    async def list_objects(
        self,
        user: str,
        relation: str,
        type: str,
    ) -> list[str]:
        """List all objects of a type that a user has a relation to.

        Example:
            list_objects("user:alice", "can_edit", "document")
            → ["document:readme", "document:design-spec"]
        """
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self._base_url}/list-objects",
                json={
                    "user": user,
                    "relation": relation,
                    "type": type,
                    "authorization_model_id": self.model_id,
                },
            )
            resp.raise_for_status()
            return resp.json().get("objects", [])

    async def expand(self, relation: str, object: str) -> dict:
        """Expand a relation to see all users who have it.

        Useful for debugging: "Who can edit document:readme?"
        Returns a tree of users and their paths to the relation.
        """
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self._base_url}/expand",
                json={
                    "tuple_key": {
                        "relation": relation,
                        "object": object,
                    },
                    "authorization_model_id": self.model_id,
                },
            )
            resp.raise_for_status()
            return resp.json()


# ── Singleton ───────────────────────────────────────────

_fga_client: OpenFGAClient | None = None


def get_fga_client() -> OpenFGAClient:
    """Get or create the OpenFGA client singleton."""
    global _fga_client
    if _fga_client is None:
        _fga_client = OpenFGAClient()
    return _fga_client
