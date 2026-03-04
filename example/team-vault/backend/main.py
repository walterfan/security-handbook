"""TeamVault — Main FastAPI application.

A team permission management platform demonstrating:
  - RBAC → ReBAC evolution (ch13, ch14)
  - Dual-layer authorization: OPA (API) + OpenFGA (resource) (ch15, ch17)
  - PEP/PDP/PIP/PAP separation (ch17)
  - Policy as Code (ch16)
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from models.database import init_db
from routers import auth, organizations, teams, documents


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield


app = FastAPI(
    title="TeamVault API",
    description="Team permission management — RBAC + ReBAC with OpenFGA & OPA",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routers ─────────────────────────────────────────────

app.include_router(auth.router)
app.include_router(organizations.router)
app.include_router(teams.router)
app.include_router(documents.router)


# ── Health Check ────────────────────────────────────────

@app.get("/health")
async def health():
    return {"status": "ok", "service": "TeamVault"}


# ── Authorization Debug Endpoints ───────────────────────

@app.get("/debug/authz/check")
async def debug_authz_check(user: str, relation: str, object: str):
    """Debug endpoint: check a permission via OpenFGA.

    Example: /debug/authz/check?user=user:alice&relation=can_edit&object=document:readme
    """
    from authz.openfga_client import get_fga_client
    fga = get_fga_client()
    try:
        allowed = await fga.check(user, relation, object)
        return {"user": user, "relation": relation, "object": object, "allowed": allowed}
    except Exception as e:
        return {"error": str(e)}


@app.get("/debug/authz/list-objects")
async def debug_list_objects(user: str, relation: str, type: str):
    """Debug endpoint: list objects a user can access.

    Example: /debug/authz/list-objects?user=user:alice&relation=can_edit&type=document
    """
    from authz.openfga_client import get_fga_client
    fga = get_fga_client()
    try:
        objects = await fga.list_objects(user, relation, type)
        return {"user": user, "relation": relation, "type": type, "objects": objects}
    except Exception as e:
        return {"error": str(e)}
