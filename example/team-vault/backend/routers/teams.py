"""Team management router.

Demonstrates ch05 (IAM) and ch13 (RBAC):
  - Teams belong to organizations
  - Team lead and member roles
  - Synced to OpenFGA for authorization
"""

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from authz.middleware import require_authenticated
from authz.openfga_client import AuthzTuple, get_fga_client
from models.database import get_db
from models.organization import Team, TeamMembership

router = APIRouter(prefix="/teams", tags=["teams"])


class TeamCreateRequest(BaseModel):
    name: str
    org_id: str


class TeamResponse(BaseModel):
    id: str
    name: str
    org_id: str


class TeamMemberRequest(BaseModel):
    user_id: str
    is_lead: bool = False


class TeamMemberResponse(BaseModel):
    user_id: str
    team_id: str
    is_lead: bool


@router.post("", response_model=TeamResponse, status_code=status.HTTP_201_CREATED)
async def create_team(
    req: TeamCreateRequest,
    user: dict = Depends(require_authenticated),
    db: AsyncSession = Depends(get_db),
):
    """Create a team within an organization."""
    team = Team(name=req.name, org_id=req.org_id)
    db.add(team)
    await db.commit()
    await db.refresh(team)

    # Sync to OpenFGA
    fga = get_fga_client()
    try:
        await fga.write_tuples([
            AuthzTuple(f"organization:{req.org_id}", "org", f"team:{team.id}"),
            AuthzTuple(f"user:{user['id']}", "lead", f"team:{team.id}"),
        ])
    except Exception:
        pass

    return TeamResponse(id=team.id, name=team.name, org_id=team.org_id)


@router.get("", response_model=list[TeamResponse])
async def list_teams(
    org_id: str,
    user: dict = Depends(require_authenticated),
    db: AsyncSession = Depends(get_db),
):
    """List teams in an organization."""
    result = await db.execute(select(Team).where(Team.org_id == org_id))
    teams = result.scalars().all()
    return [TeamResponse(id=t.id, name=t.name, org_id=t.org_id) for t in teams]


@router.post("/{team_id}/members", response_model=TeamMemberResponse, status_code=status.HTTP_201_CREATED)
async def add_team_member(
    team_id: str,
    req: TeamMemberRequest,
    user: dict = Depends(require_authenticated),
    db: AsyncSession = Depends(get_db),
):
    """Add a member to a team."""
    # Check not already a member
    result = await db.execute(
        select(TeamMembership).where(
            TeamMembership.team_id == team_id,
            TeamMembership.user_id == req.user_id,
        )
    )
    if result.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="User is already a team member")

    membership = TeamMembership(
        user_id=req.user_id,
        team_id=team_id,
        is_lead="1" if req.is_lead else "0",
    )
    db.add(membership)
    await db.commit()

    # Sync to OpenFGA
    fga = get_fga_client()
    relation = "lead" if req.is_lead else "member"
    try:
        await fga.write_tuples([
            AuthzTuple(f"user:{req.user_id}", relation, f"team:{team_id}")
        ])
    except Exception:
        pass

    return TeamMemberResponse(user_id=req.user_id, team_id=team_id, is_lead=req.is_lead)


@router.get("/{team_id}/members", response_model=list[TeamMemberResponse])
async def list_team_members(
    team_id: str,
    user: dict = Depends(require_authenticated),
    db: AsyncSession = Depends(get_db),
):
    """List members of a team."""
    result = await db.execute(
        select(TeamMembership).where(TeamMembership.team_id == team_id)
    )
    members = result.scalars().all()
    return [
        TeamMemberResponse(user_id=m.user_id, team_id=m.team_id, is_lead=m.is_lead == "1")
        for m in members
    ]
