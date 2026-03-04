"""Organization management router.

Demonstrates ch05 (IAM) and ch13 (RBAC):
  - Create / list / get organizations
  - Manage memberships with roles (owner, admin, member)
  - Sync roles to OpenFGA tuples for fine-grained authorization
"""

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from authz.middleware import require_authenticated, check_resource_permission
from authz.openfga_client import AuthzTuple, get_fga_client
from models.database import get_db
from models.organization import Organization, OrgMembership, OrgRole

router = APIRouter(prefix="/organizations", tags=["organizations"])


class OrgCreateRequest(BaseModel):
    name: str
    slug: str
    description: str = ""


class OrgResponse(BaseModel):
    id: str
    name: str
    slug: str
    description: str


class MemberAddRequest(BaseModel):
    user_id: str
    role: OrgRole = OrgRole.MEMBER


class MemberResponse(BaseModel):
    user_id: str
    role: str
    org_id: str


@router.post("", response_model=OrgResponse, status_code=status.HTTP_201_CREATED)
async def create_organization(
    req: OrgCreateRequest,
    user: dict = Depends(require_authenticated),
    db: AsyncSession = Depends(get_db),
):
    """Create a new organization. The creator becomes the owner."""
    # Check slug uniqueness
    result = await db.execute(select(Organization).where(Organization.slug == req.slug))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Organization slug already exists")

    org = Organization(name=req.name, slug=req.slug, description=req.description)
    db.add(org)
    await db.flush()

    # Creator is the owner
    membership = OrgMembership(user_id=user["id"], org_id=org.id, role=OrgRole.OWNER)
    db.add(membership)
    await db.commit()
    await db.refresh(org)

    # Sync to OpenFGA: user is owner of organization
    fga = get_fga_client()
    try:
        await fga.write_tuples([
            AuthzTuple(f"user:{user['id']}", "owner", f"organization:{org.id}")
        ])
    except Exception as e:
        # Log but don't fail — OpenFGA might not be running in tests
        import logging
        logging.getLogger(__name__).warning(f"OpenFGA sync failed: {e}")

    return OrgResponse(id=org.id, name=org.name, slug=org.slug, description=org.description)


@router.get("", response_model=list[OrgResponse])
async def list_organizations(
    user: dict = Depends(require_authenticated),
    db: AsyncSession = Depends(get_db),
):
    """List organizations the current user belongs to."""
    result = await db.execute(
        select(Organization)
        .join(OrgMembership, OrgMembership.org_id == Organization.id)
        .where(OrgMembership.user_id == user["id"])
    )
    orgs = result.scalars().all()
    return [OrgResponse(id=o.id, name=o.name, slug=o.slug, description=o.description) for o in orgs]


@router.get("/{org_id}", response_model=OrgResponse)
async def get_organization(
    org_id: str,
    user: dict = Depends(require_authenticated),
    db: AsyncSession = Depends(get_db),
):
    """Get organization details."""
    result = await db.execute(select(Organization).where(Organization.id == org_id))
    org = result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    return OrgResponse(id=org.id, name=org.name, slug=org.slug, description=org.description)


@router.post("/{org_id}/members", response_model=MemberResponse, status_code=status.HTTP_201_CREATED)
async def add_member(
    org_id: str,
    req: MemberAddRequest,
    user: dict = Depends(require_authenticated),
    db: AsyncSession = Depends(get_db),
):
    """Add a member to the organization (requires admin+ role).

    Syncs the membership to OpenFGA for fine-grained authorization.
    """
    # Check caller has admin permission via OpenFGA
    fga = get_fga_client()
    try:
        allowed = await fga.check(f"user:{user['id']}", "admin", f"organization:{org_id}")
        if not allowed:
            raise HTTPException(status_code=403, detail="Admin permission required")
    except HTTPException:
        raise
    except Exception:
        # Fallback: check DB role
        result = await db.execute(
            select(OrgMembership).where(
                OrgMembership.org_id == org_id,
                OrgMembership.user_id == user["id"],
                OrgMembership.role.in_([OrgRole.OWNER, OrgRole.ADMIN]),
            )
        )
        if not result.scalar_one_or_none():
            raise HTTPException(status_code=403, detail="Admin permission required")

    # Check not already a member
    result = await db.execute(
        select(OrgMembership).where(
            OrgMembership.org_id == org_id,
            OrgMembership.user_id == req.user_id,
        )
    )
    if result.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="User is already a member")

    membership = OrgMembership(user_id=req.user_id, org_id=org_id, role=req.role)
    db.add(membership)
    await db.commit()

    # Sync to OpenFGA
    try:
        await fga.write_tuples([
            AuthzTuple(f"user:{req.user_id}", req.role.value, f"organization:{org_id}")
        ])
    except Exception as e:
        import logging
        logging.getLogger(__name__).warning(f"OpenFGA sync failed: {e}")

    return MemberResponse(user_id=req.user_id, role=req.role.value, org_id=org_id)


@router.get("/{org_id}/members", response_model=list[MemberResponse])
async def list_members(
    org_id: str,
    user: dict = Depends(require_authenticated),
    db: AsyncSession = Depends(get_db),
):
    """List all members of an organization."""
    result = await db.execute(
        select(OrgMembership).where(OrgMembership.org_id == org_id)
    )
    members = result.scalars().all()
    return [MemberResponse(user_id=m.user_id, role=m.role.value, org_id=m.org_id) for m in members]
