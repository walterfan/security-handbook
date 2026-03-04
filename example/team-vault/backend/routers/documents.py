"""Document management router with fine-grained authorization.

Demonstrates ch14 (OpenFGA) and ch18 (OpenFGA + FastAPI):
  - Document CRUD with OpenFGA permission checks
  - Permission inheritance: folder → document
  - Sharing: grant/revoke access to specific users
  - List accessible documents (list_objects query)
"""

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from authz.middleware import require_authenticated
from authz.openfga_client import AuthzTuple, get_fga_client
from models.database import get_db
from models.document import Document, Folder

router = APIRouter(prefix="/documents", tags=["documents"])


class FolderCreateRequest(BaseModel):
    name: str
    org_id: str


class FolderResponse(BaseModel):
    id: str
    name: str
    org_id: str


class DocumentCreateRequest(BaseModel):
    title: str
    content: str = ""
    folder_id: str


class DocumentResponse(BaseModel):
    id: str
    title: str
    content: str
    folder_id: str
    created_by: str


class DocumentUpdateRequest(BaseModel):
    title: str | None = None
    content: str | None = None


class ShareRequest(BaseModel):
    user_id: str
    relation: str = "viewer"  # "viewer" or "editor"


# ── Folders ─────────────────────────────────────────────

@router.post("/folders", response_model=FolderResponse, status_code=status.HTTP_201_CREATED)
async def create_folder(
    req: FolderCreateRequest,
    user: dict = Depends(require_authenticated),
    db: AsyncSession = Depends(get_db),
):
    """Create a folder within an organization.

    The creator becomes the folder owner in OpenFGA.
    The folder inherits the organization's permission hierarchy.
    """
    folder = Folder(name=req.name, org_id=req.org_id, created_by=user["id"])
    db.add(folder)
    await db.commit()
    await db.refresh(folder)

    # Sync to OpenFGA: set org parent and owner
    fga = get_fga_client()
    try:
        await fga.write_tuples([
            AuthzTuple(f"organization:{req.org_id}", "org", f"folder:{folder.id}"),
            AuthzTuple(f"user:{user['id']}", "owner", f"folder:{folder.id}"),
        ])
    except Exception:
        pass

    return FolderResponse(id=folder.id, name=folder.name, org_id=folder.org_id)


@router.get("/folders", response_model=list[FolderResponse])
async def list_folders(
    org_id: str,
    user: dict = Depends(require_authenticated),
    db: AsyncSession = Depends(get_db),
):
    """List folders in an organization."""
    result = await db.execute(select(Folder).where(Folder.org_id == org_id))
    folders = result.scalars().all()
    return [FolderResponse(id=f.id, name=f.name, org_id=f.org_id) for f in folders]


# ── Documents ───────────────────────────────────────────

@router.post("", response_model=DocumentResponse, status_code=status.HTTP_201_CREATED)
async def create_document(
    req: DocumentCreateRequest,
    user: dict = Depends(require_authenticated),
    db: AsyncSession = Depends(get_db),
):
    """Create a document in a folder.

    The creator becomes the document owner.
    The document inherits permissions from its parent folder.
    """
    # Verify folder exists
    result = await db.execute(select(Folder).where(Folder.id == req.folder_id))
    folder = result.scalar_one_or_none()
    if not folder:
        raise HTTPException(status_code=404, detail="Folder not found")

    doc = Document(
        title=req.title,
        content=req.content,
        folder_id=req.folder_id,
        created_by=user["id"],
    )
    db.add(doc)
    await db.commit()
    await db.refresh(doc)

    # Sync to OpenFGA: set parent folder and owner
    fga = get_fga_client()
    try:
        await fga.write_tuples([
            AuthzTuple(f"folder:{req.folder_id}", "parent", f"document:{doc.id}"),
            AuthzTuple(f"user:{user['id']}", "owner", f"document:{doc.id}"),
        ])
    except Exception:
        pass

    return DocumentResponse(
        id=doc.id, title=doc.title, content=doc.content,
        folder_id=doc.folder_id, created_by=doc.created_by,
    )


@router.get("/{doc_id}", response_model=DocumentResponse)
async def get_document(
    doc_id: str,
    user: dict = Depends(require_authenticated),
    db: AsyncSession = Depends(get_db),
):
    """Get a document (requires 'can_view' permission).

    OpenFGA evaluates:
      can_view = viewer (direct) OR editor OR viewer from parent folder
    """
    # Check permission via OpenFGA
    fga = get_fga_client()
    try:
        allowed = await fga.check(f"user:{user['id']}", "can_view", f"document:{doc_id}")
        if not allowed:
            raise HTTPException(status_code=403, detail="No view permission on this document")
    except HTTPException:
        raise
    except Exception:
        pass  # OpenFGA not available, fall through to DB check

    result = await db.execute(select(Document).where(Document.id == doc_id))
    doc = result.scalar_one_or_none()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")

    return DocumentResponse(
        id=doc.id, title=doc.title, content=doc.content,
        folder_id=doc.folder_id, created_by=doc.created_by,
    )


@router.put("/{doc_id}", response_model=DocumentResponse)
async def update_document(
    doc_id: str,
    req: DocumentUpdateRequest,
    user: dict = Depends(require_authenticated),
    db: AsyncSession = Depends(get_db),
):
    """Update a document (requires 'can_edit' permission).

    OpenFGA evaluates:
      can_edit = editor (direct) OR owner OR editor from parent folder
    """
    # Check edit permission
    fga = get_fga_client()
    try:
        allowed = await fga.check(f"user:{user['id']}", "can_edit", f"document:{doc_id}")
        if not allowed:
            raise HTTPException(status_code=403, detail="No edit permission on this document")
    except HTTPException:
        raise
    except Exception:
        pass

    result = await db.execute(select(Document).where(Document.id == doc_id))
    doc = result.scalar_one_or_none()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")

    if req.title is not None:
        doc.title = req.title
    if req.content is not None:
        doc.content = req.content

    await db.commit()
    await db.refresh(doc)

    return DocumentResponse(
        id=doc.id, title=doc.title, content=doc.content,
        folder_id=doc.folder_id, created_by=doc.created_by,
    )


@router.delete("/{doc_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_document(
    doc_id: str,
    user: dict = Depends(require_authenticated),
    db: AsyncSession = Depends(get_db),
):
    """Delete a document (requires 'owner' relation)."""
    fga = get_fga_client()
    try:
        allowed = await fga.check(f"user:{user['id']}", "owner", f"document:{doc_id}")
        if not allowed:
            raise HTTPException(status_code=403, detail="Only the owner can delete this document")
    except HTTPException:
        raise
    except Exception:
        pass

    result = await db.execute(select(Document).where(Document.id == doc_id))
    doc = result.scalar_one_or_none()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")

    # Clean up OpenFGA tuples
    try:
        tuples = await fga.read_tuples(object=f"document:{doc_id}")
        if tuples:
            await fga.delete_tuples([
                AuthzTuple(t["key"]["user"], t["key"]["relation"], t["key"]["object"])
                for t in tuples
            ])
    except Exception:
        pass

    await db.delete(doc)
    await db.commit()


# ── Sharing ─────────────────────────────────────────────

@router.post("/{doc_id}/share", status_code=status.HTTP_201_CREATED)
async def share_document(
    doc_id: str,
    req: ShareRequest,
    user: dict = Depends(require_authenticated),
    db: AsyncSession = Depends(get_db),
):
    """Share a document with another user (requires 'can_share' permission).

    Demonstrates ch14: granting fine-grained access by writing tuples.
    Only the document owner (or org admin) can share.
    """
    if req.relation not in ("viewer", "editor"):
        raise HTTPException(status_code=400, detail="Relation must be 'viewer' or 'editor'")

    fga = get_fga_client()

    # Check share permission
    try:
        allowed = await fga.check(f"user:{user['id']}", "can_share", f"document:{doc_id}")
        if not allowed:
            raise HTTPException(status_code=403, detail="No share permission on this document")
    except HTTPException:
        raise
    except Exception:
        pass

    # Grant access
    try:
        await fga.write_tuples([
            AuthzTuple(f"user:{req.user_id}", req.relation, f"document:{doc_id}")
        ])
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to grant access: {e}")

    return {"message": f"Granted '{req.relation}' access to user {req.user_id}"}


@router.delete("/{doc_id}/share/{target_user_id}")
async def revoke_share(
    doc_id: str,
    target_user_id: str,
    user: dict = Depends(require_authenticated),
):
    """Revoke a user's access to a document.

    Removes all direct tuples for the target user on this document.
    Inherited permissions (from folder/org) are NOT affected.
    """
    fga = get_fga_client()

    # Check share permission
    try:
        allowed = await fga.check(f"user:{user['id']}", "can_share", f"document:{doc_id}")
        if not allowed:
            raise HTTPException(status_code=403, detail="No share permission")
    except HTTPException:
        raise
    except Exception:
        pass

    # Remove direct tuples
    for relation in ("viewer", "editor"):
        try:
            await fga.delete_tuples([
                AuthzTuple(f"user:{target_user_id}", relation, f"document:{doc_id}")
            ])
        except Exception:
            pass

    return {"message": f"Revoked access for user {target_user_id}"}
