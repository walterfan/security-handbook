"""Pydantic schemas for authorization requests and responses."""

from pydantic import BaseModel


class AuthzCheckRequest(BaseModel):
    """Request to check a permission."""
    user: str       # e.g., "user:alice"
    relation: str   # e.g., "can_edit"
    object: str     # e.g., "document:readme"


class AuthzCheckResponse(BaseModel):
    """Response from a permission check."""
    allowed: bool
    user: str
    relation: str
    object: str


class TupleWriteRequest(BaseModel):
    """Request to write a relationship tuple."""
    user: str
    relation: str
    object: str


class ListObjectsRequest(BaseModel):
    """Request to list accessible objects."""
    user: str
    relation: str
    type: str


class ListObjectsResponse(BaseModel):
    """Response with list of accessible objects."""
    objects: list[str]
