"""Organization, Team, and Membership models.

Demonstrates ch05 — IAM (Identity and Access Management):
  - Multi-tenant organization hierarchy
  - Role-based membership (owner, admin, member)
  - Team grouping within organizations
"""

import uuid
from datetime import datetime
from enum import Enum

from sqlalchemy import Column, DateTime, Enum as SAEnum, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import relationship

from models.database import Base


class OrgRole(str, Enum):
    """Organization-level roles (ch13: RBAC)."""
    OWNER = "owner"
    ADMIN = "admin"
    MEMBER = "member"


class Organization(Base):
    __tablename__ = "organizations"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(128), unique=True, nullable=False)
    slug = Column(String(64), unique=True, nullable=False, index=True)
    description = Column(String(512), default="")
    created_at = Column(DateTime, default=datetime.utcnow)

    memberships = relationship("OrgMembership", back_populates="organization", cascade="all, delete-orphan")
    teams = relationship("Team", back_populates="organization", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Organization {self.slug}>"


class OrgMembership(Base):
    """User membership in an organization with a specific role."""
    __tablename__ = "org_memberships"
    __table_args__ = (UniqueConstraint("user_id", "org_id"),)

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    org_id = Column(String(36), ForeignKey("organizations.id"), nullable=False)
    role = Column(SAEnum(OrgRole), nullable=False, default=OrgRole.MEMBER)
    joined_at = Column(DateTime, default=datetime.utcnow)

    organization = relationship("Organization", back_populates="memberships")
    user = relationship("User", back_populates="org_memberships")


class Team(Base):
    __tablename__ = "teams"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(128), nullable=False)
    org_id = Column(String(36), ForeignKey("organizations.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    organization = relationship("Organization", back_populates="teams")
    members = relationship("TeamMembership", back_populates="team", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Team {self.name}>"


class TeamMembership(Base):
    __tablename__ = "team_memberships"
    __table_args__ = (UniqueConstraint("user_id", "team_id"),)

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    team_id = Column(String(36), ForeignKey("teams.id"), nullable=False)
    is_lead = Column(String(1), default="0")  # "1" = team lead
    joined_at = Column(DateTime, default=datetime.utcnow)

    team = relationship("Team", back_populates="members")
    user = relationship("User", back_populates="team_memberships")


class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String(64), unique=True, nullable=False, index=True)
    email = Column(String(256), unique=True, nullable=False)
    hashed_password = Column(String(256), nullable=False)
    is_active = Column(String(1), default="1")
    created_at = Column(DateTime, default=datetime.utcnow)

    org_memberships = relationship("OrgMembership", back_populates="user", cascade="all, delete-orphan")
    team_memberships = relationship("TeamMembership", back_populates="user", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<User {self.username}>"
