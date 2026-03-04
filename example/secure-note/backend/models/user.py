"""User model — stores credentials, MFA secrets, and OAuth2 links.

Related chapters:
  - ch02: Argon2 password hashing
  - ch09: JWT refresh token tracking
  - ch10: TOTP secret & recovery codes
"""

import uuid
from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, String, Text
from sqlalchemy.orm import relationship

from models.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String(64), unique=True, nullable=False, index=True)
    email = Column(String(256), unique=True, nullable=False, index=True)
    full_name = Column(String(128), default="")

    # ── Password (ch02: Argon2id) ────────────────────────
    hashed_password = Column(String(256), nullable=True)  # nullable for OAuth-only users

    # ── MFA / TOTP (ch10) ────────────────────────────────
    totp_secret = Column(String(64), nullable=True)       # base32-encoded secret
    totp_enabled = Column(Boolean, default=False)
    recovery_codes = Column(Text, nullable=True)           # JSON list of hashed codes

    # ── OAuth2 / OIDC (ch07, ch08) ──────────────────────
    oauth_provider = Column(String(32), nullable=True)     # "google" | "github" | null
    oauth_sub = Column(String(256), nullable=True)         # subject claim from IdP

    # ── Account state ───────────────────────────────────
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # ── Relationships ───────────────────────────────────
    notes = relationship("Note", back_populates="owner", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<User {self.username}>"


class RevokedToken(Base):
    """JWT blacklist — stores revoked token JTI values (ch09: token revocation)."""
    __tablename__ = "revoked_tokens"

    jti = Column(String(36), primary_key=True)
    revoked_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)  # for cleanup
