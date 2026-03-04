"""Note model — encrypted content stored at rest.

Related chapters:
  - ch02: AES-256-GCM authenticated encryption
  - ch02: HKDF key derivation
"""

import uuid
from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, LargeBinary, String, Text
from sqlalchemy.orm import relationship

from models.database import Base


class Note(Base):
    __tablename__ = "notes"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    title = Column(String(256), nullable=False)

    # ── Encrypted content (ch02: AES-256-GCM) ───────────
    # The plaintext is encrypted before storage; these fields hold ciphertext + nonce.
    encrypted_content = Column(LargeBinary, nullable=False)
    nonce = Column(LargeBinary(12), nullable=False)  # 96-bit GCM nonce
    tag = Column(LargeBinary(16), nullable=False)     # 128-bit GCM auth tag

    # ── Metadata (stored in plaintext) ──────────────────
    owner_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # ── Relationships ───────────────────────────────────
    owner = relationship("User", back_populates="notes")

    def __repr__(self):
        return f"<Note {self.id[:8]}… title={self.title!r}>"
