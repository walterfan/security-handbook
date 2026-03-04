"""Document and Folder models.

Demonstrates ch14 — OpenFGA:
  - Folder/Document hierarchy for permission inheritance
  - Documents belong to folders, folders belong to organizations
  - Fine-grained permissions managed via OpenFGA tuples
"""

import uuid
from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import relationship

from models.database import Base


class Folder(Base):
    __tablename__ = "folders"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(256), nullable=False)
    org_id = Column(String(36), ForeignKey("organizations.id"), nullable=False)
    created_by = Column(String(36), ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    documents = relationship("Document", back_populates="folder", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Folder {self.name}>"


class Document(Base):
    __tablename__ = "documents"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    title = Column(String(256), nullable=False)
    content = Column(Text, default="")
    folder_id = Column(String(36), ForeignKey("folders.id"), nullable=False)
    created_by = Column(String(36), ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    folder = relationship("Folder", back_populates="documents")

    def __repr__(self):
        return f"<Document {self.title}>"
