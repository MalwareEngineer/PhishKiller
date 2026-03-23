"""Investigation model — groups kits from a multi-step phishing chain."""

from __future__ import annotations

import enum
import uuid
from typing import TYPE_CHECKING

from sqlalchemy import Enum, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from phishkiller.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from phishkiller.models.kit import Kit


class InvestigationStatus(enum.StrEnum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"


class Investigation(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "investigations"

    name: Mapped[str | None] = mapped_column(String(256))
    root_kit_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("kits.id", ondelete="CASCADE"), nullable=False, index=True
    )
    status: Mapped[InvestigationStatus] = mapped_column(
        Enum(InvestigationStatus), default=InvestigationStatus.PENDING
    )
    max_depth: Mapped[int] = mapped_column(Integer, default=3)
    total_kits: Mapped[int] = mapped_column(Integer, default=1)
    total_depth_reached: Mapped[int] = mapped_column(Integer, default=0)

    # Relationships
    root_kit: Mapped[Kit] = relationship(foreign_keys=[root_kit_id])
    kits: Mapped[list[Kit]] = relationship(
        back_populates="investigation",
        foreign_keys="Kit.investigation_id",
    )
