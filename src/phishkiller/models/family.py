"""Family model — represents a phishing kit family (e.g. Tycoon2FA, Sneaky2FA)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import String, Text
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import Mapped, mapped_column, relationship

from phishkiller.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from phishkiller.models.actor import Actor
    from phishkiller.models.kit import Kit


class Family(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "families"

    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    aliases: Mapped[list[str] | None] = mapped_column(ARRAY(String))
    description: Mapped[str | None] = mapped_column(Text)

    # Relationships
    kits: Mapped[list[Kit]] = relationship(
        secondary="family_kits", back_populates="families"
    )
    actors: Mapped[list[Actor]] = relationship(
        secondary="family_actors", back_populates="families"
    )
