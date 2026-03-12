"""Campaign model — represents a phishing campaign linking kits and actors."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from phishkiller.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from phishkiller.models.actor import Actor
    from phishkiller.models.kit import Kit


class Campaign(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "campaigns"

    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    description: Mapped[str | None] = mapped_column(Text)
    target_brand: Mapped[str | None] = mapped_column(String(255), index=True)
    start_date: Mapped[str | None] = mapped_column(String(32))
    end_date: Mapped[str | None] = mapped_column(String(32))

    # Relationships
    kits: Mapped[list[Kit]] = relationship(
        secondary="campaign_kits", back_populates="campaigns"
    )
    actors: Mapped[list[Actor]] = relationship(
        secondary="campaign_actors", back_populates="campaigns"
    )
