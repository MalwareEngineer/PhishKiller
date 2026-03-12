"""Actor model — represents a threat actor associated with phishing kits."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import String, Text
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import Mapped, mapped_column, relationship

from phishkiller.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from phishkiller.models.campaign import Campaign
    from phishkiller.models.indicator import Indicator


class Actor(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "actors"

    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    aliases: Mapped[list[str] | None] = mapped_column(ARRAY(String))
    description: Mapped[str | None] = mapped_column(Text)
    first_seen: Mapped[str | None] = mapped_column(String(32))
    last_seen: Mapped[str | None] = mapped_column(String(32))

    # Attribution
    email_addresses: Mapped[list[str] | None] = mapped_column(ARRAY(String))
    telegram_handles: Mapped[list[str] | None] = mapped_column(ARRAY(String))

    # Relationships
    indicators: Mapped[list[Indicator]] = relationship(back_populates="actor")
    campaigns: Mapped[list[Campaign]] = relationship(
        secondary="campaign_actors", back_populates="actors"
    )
