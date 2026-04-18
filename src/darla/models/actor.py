"""Actor model — represents a threat actor associated with phishing kits."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import Boolean, String, Text
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import Mapped, mapped_column, relationship

from darla.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from darla.models.campaign import Campaign
    from darla.models.family import Family
    from darla.models.indicator import Indicator
    from darla.models.kit import Kit


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

    # True for synthetic entities minted by the legacy ``correlate_kit_actors``
    # task (names like ``ACTOR-XXXX``).  PhishMatch filters these out of
    # default analyst views — they live on only so we don't orphan historical
    # indicator/kit links.
    auto_generated: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default="false", nullable=False
    )

    # Relationships
    indicators: Mapped[list[Indicator]] = relationship(back_populates="actor")
    campaigns: Mapped[list[Campaign]] = relationship(
        secondary="campaign_actors", back_populates="actors"
    )
    kits: Mapped[list[Kit]] = relationship(
        secondary="kit_actors", back_populates="actors"
    )
    families: Mapped[list[Family]] = relationship(
        secondary="family_actors", back_populates="actors"
    )
