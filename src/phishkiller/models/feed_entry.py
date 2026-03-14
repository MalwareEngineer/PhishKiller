"""FeedEntry model — represents a raw entry from a threat intelligence feed."""

from __future__ import annotations

import enum
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, Enum, Index, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from phishkiller.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from phishkiller.models.kit import Kit


class FeedSource(str, enum.Enum):
    PHISHTANK = "phishtank"
    URLHAUS = "urlhaus"
    OPENPHISH = "openphish"
    PHISHSTATS = "phishstats"
    PHISHING_DATABASE = "phishing_database"
    CERTSTREAM = "certstream"
    MANUAL = "manual"


class FeedEntry(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "feed_entries"

    source: Mapped[FeedSource] = mapped_column(
        Enum(FeedSource), nullable=False, index=True
    )
    url: Mapped[str] = mapped_column(Text, nullable=False)
    external_id: Mapped[str | None] = mapped_column(String(255))
    raw_data: Mapped[dict | None] = mapped_column(JSONB)
    target_brand: Mapped[str | None] = mapped_column(String(255))
    is_processed: Mapped[bool] = mapped_column(Boolean, default=False, index=True)

    # Relationships
    kits: Mapped[list[Kit]] = relationship(back_populates="feed_entry")

    __table_args__ = (
        Index(
            "ix_feed_entries_source_external_id",
            "source",
            "external_id",
            unique=True,
        ),
        Index("ix_feed_entries_url", "url"),
    )
