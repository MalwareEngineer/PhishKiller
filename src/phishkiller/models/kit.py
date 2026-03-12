"""Kit model — represents a downloaded phishing kit archive."""

from __future__ import annotations

import enum
import uuid
from typing import TYPE_CHECKING

from sqlalchemy import BigInteger, Enum, ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from phishkiller.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from phishkiller.models.analysis_result import AnalysisResult
    from phishkiller.models.campaign import Campaign
    from phishkiller.models.feed_entry import FeedEntry
    from phishkiller.models.indicator import Indicator


class KitStatus(str, enum.Enum):
    PENDING = "pending"
    DOWNLOADING = "downloading"
    DOWNLOADED = "downloaded"
    ANALYZING = "analyzing"
    ANALYZED = "analyzed"
    FAILED = "failed"


class Kit(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "kits"

    # Source information
    source_url: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    source_feed: Mapped[str | None] = mapped_column(String(50))
    feed_entry_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("feed_entries.id")
    )

    # File metadata
    filename: Mapped[str | None] = mapped_column(String(512))
    file_size: Mapped[int | None] = mapped_column(BigInteger)
    mime_type: Mapped[str | None] = mapped_column(String(128))

    # Hashes
    sha256: Mapped[str | None] = mapped_column(String(64), unique=True, index=True)
    md5: Mapped[str | None] = mapped_column(String(32))
    sha1: Mapped[str | None] = mapped_column(String(40))
    tlsh: Mapped[str | None] = mapped_column(String(72), index=True)

    # Processing state
    status: Mapped[KitStatus] = mapped_column(
        Enum(KitStatus), default=KitStatus.PENDING, index=True
    )
    error_message: Mapped[str | None] = mapped_column(Text)

    # Storage
    local_path: Mapped[str | None] = mapped_column(Text)

    # Relationships
    indicators: Mapped[list[Indicator]] = relationship(
        back_populates="kit", cascade="all, delete-orphan"
    )
    analysis_results: Mapped[list[AnalysisResult]] = relationship(
        back_populates="kit", cascade="all, delete-orphan"
    )
    feed_entry: Mapped[FeedEntry | None] = relationship(back_populates="kits")
    campaigns: Mapped[list[Campaign]] = relationship(
        secondary="campaign_kits", back_populates="kits"
    )

    __table_args__ = (
        Index("ix_kits_tlsh_status", "tlsh", "status"),
        Index("ix_kits_created_at", "created_at"),
    )
