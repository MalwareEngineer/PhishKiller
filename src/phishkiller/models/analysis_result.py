"""AnalysisResult model — stores results from each analysis step."""

from __future__ import annotations

import enum
import uuid
from typing import TYPE_CHECKING

from sqlalchemy import Enum, Float, ForeignKey, Integer, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from phishkiller.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from phishkiller.models.kit import Kit


class AnalysisType(str, enum.Enum):
    HASH = "hash"
    IOC_EXTRACTION = "ioc_extraction"
    DEOBFUSCATION = "deobfuscation"
    YARA_SCAN = "yara_scan"
    SIMILARITY = "similarity"


class AnalysisResult(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "analysis_results"

    kit_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("kits.id"), nullable=False, index=True
    )
    analysis_type: Mapped[AnalysisType] = mapped_column(
        Enum(AnalysisType), nullable=False
    )
    result_data: Mapped[dict] = mapped_column(JSONB, nullable=False)
    duration_seconds: Mapped[float | None] = mapped_column(Float)
    files_processed: Mapped[int | None] = mapped_column(Integer)
    error: Mapped[str | None] = mapped_column(Text)

    # Relationships
    kit: Mapped[Kit] = relationship(back_populates="analysis_results")
