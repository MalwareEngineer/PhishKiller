"""Indicator model — represents an IOC extracted from a phishing kit."""

from __future__ import annotations

import enum
import uuid
from typing import TYPE_CHECKING

from sqlalchemy import Enum, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from phishkiller.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from phishkiller.models.actor import Actor
    from phishkiller.models.kit import Kit


class IndicatorType(str, enum.Enum):
    EMAIL = "email"
    TELEGRAM_BOT_TOKEN = "telegram_bot_token"
    TELEGRAM_CHAT_ID = "telegram_chat_id"
    C2_URL = "c2_url"
    IP_ADDRESS = "ip_address"
    SMTP_CREDENTIAL = "smtp_credential"
    BASE64_BLOCK = "base64_block"
    DOMAIN = "domain"
    PHONE_NUMBER = "phone_number"
    CRYPTOCURRENCY_WALLET = "crypto_wallet"


class Indicator(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "indicators"

    type: Mapped[IndicatorType] = mapped_column(
        Enum(IndicatorType), nullable=False, index=True
    )
    value: Mapped[str] = mapped_column(Text, nullable=False)
    context: Mapped[str | None] = mapped_column(Text)
    source_file: Mapped[str | None] = mapped_column(Text)
    confidence: Mapped[int] = mapped_column(Integer, default=50)

    # Foreign keys
    kit_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("kits.id"), nullable=False, index=True
    )
    actor_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("actors.id")
    )

    # Relationships
    kit: Mapped[Kit] = relationship(back_populates="indicators")
    actor: Mapped[Actor | None] = relationship(back_populates="indicators")

    __table_args__ = (
        Index("ix_indicators_type_value", "type", "value"),
        Index("ix_indicators_kit_type", "kit_id", "type"),
    )
