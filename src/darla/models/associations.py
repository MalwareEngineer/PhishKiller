"""Many-to-many association tables."""

from sqlalchemy import Column, ForeignKey, Table
from sqlalchemy.dialects.postgresql import UUID

from darla.models.base import Base

campaign_kits = Table(
    "campaign_kits",
    Base.metadata,
    Column(
        "campaign_id",
        UUID(as_uuid=True),
        ForeignKey("campaigns.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "kit_id",
        UUID(as_uuid=True),
        ForeignKey("kits.id", ondelete="CASCADE"),
        primary_key=True,
    ),
)

campaign_actors = Table(
    "campaign_actors",
    Base.metadata,
    Column(
        "campaign_id",
        UUID(as_uuid=True),
        ForeignKey("campaigns.id"),
        primary_key=True,
    ),
    Column(
        "actor_id",
        UUID(as_uuid=True),
        ForeignKey("actors.id"),
        primary_key=True,
    ),
)

family_kits = Table(
    "family_kits",
    Base.metadata,
    Column(
        "family_id",
        UUID(as_uuid=True),
        ForeignKey("families.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "kit_id",
        UUID(as_uuid=True),
        ForeignKey("kits.id", ondelete="CASCADE"),
        primary_key=True,
    ),
)

family_actors = Table(
    "family_actors",
    Base.metadata,
    Column(
        "family_id",
        UUID(as_uuid=True),
        ForeignKey("families.id"),
        primary_key=True,
    ),
    Column(
        "actor_id",
        UUID(as_uuid=True),
        ForeignKey("actors.id"),
        primary_key=True,
    ),
)

kit_actors = Table(
    "kit_actors",
    Base.metadata,
    Column(
        "kit_id",
        UUID(as_uuid=True),
        ForeignKey("kits.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "actor_id",
        UUID(as_uuid=True),
        ForeignKey("actors.id", ondelete="CASCADE"),
        primary_key=True,
    ),
)
