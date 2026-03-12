"""Many-to-many association tables."""

from sqlalchemy import Column, ForeignKey, Table
from sqlalchemy.dialects.postgresql import UUID

from phishkiller.models.base import Base

campaign_kits = Table(
    "campaign_kits",
    Base.metadata,
    Column(
        "campaign_id",
        UUID(as_uuid=True),
        ForeignKey("campaigns.id"),
        primary_key=True,
    ),
    Column(
        "kit_id",
        UUID(as_uuid=True),
        ForeignKey("kits.id"),
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
