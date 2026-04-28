"""Pydantic schemas for Actor API endpoints."""

import uuid
from datetime import datetime

from pydantic import BaseModel


class ActorCreate(BaseModel):
    name: str
    aliases: list[str] | None = None
    description: str | None = None
    email_addresses: list[str] | None = None
    telegram_handles: list[str] | None = None


class ActorUpdate(BaseModel):
    name: str | None = None
    aliases: list[str] | None = None
    description: str | None = None
    first_seen: str | None = None
    last_seen: str | None = None
    email_addresses: list[str] | None = None
    telegram_handles: list[str] | None = None


class ActorSummary(BaseModel):
    id: uuid.UUID
    name: str
    aliases: list[str] | None
    first_seen: str | None
    last_seen: str | None
    auto_generated: bool = False
    created_at: datetime

    model_config = {"from_attributes": True}


class ActorDetail(ActorSummary):
    description: str | None
    email_addresses: list[str] | None
    telegram_handles: list[str] | None

    model_config = {"from_attributes": True}


class ActorListResponse(BaseModel):
    items: list[ActorSummary]
    total: int


class LinkIndicatorsRequest(BaseModel):
    indicator_ids: list[uuid.UUID]


# ---------------------------------------------------------------------------
# Stats shapes — drive the rebuilt actor-detail Overview tab + chart cards
# ---------------------------------------------------------------------------

class ActorBrandCount(BaseModel):
    """One row in the target-brand-mix bar chart."""

    brand: str
    count: int


class ActorFamilyCount(BaseModel):
    """One row in the kit-families-deployed bar chart.  Includes
    ``family_id`` so each row can link to the family detail page."""

    family_id: uuid.UUID
    family_name: str
    count: int


class ActorTimelineBucket(BaseModel):
    """One bar in the activity-over-time chart.  ``month`` is the
    YYYY-MM Postgres ``date_trunc('month', ...)`` value rendered as
    a string so the frontend doesn't have to fight Date parsing."""

    month: str
    count: int


class ActorIndicatorCount(BaseModel):
    """One row in the top-indicators panel.  Pre-aggregated by the
    backend (group by type+value) so the frontend just renders."""

    type: str
    value: str
    count: int


class ActorStats(BaseModel):
    """Full Overview-tab payload.  Single endpoint to keep round-trip
    count down on page load."""

    kit_count: int
    campaign_count: int
    family_count: int
    indicator_count: int
    # Computed first/last seen — derived from min/max kit timestamps
    # rather than the operator-edited string fields on the Actor row.
    first_seen_computed: datetime | None
    last_seen_computed: datetime | None
    target_brand_distribution: list[ActorBrandCount]
    family_distribution: list[ActorFamilyCount]
    timeline: list[ActorTimelineBucket]
    top_indicators: list[ActorIndicatorCount]
