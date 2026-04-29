"""Pydantic schemas for Family API endpoints."""

import uuid
from datetime import datetime

from pydantic import BaseModel


class FamilyCreate(BaseModel):
    name: str
    aliases: list[str] | None = None
    description: str | None = None


class FamilyUpdate(BaseModel):
    name: str | None = None
    aliases: list[str] | None = None
    description: str | None = None


class FamilySummary(BaseModel):
    id: uuid.UUID
    name: str
    aliases: list[str] | None
    created_at: datetime

    model_config = {"from_attributes": True}


class FamilyBrief(BaseModel):
    id: uuid.UUID
    name: str

    model_config = {"from_attributes": True}


class ActorBrief(BaseModel):
    id: uuid.UUID
    name: str

    model_config = {"from_attributes": True}


class FamilyDetail(FamilySummary):
    description: str | None
    actors: list[ActorBrief] = []

    model_config = {"from_attributes": True}


class FamilyListResponse(BaseModel):
    items: list[FamilySummary]
    total: int


class LinkKitsRequest(BaseModel):
    kit_ids: list[uuid.UUID]


class LinkActorsRequest(BaseModel):
    actor_ids: list[uuid.UUID]


# ---------------------------------------------------------------------------
# Stats shapes — drive the rebuilt family-detail Overview tab + chart cards
# ---------------------------------------------------------------------------


class FamilyBrandCount(BaseModel):
    """One row in the target-brand-mix bar chart."""

    brand: str
    count: int


class FamilyActorCount(BaseModel):
    """One row in the top-deploying-actors panel.  Includes
    ``actor_id`` so each row links to the actor detail page."""

    actor_id: uuid.UUID
    actor_name: str
    count: int


class FamilyYaraRuleCount(BaseModel):
    """One row in the YARA-rules-anchoring-this-family table.
    The rule name is whatever string the YARA scan emitted in
    ``result_data["matches"][i]["rule"]``."""

    rule: str
    count: int


class FamilyTimelineBucket(BaseModel):
    """One bar in the activity-over-time chart.  ``month`` is the
    YYYY-MM Postgres ``date_trunc('month', ...)`` value rendered as
    a string."""

    month: str
    count: int


class FamilyIndicatorCount(BaseModel):
    """One row in the top-indicators panel."""

    type: str
    value: str
    count: int


class FamilyStats(BaseModel):
    """Full Overview-tab payload for a family."""

    kit_count: int
    actor_count: int
    campaign_count: int
    indicator_count: int
    # Polymorphism — distinct binaries vs near-duplicate clusters.
    # Reads as: this family has N kits but only M unique SHA256s
    # (repackaging) or only K TLSH clusters (recompiles).
    distinct_sha256_count: int
    distinct_tlsh_count: int
    first_seen_computed: datetime | None
    last_seen_computed: datetime | None
    target_brand_distribution: list[FamilyBrandCount]
    top_actors: list[FamilyActorCount]
    top_yara_rules: list[FamilyYaraRuleCount]
    timeline: list[FamilyTimelineBucket]
    top_indicators: list[FamilyIndicatorCount]
