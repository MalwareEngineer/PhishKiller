"""Pydantic schemas for Campaign API endpoints."""

import uuid
from datetime import datetime

from pydantic import BaseModel

from darla.schemas.kit import KitSummary


class CampaignCreate(BaseModel):
    name: str
    description: str | None = None
    target_brand: str | None = None
    start_date: str | None = None
    end_date: str | None = None


class CampaignUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    target_brand: str | None = None
    start_date: str | None = None
    end_date: str | None = None


class CampaignSummary(BaseModel):
    id: uuid.UUID
    name: str
    target_brand: str | None
    start_date: str | None
    end_date: str | None
    auto_generated: bool = False
    created_at: datetime

    model_config = {"from_attributes": True}


class ActorBrief(BaseModel):
    id: uuid.UUID
    name: str

    model_config = {"from_attributes": True}


class CampaignDetail(CampaignSummary):
    description: str | None
    kits: list[KitSummary] = []
    actors: list[ActorBrief] = []

    model_config = {"from_attributes": True}


class CampaignListResponse(BaseModel):
    items: list[CampaignSummary]
    total: int


class AddKitsRequest(BaseModel):
    kit_ids: list[uuid.UUID]


# ---------------------------------------------------------------------------
# Stats shapes — drive the rebuilt campaign-detail Overview tab.
# ---------------------------------------------------------------------------


class CampaignActorCount(BaseModel):
    actor_id: uuid.UUID
    actor_name: str
    count: int


class CampaignFamilyCount(BaseModel):
    family_id: uuid.UUID
    family_name: str
    count: int


class CampaignVictimCount(BaseModel):
    """One row in the top-victims panel.  Includes ``email`` (for
    sorting/grouping by domain) and the operator-set ``display_name``
    (rendered as label when present)."""

    victim_id: uuid.UUID
    email: str
    display_name: str | None
    type: str  # VictimType string
    count: int


class CampaignYaraRuleCount(BaseModel):
    rule: str
    count: int


class CampaignTimelineBucket(BaseModel):
    month: str
    count: int


class CampaignIndicatorCount(BaseModel):
    type: str
    value: str
    count: int


class CampaignVictimSourceBreakdown(BaseModel):
    """Aggregate observation count per source channel (OAuth state,
    EML To, AITM URL fragment, …) for the campaign's victims.
    Drives the 'how is this campaign hitting victims' card."""

    source: str  # VictimObservationSource string
    count: int


class CampaignStats(BaseModel):
    """Full Overview-tab payload for a campaign."""

    kit_count: int
    actor_count: int
    family_count: int
    indicator_count: int
    # PhishPrint integration headline.  Distinct victims observed
    # across any kit attributed to this campaign.
    victim_count: int
    first_seen_computed: datetime | None
    last_seen_computed: datetime | None
    top_actors: list[CampaignActorCount]
    top_families: list[CampaignFamilyCount]
    top_victims: list[CampaignVictimCount]
    top_yara_rules: list[CampaignYaraRuleCount]
    timeline: list[CampaignTimelineBucket]
    top_indicators: list[CampaignIndicatorCount]
    victim_source_breakdown: list[CampaignVictimSourceBreakdown]
