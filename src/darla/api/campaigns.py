"""Campaign API endpoints."""

import uuid

from fastapi import APIRouter, HTTPException, Query, status

from darla.api.deps import DbSession, Pagination
from darla.schemas.actor import ActorSummary
from darla.schemas.campaign import (
    AddKitsRequest,
    CampaignCreate,
    CampaignDetail,
    CampaignListResponse,
    CampaignStats,
    CampaignUpdate,
    CampaignYaraRuleCount,
)
from darla.schemas.family import FamilySummary
from darla.schemas.indicator import IndicatorListResponse
from darla.schemas.kit import KitListResponse
from darla.schemas.victim import VictimListResponse
from darla.services.campaign_service import CampaignService

router = APIRouter()


@router.get("", response_model=CampaignListResponse)
async def list_campaigns(
    db: DbSession,
    pagination: Pagination,
    target_brand: str | None = None,
    include_auto: bool = False,
):
    """List campaigns.  Auto-generated (synthetic) campaigns are hidden
    unless ``include_auto=true`` is passed."""
    service = CampaignService(db)
    campaigns, total = await service.list_campaigns(
        offset=pagination.offset,
        limit=pagination.limit,
        target_brand=target_brand,
        include_auto=include_auto,
    )
    return CampaignListResponse(items=campaigns, total=total)


@router.post("", response_model=CampaignDetail, status_code=status.HTTP_201_CREATED)
async def create_campaign(payload: CampaignCreate, db: DbSession):
    service = CampaignService(db)
    campaign = await service.create_campaign(payload.model_dump())
    return campaign


@router.get("/{campaign_id}", response_model=CampaignDetail)
async def get_campaign(campaign_id: uuid.UUID, db: DbSession):
    service = CampaignService(db)
    campaign = await service.get_campaign(campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return campaign


@router.put("/{campaign_id}", response_model=CampaignDetail)
async def update_campaign(
    campaign_id: uuid.UUID, payload: CampaignUpdate, db: DbSession
):
    service = CampaignService(db)
    campaign = await service.update_campaign(
        campaign_id, payload.model_dump(exclude_unset=True)
    )
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return campaign


@router.delete("/{campaign_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_campaign(campaign_id: uuid.UUID, db: DbSession):
    service = CampaignService(db)
    deleted = await service.delete_campaign(campaign_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Campaign not found")


@router.post("/{campaign_id}/kits")
async def add_kits_to_campaign(
    campaign_id: uuid.UUID, payload: AddKitsRequest, db: DbSession
):
    service = CampaignService(db)
    try:
        count = await service.add_kits(campaign_id, payload.kit_ids)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Campaign not found") from exc
    return {"added": count}


# ---------------------------------------------------------------------------
# Stats + drill-down endpoints — power the rebuilt detail page tabs.
# ---------------------------------------------------------------------------


@router.get("/{campaign_id}/stats", response_model=CampaignStats)
async def get_campaign_stats(campaign_id: uuid.UUID, db: DbSession):
    """Aggregate Overview-tab payload."""
    service = CampaignService(db)
    stats = await service.get_stats(campaign_id)
    if stats is None:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return stats


@router.get("/{campaign_id}/kits-list", response_model=KitListResponse)
async def list_campaign_kits(
    campaign_id: uuid.UUID,
    db: DbSession,
    pagination: Pagination,
    status: str | None = Query(  # noqa: A002 — matches schema
        default=None, description="Filter by kit status",
    ),
):
    """Paginated kit list for the Kits tab.  Routed at
    ``/kits-list`` rather than ``/kits`` because the latter is the
    POST-link endpoint — same path-disambiguation pattern as
    ``/families/{id}/actors-list``."""
    service = CampaignService(db)
    items, total = await service.list_kits(
        campaign_id,
        offset=pagination.offset,
        limit=pagination.limit,
        status=status,
    )
    return KitListResponse(items=items, total=total)


@router.get("/{campaign_id}/indicators", response_model=IndicatorListResponse)
async def list_campaign_indicators(
    campaign_id: uuid.UUID,
    db: DbSession,
    pagination: Pagination,
):
    """Paginated indicator list for the Indicators tab."""
    service = CampaignService(db)
    items, total = await service.list_indicators(
        campaign_id, offset=pagination.offset, limit=pagination.limit,
    )
    return IndicatorListResponse(items=items, total=total)


@router.get("/{campaign_id}/victims", response_model=VictimListResponse)
async def list_campaign_victims(
    campaign_id: uuid.UUID,
    db: DbSession,
    pagination: Pagination,
):
    """Paginated victim list — distinct victims observed in any kit
    attributed to this campaign (PhishPrint integration)."""
    service = CampaignService(db)
    items, total = await service.list_victims(
        campaign_id, offset=pagination.offset, limit=pagination.limit,
    )
    return VictimListResponse(items=items, total=total)


@router.get("/{campaign_id}/actors", response_model=list[ActorSummary])
async def list_campaign_actors(campaign_id: uuid.UUID, db: DbSession):
    """Actors curated as members of this campaign."""
    service = CampaignService(db)
    return await service.list_actors(campaign_id)


@router.get("/{campaign_id}/families", response_model=list[FamilySummary])
async def list_campaign_families(campaign_id: uuid.UUID, db: DbSession):
    """Families sharing at least one kit with this campaign."""
    service = CampaignService(db)
    return await service.list_families(campaign_id)


@router.get(
    "/{campaign_id}/yara-rules", response_model=list[CampaignYaraRuleCount]
)
async def list_campaign_yara_rules(campaign_id: uuid.UUID, db: DbSession):
    """YARA rules anchoring this campaign — aggregated rule-name hit
    counts across the campaign's kits."""
    service = CampaignService(db)
    return await service.list_yara_rules(campaign_id)
