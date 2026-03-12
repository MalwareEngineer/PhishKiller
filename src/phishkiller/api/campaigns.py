"""Campaign API endpoints."""

import uuid

from fastapi import APIRouter, HTTPException, status

from phishkiller.api.deps import DbSession, Pagination
from phishkiller.schemas.campaign import (
    AddKitsRequest,
    CampaignCreate,
    CampaignDetail,
    CampaignListResponse,
    CampaignUpdate,
)
from phishkiller.services.campaign_service import CampaignService

router = APIRouter()


@router.get("", response_model=CampaignListResponse)
async def list_campaigns(
    db: DbSession, pagination: Pagination, target_brand: str | None = None
):
    service = CampaignService(db)
    campaigns, total = await service.list_campaigns(
        offset=pagination.offset,
        limit=pagination.limit,
        target_brand=target_brand,
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


@router.post("/{campaign_id}/kits")
async def add_kits_to_campaign(
    campaign_id: uuid.UUID, payload: AddKitsRequest, db: DbSession
):
    service = CampaignService(db)
    try:
        count = await service.add_kits(campaign_id, payload.kit_ids)
    except ValueError:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return {"added": count}
