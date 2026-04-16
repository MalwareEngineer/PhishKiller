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
