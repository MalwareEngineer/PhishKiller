"""Pydantic schemas for Investigation API endpoints."""

import uuid
from datetime import datetime

from pydantic import BaseModel, HttpUrl

from phishkiller.schemas.kit import KitSummary


class InvestigationCreate(BaseModel):
    url: HttpUrl | None = None
    max_depth: int = 3


class InvestigationSummary(BaseModel):
    id: uuid.UUID
    name: str | None
    status: str
    max_depth: int
    total_kits: int
    total_depth_reached: int
    created_at: datetime

    model_config = {"from_attributes": True}


class InvestigationDetail(InvestigationSummary):
    root_kit: KitSummary | None = None

    model_config = {"from_attributes": True}


class InvestigationTreeNode(BaseModel):
    kit: KitSummary
    discovery_method: str | None = None
    chain_depth: int = 0
    children: list["InvestigationTreeNode"] = []

    model_config = {"from_attributes": True}


class InvestigationListResponse(BaseModel):
    items: list[InvestigationSummary]
    total: int


class InvestigationSubmitResponse(BaseModel):
    investigation_id: uuid.UUID
    kit_id: uuid.UUID
    task_id: str
    message: str = "Investigation started"
