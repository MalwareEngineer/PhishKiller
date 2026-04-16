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
