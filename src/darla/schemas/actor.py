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
