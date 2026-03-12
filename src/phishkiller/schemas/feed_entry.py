"""Pydantic schemas for Feed API endpoints."""

import uuid
from datetime import datetime

from pydantic import BaseModel

from phishkiller.models.feed_entry import FeedSource


class FeedEntrySummary(BaseModel):
    id: uuid.UUID
    source: FeedSource
    url: str
    external_id: str | None
    target_brand: str | None
    is_processed: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class FeedEntryListResponse(BaseModel):
    items: list[FeedEntrySummary]
    total: int


class FeedIngestRequest(BaseModel):
    source: str = "all"


class FeedIngestResponse(BaseModel):
    task_ids: list[str]
    message: str = "Feed ingestion triggered"


class FeedStats(BaseModel):
    source: str
    total: int
    processed: int
    unprocessed: int
