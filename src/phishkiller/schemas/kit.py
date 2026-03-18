"""Pydantic schemas for Kit API endpoints."""

import uuid
from datetime import datetime

from pydantic import BaseModel, HttpUrl

from phishkiller.models.kit import KitStatus


class KitCreate(BaseModel):
    url: HttpUrl
    source_feed: str | None = None


class KitSummary(BaseModel):
    id: uuid.UUID
    source_url: str
    sha256: str | None
    tlsh: str | None
    status: KitStatus
    file_size: int | None
    source_feed: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


class IndicatorBrief(BaseModel):
    id: uuid.UUID
    type: str
    value: str
    confidence: int

    model_config = {"from_attributes": True}


class AnalysisResultBrief(BaseModel):
    id: uuid.UUID
    analysis_type: str
    duration_seconds: float | None
    files_processed: int | None
    created_at: datetime

    model_config = {"from_attributes": True}


class CampaignBrief(BaseModel):
    id: uuid.UUID
    name: str
    target_brand: str | None = None

    model_config = {"from_attributes": True}


class KitDetail(KitSummary):
    md5: str | None
    sha1: str | None
    filename: str | None
    mime_type: str | None
    error_message: str | None
    parent_kit_id: uuid.UUID | None = None
    investigation_id: uuid.UUID | None = None
    chain_depth: int = 0
    discovery_method: str | None = None
    indicators: list[IndicatorBrief] = []
    analysis_results: list[AnalysisResultBrief] = []
    campaigns: list[CampaignBrief] = []
    child_kits: list[KitSummary] = []

    model_config = {"from_attributes": True}


class KitListResponse(BaseModel):
    items: list[KitSummary]
    total: int


class KitSubmitResponse(BaseModel):
    kit_id: uuid.UUID
    task_id: str
    duplicate: bool = False
    message: str = "Kit submitted for analysis"


class KitBulkCreate(BaseModel):
    urls: list[HttpUrl]
    source_feed: str | None = None


class KitBulkResult(BaseModel):
    url: str
    kit_id: uuid.UUID
    task_id: str | None = None
    duplicate: bool = False


class KitBulkResponse(BaseModel):
    submitted: int
    skipped_duplicate: int
    results: list[KitBulkResult]


class KitBulkUploadResult(BaseModel):
    filename: str
    kit_id: uuid.UUID
    task_id: str | None = None
    investigation_id: uuid.UUID | None = None


class KitBulkUploadResponse(BaseModel):
    submitted: int
    results: list[KitBulkUploadResult]


class SimilarKit(BaseModel):
    id: uuid.UUID
    sha256: str | None
    tlsh: str | None
    source_url: str
    distance: int
