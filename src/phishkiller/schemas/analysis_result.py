"""Pydantic schemas for Analysis API endpoints."""

import uuid
from datetime import datetime

from pydantic import BaseModel

from phishkiller.models.analysis_result import AnalysisType


class AnalysisResultSummary(BaseModel):
    id: uuid.UUID
    kit_id: uuid.UUID
    analysis_type: AnalysisType
    duration_seconds: float | None
    files_processed: int | None
    error: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


class AnalysisResultDetail(AnalysisResultSummary):
    result_data: dict

    model_config = {"from_attributes": True}


class AnalysisResultListResponse(BaseModel):
    items: list[AnalysisResultSummary]
    total: int


class TaskStatusResponse(BaseModel):
    task_id: str
    status: str
    result: dict | None = None
