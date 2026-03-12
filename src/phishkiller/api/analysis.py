"""Analysis API endpoints."""

import uuid

from fastapi import APIRouter, HTTPException

from phishkiller.api.deps import DbSession, Pagination
from phishkiller.schemas.analysis_result import (
    AnalysisResultDetail,
    AnalysisResultListResponse,
    TaskStatusResponse,
)
from phishkiller.services.analysis_service import AnalysisService

router = APIRouter()


@router.get("/results", response_model=AnalysisResultListResponse)
async def list_results(
    db: DbSession,
    pagination: Pagination,
    kit_id: uuid.UUID | None = None,
    analysis_type: str | None = None,
):
    service = AnalysisService(db)
    results, total = await service.list_results(
        offset=pagination.offset,
        limit=pagination.limit,
        kit_id=kit_id,
        analysis_type=analysis_type,
    )
    return AnalysisResultListResponse(items=results, total=total)


@router.get("/results/{result_id}", response_model=AnalysisResultDetail)
async def get_result(result_id: uuid.UUID, db: DbSession):
    service = AnalysisService(db)
    result = await service.get_result(result_id)
    if not result:
        raise HTTPException(status_code=404, detail="Analysis result not found")
    return result


@router.get("/tasks/{task_id}", response_model=TaskStatusResponse)
async def get_task_status(task_id: str):
    return AnalysisService.get_task_status(task_id)
