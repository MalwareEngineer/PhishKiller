"""Indicator API endpoints."""

import uuid

from fastapi import APIRouter, HTTPException

from phishkiller.api.deps import DbSession, Pagination
from phishkiller.schemas.indicator import (
    IndicatorDetail,
    IndicatorListResponse,
    IndicatorStats,
)
from phishkiller.services.indicator_service import IndicatorService

router = APIRouter()


@router.get("", response_model=IndicatorListResponse)
async def list_indicators(
    db: DbSession,
    pagination: Pagination,
    type_filter: str | None = None,
):
    service = IndicatorService(db)
    indicators, total = await service.list_indicators(
        offset=pagination.offset,
        limit=pagination.limit,
        type_filter=type_filter,
    )
    return IndicatorListResponse(items=indicators, total=total)


@router.get("/search", response_model=IndicatorListResponse)
async def search_indicators(
    q: str,
    db: DbSession,
    pagination: Pagination,
    type_filter: str | None = None,
):
    service = IndicatorService(db)
    indicators, total = await service.search_indicators(
        query_str=q,
        type_filter=type_filter,
        offset=pagination.offset,
        limit=pagination.limit,
    )
    return IndicatorListResponse(items=indicators, total=total)


@router.get("/stats", response_model=list[IndicatorStats])
async def indicator_stats(db: DbSession):
    service = IndicatorService(db)
    return await service.get_stats()


@router.get("/{indicator_id}", response_model=IndicatorDetail)
async def get_indicator(indicator_id: uuid.UUID, db: DbSession):
    service = IndicatorService(db)
    indicator = await service.get_indicator(indicator_id)
    if not indicator:
        raise HTTPException(status_code=404, detail="Indicator not found")
    return indicator
