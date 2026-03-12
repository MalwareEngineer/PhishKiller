"""Kit API endpoints."""

import uuid

from fastapi import APIRouter, HTTPException, status

from phishkiller.api.deps import DbSession, Pagination
from phishkiller.schemas.kit import (
    KitCreate,
    KitDetail,
    KitListResponse,
    KitSubmitResponse,
    SimilarKit,
)
from phishkiller.services.kit_service import KitService

router = APIRouter()


@router.get("", response_model=KitListResponse)
async def list_kits(
    db: DbSession,
    pagination: Pagination,
    status_filter: str | None = None,
    source_feed: str | None = None,
) -> KitListResponse:
    service = KitService(db)
    kits, total = await service.list_kits(
        offset=pagination.offset,
        limit=pagination.limit,
        status_filter=status_filter,
        source_feed=source_feed,
    )
    return KitListResponse(items=kits, total=total)


@router.post("", response_model=KitSubmitResponse, status_code=status.HTTP_202_ACCEPTED)
async def create_kit(payload: KitCreate, db: DbSession) -> KitSubmitResponse:
    service = KitService(db)
    kit, task_id = await service.submit_kit(
        str(payload.url), payload.source_feed
    )
    return KitSubmitResponse(kit_id=kit.id, task_id=task_id)


@router.get("/{kit_id}", response_model=KitDetail)
async def get_kit(kit_id: uuid.UUID, db: DbSession) -> KitDetail:
    service = KitService(db)
    kit = await service.get_kit(kit_id)
    if not kit:
        raise HTTPException(status_code=404, detail="Kit not found")
    return KitDetail.model_validate(kit)


@router.delete("/{kit_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_kit(kit_id: uuid.UUID, db: DbSession) -> None:
    service = KitService(db)
    deleted = await service.delete_kit(kit_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Kit not found")


@router.get("/{kit_id}/indicators")
async def get_kit_indicators(
    kit_id: uuid.UUID, db: DbSession, pagination: Pagination
):
    from phishkiller.services.indicator_service import IndicatorService

    service = IndicatorService(db)
    indicators, total = await service.list_indicators(
        offset=pagination.offset, limit=pagination.limit, kit_id=kit_id
    )
    return {"items": indicators, "total": total}


@router.get("/{kit_id}/similar", response_model=list[SimilarKit])
async def find_similar_kits(
    kit_id: uuid.UUID,
    db: DbSession,
    threshold: int = 100,
) -> list[SimilarKit]:
    service = KitService(db)
    return await service.find_similar(kit_id, threshold=threshold)


@router.post("/{kit_id}/reanalyze", status_code=status.HTTP_202_ACCEPTED)
async def reanalyze_kit(kit_id: uuid.UUID, db: DbSession):
    service = KitService(db)
    try:
        task_id = await service.reanalyze(kit_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Kit not found")
    return {"kit_id": str(kit_id), "task_id": task_id}
