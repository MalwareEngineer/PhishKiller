"""Feed API endpoints."""

from fastapi import APIRouter

from phishkiller.api.deps import DbSession, Pagination
from phishkiller.schemas.feed_entry import (
    FeedEntryListResponse,
    FeedIngestRequest,
    FeedIngestResponse,
    FeedStats,
)
from phishkiller.services.feed_service import FeedService

router = APIRouter()


@router.get("/entries", response_model=FeedEntryListResponse)
async def list_feed_entries(
    db: DbSession,
    pagination: Pagination,
    source: str | None = None,
    processed: bool | None = None,
):
    service = FeedService(db)
    entries, total = await service.list_entries(
        offset=pagination.offset,
        limit=pagination.limit,
        source=source,
        processed=processed,
    )
    return FeedEntryListResponse(items=entries, total=total)


@router.post("/ingest", response_model=FeedIngestResponse)
async def trigger_feed_ingestion(
    payload: FeedIngestRequest, db: DbSession
) -> FeedIngestResponse:
    service = FeedService(db)
    task_ids = await service.trigger_ingestion(payload.source)
    return FeedIngestResponse(task_ids=task_ids)


@router.get("/stats", response_model=list[FeedStats])
async def feed_stats(db: DbSession):
    service = FeedService(db)
    return await service.get_stats()
