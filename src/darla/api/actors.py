"""Actor API endpoints."""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status

from darla.api.deps import DbSession, Pagination
from darla.auth import require_role
from darla.models import UserRole
from darla.schemas.actor import (
    ActorCreate,
    ActorDetail,
    ActorListResponse,
    ActorStats,
    ActorUpdate,
    LinkIndicatorsRequest,
)
from darla.schemas.campaign import CampaignSummary
from darla.schemas.family import FamilySummary
from darla.schemas.indicator import IndicatorListResponse
from darla.schemas.kit import KitListResponse
from darla.services.actor_service import ActorService

router = APIRouter()

# Shorthand reused on every write endpoint in this module.  Read
# endpoints rely solely on the router-level ``Depends(current_user)``
# applied in ``darla.api.router`` — they pass the auth check but
# don't require the elevated role.
_ANALYST = [Depends(require_role(UserRole.ANALYST))]


@router.get("", response_model=ActorListResponse)
async def list_actors(
    db: DbSession, pagination: Pagination, include_auto: bool = False
):
    """List actors.  Auto-generated (synthetic) actors are hidden unless
    ``include_auto=true`` is passed."""
    service = ActorService(db)
    actors, total = await service.list_actors(
        offset=pagination.offset,
        limit=pagination.limit,
        include_auto=include_auto,
    )
    return ActorListResponse(items=actors, total=total)


@router.post(
    "",
    response_model=ActorDetail,
    status_code=status.HTTP_201_CREATED,
    dependencies=_ANALYST,
)
async def create_actor(payload: ActorCreate, db: DbSession):
    service = ActorService(db)
    actor = await service.create_actor(payload.model_dump())
    return actor


@router.get("/{actor_id}", response_model=ActorDetail)
async def get_actor(actor_id: uuid.UUID, db: DbSession):
    service = ActorService(db)
    actor = await service.get_actor(actor_id)
    if not actor:
        raise HTTPException(status_code=404, detail="Actor not found")
    return actor


@router.put("/{actor_id}", response_model=ActorDetail, dependencies=_ANALYST)
async def update_actor(actor_id: uuid.UUID, payload: ActorUpdate, db: DbSession):
    service = ActorService(db)
    actor = await service.update_actor(
        actor_id, payload.model_dump(exclude_unset=True)
    )
    if not actor:
        raise HTTPException(status_code=404, detail="Actor not found")
    return actor


@router.delete(
    "/{actor_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=_ANALYST,
)
async def delete_actor(actor_id: uuid.UUID, db: DbSession):
    service = ActorService(db)
    deleted = await service.delete_actor(actor_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Actor not found")


@router.post("/{actor_id}/link", dependencies=_ANALYST)
async def link_indicators(
    actor_id: uuid.UUID, payload: LinkIndicatorsRequest, db: DbSession
):
    service = ActorService(db)
    count = await service.link_indicators(actor_id, payload.indicator_ids)
    return {"linked": count}


# ---------------------------------------------------------------------------
# Stats + drill-down endpoints — power the rebuilt detail page tabs.
# ---------------------------------------------------------------------------


@router.get("/{actor_id}/stats", response_model=ActorStats)
async def get_actor_stats(actor_id: uuid.UUID, db: DbSession):
    """Aggregate Overview-tab payload: counts, target-brand mix,
    family distribution, monthly timeline, top indicators."""
    service = ActorService(db)
    stats = await service.get_stats(actor_id)
    if stats is None:
        raise HTTPException(status_code=404, detail="Actor not found")
    return stats


@router.get("/{actor_id}/kits", response_model=KitListResponse)
async def list_actor_kits(
    actor_id: uuid.UUID,
    db: DbSession,
    pagination: Pagination,
    status: str | None = Query(  # noqa: A002 — matches schema
        default=None, description="Filter by kit status",
    ),
):
    """Paginated kit list for the Kits tab."""
    service = ActorService(db)
    items, total = await service.list_kits(
        actor_id,
        offset=pagination.offset,
        limit=pagination.limit,
        status=status,
    )
    return KitListResponse(items=items, total=total)


@router.get("/{actor_id}/indicators", response_model=IndicatorListResponse)
async def list_actor_indicators(
    actor_id: uuid.UUID,
    db: DbSession,
    pagination: Pagination,
):
    """Paginated indicator list for the Indicators tab."""
    service = ActorService(db)
    items, total = await service.list_indicators(
        actor_id, offset=pagination.offset, limit=pagination.limit,
    )
    return IndicatorListResponse(items=items, total=total)


@router.get("/{actor_id}/campaigns", response_model=list[CampaignSummary])
async def list_actor_campaigns(actor_id: uuid.UUID, db: DbSession):
    """Campaigns linked to this actor.  Not paginated — typical
    actors have <50 campaigns and the tab benefits from a single
    flat list."""
    service = ActorService(db)
    return await service.list_campaigns(actor_id)


@router.get("/{actor_id}/families", response_model=list[FamilySummary])
async def list_actor_families(actor_id: uuid.UUID, db: DbSession):
    """Families linked to this actor — same pagination rationale as
    campaigns."""
    service = ActorService(db)
    return await service.list_families(actor_id)
