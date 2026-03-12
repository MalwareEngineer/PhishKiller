"""Actor API endpoints."""

import uuid

from fastapi import APIRouter, HTTPException, status

from phishkiller.api.deps import DbSession, Pagination
from phishkiller.schemas.actor import (
    ActorCreate,
    ActorDetail,
    ActorListResponse,
    ActorUpdate,
    LinkIndicatorsRequest,
)
from phishkiller.services.actor_service import ActorService

router = APIRouter()


@router.get("", response_model=ActorListResponse)
async def list_actors(db: DbSession, pagination: Pagination):
    service = ActorService(db)
    actors, total = await service.list_actors(
        offset=pagination.offset, limit=pagination.limit
    )
    return ActorListResponse(items=actors, total=total)


@router.post("", response_model=ActorDetail, status_code=status.HTTP_201_CREATED)
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


@router.put("/{actor_id}", response_model=ActorDetail)
async def update_actor(actor_id: uuid.UUID, payload: ActorUpdate, db: DbSession):
    service = ActorService(db)
    actor = await service.update_actor(
        actor_id, payload.model_dump(exclude_unset=True)
    )
    if not actor:
        raise HTTPException(status_code=404, detail="Actor not found")
    return actor


@router.post("/{actor_id}/link")
async def link_indicators(
    actor_id: uuid.UUID, payload: LinkIndicatorsRequest, db: DbSession
):
    service = ActorService(db)
    count = await service.link_indicators(actor_id, payload.indicator_ids)
    return {"linked": count}
