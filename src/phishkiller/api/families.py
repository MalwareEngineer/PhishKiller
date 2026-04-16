"""Family API endpoints."""

import uuid

from fastapi import APIRouter, HTTPException, status

from phishkiller.api.deps import DbSession, Pagination
from phishkiller.schemas.family import (
    FamilyCreate,
    FamilyDetail,
    FamilyListResponse,
    FamilyUpdate,
    LinkActorsRequest,
    LinkKitsRequest,
)
from phishkiller.services.family_service import FamilyService

router = APIRouter()


@router.get("", response_model=FamilyListResponse)
async def list_families(db: DbSession, pagination: Pagination):
    service = FamilyService(db)
    families, total = await service.list_families(
        offset=pagination.offset, limit=pagination.limit
    )
    return FamilyListResponse(items=families, total=total)


@router.post("", response_model=FamilyDetail, status_code=status.HTTP_201_CREATED)
async def create_family(payload: FamilyCreate, db: DbSession):
    service = FamilyService(db)
    family = await service.create_family(payload.model_dump())
    return family


@router.get("/{family_id}", response_model=FamilyDetail)
async def get_family(family_id: uuid.UUID, db: DbSession):
    service = FamilyService(db)
    family = await service.get_family(family_id)
    if not family:
        raise HTTPException(status_code=404, detail="Family not found")
    return family


@router.put("/{family_id}", response_model=FamilyDetail)
async def update_family(family_id: uuid.UUID, payload: FamilyUpdate, db: DbSession):
    service = FamilyService(db)
    family = await service.update_family(
        family_id, payload.model_dump(exclude_unset=True)
    )
    if not family:
        raise HTTPException(status_code=404, detail="Family not found")
    return family


@router.delete("/{family_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_family(family_id: uuid.UUID, db: DbSession):
    service = FamilyService(db)
    deleted = await service.delete_family(family_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Family not found")


@router.post("/{family_id}/kits")
async def link_kits(
    family_id: uuid.UUID, payload: LinkKitsRequest, db: DbSession
):
    service = FamilyService(db)
    try:
        count = await service.link_kits(family_id, payload.kit_ids)
    except ValueError:
        raise HTTPException(status_code=404, detail="Family not found")
    return {"added": count}


@router.post("/{family_id}/actors")
async def link_actors(
    family_id: uuid.UUID, payload: LinkActorsRequest, db: DbSession
):
    service = FamilyService(db)
    try:
        count = await service.link_actors(family_id, payload.actor_ids)
    except ValueError:
        raise HTTPException(status_code=404, detail="Family not found")
    return {"added": count}
