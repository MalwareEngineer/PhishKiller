"""MonitoredDomain CRUD endpoints — drives the PhishPrint allowlist."""

import uuid

from fastapi import APIRouter, HTTPException, status

from darla.api.deps import DbSession, Pagination
from darla.schemas.victim import (
    MonitoredDomainCreate,
    MonitoredDomainListResponse,
    MonitoredDomainOut,
    MonitoredDomainUpdate,
)
from darla.services.monitored_domain_service import MonitoredDomainService

router = APIRouter()


@router.get("", response_model=MonitoredDomainListResponse)
async def list_monitored_domains(db: DbSession, pagination: Pagination):
    service = MonitoredDomainService(db)
    items, total = await service.list_domains(
        offset=pagination.offset, limit=pagination.limit,
    )
    return MonitoredDomainListResponse(items=items, total=total)


@router.post(
    "",
    response_model=MonitoredDomainOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_monitored_domain(
    payload: MonitoredDomainCreate, db: DbSession,
):
    service = MonitoredDomainService(db)
    try:
        domain = await service.create_domain(payload.model_dump())
    except Exception as exc:
        # Most likely a unique-constraint violation on the domain
        # column — operator tried to add a duplicate.
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Domain may already exist: {exc}",
        ) from exc
    return domain


@router.get("/{domain_id}", response_model=MonitoredDomainOut)
async def get_monitored_domain(domain_id: uuid.UUID, db: DbSession):
    service = MonitoredDomainService(db)
    domain = await service.get_domain(domain_id)
    if domain is None:
        raise HTTPException(status_code=404, detail="Monitored domain not found")
    return domain


@router.put("/{domain_id}", response_model=MonitoredDomainOut)
async def update_monitored_domain(
    domain_id: uuid.UUID, payload: MonitoredDomainUpdate, db: DbSession,
):
    service = MonitoredDomainService(db)
    domain = await service.update_domain(
        domain_id, payload.model_dump(exclude_unset=True),
    )
    if domain is None:
        raise HTTPException(status_code=404, detail="Monitored domain not found")
    return domain


@router.delete("/{domain_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_monitored_domain(domain_id: uuid.UUID, db: DbSession):
    service = MonitoredDomainService(db)
    deleted = await service.delete_domain(domain_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Monitored domain not found")
