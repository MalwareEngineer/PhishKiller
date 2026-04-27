"""Victim API endpoints — powers the PhishPrint pages.

Victim creation is intentionally NOT exposed.  Victims are
pipeline-managed: emails observed during analysis whose domain
matches a row in :class:`MonitoredDomain` get promoted via
:func:`darla.services.victim_service.observe_victim_email`.
Operators interact with the existing rows: list, view, edit
``display_name`` / ``type`` / ``notes``, query observations.
"""

import uuid

from fastapi import APIRouter, HTTPException, Query

from darla.api.deps import DbSession, Pagination
from darla.models.victim import VictimType
from darla.schemas.victim import (
    VictimDetail,
    VictimListResponse,
    VictimObservationListResponse,
    VictimUpdate,
)
from darla.services.victim_service import VictimService

router = APIRouter()


@router.get("", response_model=VictimListResponse)
async def list_victims(
    db: DbSession,
    pagination: Pagination,
    domain: str | None = Query(default=None, description="Exact domain filter"),
    type: VictimType | None = Query(  # noqa: A002 — matches schema
        default=None, description="Filter by victim type",
    ),
    search: str | None = Query(
        default=None, description="Substring match on email or display_name",
    ),
):
    """Paginated victim list — drives the PhishPrint dashboard.

    Sorting is fixed at ``last_seen DESC`` (most recently targeted
    first); add a ``sort`` query param later if operators need
    something else.
    """
    service = VictimService(db)
    items, total = await service.list_victims(
        offset=pagination.offset,
        limit=pagination.limit,
        domain=domain,
        type_=type,
        search=search,
    )
    return VictimListResponse(items=items, total=total)


@router.get("/{victim_id}", response_model=VictimDetail)
async def get_victim(victim_id: uuid.UUID, db: DbSession):
    service = VictimService(db)
    victim = await service.get_victim(victim_id)
    if victim is None:
        raise HTTPException(status_code=404, detail="Victim not found")
    return victim


@router.put("/{victim_id}", response_model=VictimDetail)
async def update_victim(
    victim_id: uuid.UUID, payload: VictimUpdate, db: DbSession,
):
    service = VictimService(db)
    victim = await service.update_victim(
        victim_id, payload.model_dump(exclude_unset=True),
    )
    if victim is None:
        raise HTTPException(status_code=404, detail="Victim not found")
    return victim


@router.get(
    "/{victim_id}/observations",
    response_model=VictimObservationListResponse,
)
async def list_victim_observations(
    victim_id: uuid.UUID,
    db: DbSession,
    pagination: Pagination,
):
    """Per-victim observation list — every kit that mentioned this
    person, the source channel, and when.  Drives the per-victim
    detail page's kit table."""
    service = VictimService(db)
    items, total = await service.list_observations(
        victim_id, offset=pagination.offset, limit=pagination.limit,
    )
    return VictimObservationListResponse(items=items, total=total)
