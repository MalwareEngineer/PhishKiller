"""Victim API endpoints — powers the PhishPrint pages.

Victim creation is intentionally NOT exposed.  Victims are
pipeline-managed: emails observed during analysis whose domain
matches a row in :class:`MonitoredDomain` get promoted via
:func:`darla.services.victim_service.observe_victim_email`.
Operators interact with the existing rows: list, view, edit
``display_name`` / ``type`` / ``notes``, query observations.
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from darla.api.deps import DbSession, Pagination
from darla.auth import require_role, set_audit_extra
from darla.models import UserRole
from darla.models.victim import VictimType
from darla.schemas.victim import (
    VictimDetail,
    VictimListResponse,
    VictimObservationListResponse,
    VictimUpdate,
)
from darla.services.victim_service import VictimService

router = APIRouter()

# Victim writes will move to a CLI/CSV-driven path in Phase 6 (RFC §9);
# until then, ANALYST-gated rather than anonymous.  Reads stay analyst-
# adjacent for the per-employee dashboard.
_ANALYST = [Depends(require_role(UserRole.ANALYST))]


@router.get("", response_model=VictimListResponse)
async def list_victims(
    request: Request,
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

    Audit: records the IDs of victims returned in ``audit_log.extra``
    so "who saw which victims this quarter" reports are a single
    indexed query (RFC §5.2).
    """
    service = VictimService(db)
    items, total = await service.list_victims(
        offset=pagination.offset,
        limit=pagination.limit,
        domain=domain,
        type_=type,
        search=search,
    )
    set_audit_extra(request, victim_ids=[str(v.id) for v in items])
    return VictimListResponse(items=items, total=total)


@router.get("/{victim_id}", response_model=VictimDetail)
async def get_victim(victim_id: uuid.UUID, request: Request, db: DbSession):
    service = VictimService(db)
    victim = await service.get_victim(victim_id)
    if victim is None:
        raise HTTPException(status_code=404, detail="Victim not found")
    # Single-victim read — record the ID accessed so the audit log
    # can answer per-victim "who looked at this person's record" queries.
    set_audit_extra(request, victim_ids=[str(victim.id)])
    return victim


@router.put("/{victim_id}", response_model=VictimDetail, dependencies=_ANALYST)
async def update_victim(
    victim_id: uuid.UUID,
    payload: VictimUpdate,
    request: Request,
    db: DbSession,
):
    service = VictimService(db)
    victim = await service.update_victim(
        victim_id, payload.model_dump(exclude_unset=True),
    )
    if victim is None:
        raise HTTPException(status_code=404, detail="Victim not found")
    set_audit_extra(request, victim_ids=[str(victim.id)])
    return victim


@router.get(
    "/{victim_id}/observations",
    response_model=VictimObservationListResponse,
)
async def list_victim_observations(
    victim_id: uuid.UUID,
    request: Request,
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
    set_audit_extra(request, victim_ids=[str(victim_id)])
    return VictimObservationListResponse(items=items, total=total)
