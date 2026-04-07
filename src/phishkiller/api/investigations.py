"""Investigation API endpoints."""

import uuid

from fastapi import APIRouter, HTTPException, status

from phishkiller.api.deps import DbSession, Pagination
from phishkiller.schemas.investigation import (
    InvestigationCreate,
    InvestigationDetail,
    InvestigationListResponse,
    InvestigationSubmitResponse,
    InvestigationSummary,
    InvestigationTreeNode,
    InvestigationUpdate,
)
from phishkiller.schemas.kit import KitSummary
from phishkiller.services.investigation_service import InvestigationService

router = APIRouter()


@router.get("", response_model=InvestigationListResponse)
async def list_investigations(
    db: DbSession,
    pagination: Pagination,
) -> InvestigationListResponse:
    service = InvestigationService(db)
    investigations, total = await service.list_investigations(
        offset=pagination.offset, limit=pagination.limit,
    )
    return InvestigationListResponse(
        items=[InvestigationSummary.model_validate(i) for i in investigations],
        total=total,
    )


@router.post("", response_model=InvestigationSubmitResponse, status_code=status.HTTP_202_ACCEPTED)
async def create_investigation(
    payload: InvestigationCreate,
    db: DbSession,
) -> InvestigationSubmitResponse:
    """Create an investigation from a URL to crawl."""
    if not payload.url:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="URL is required",
        )

    service = InvestigationService(db)
    investigation, kit, task_id = await service.create_from_url(
        str(payload.url), max_depth=payload.max_depth,
    )
    await db.commit()

    return InvestigationSubmitResponse(
        investigation_id=investigation.id,
        kit_id=kit.id,
        task_id=task_id,
    )


@router.get("/{investigation_id}", response_model=InvestigationDetail)
async def get_investigation(
    investigation_id: uuid.UUID,
    db: DbSession,
) -> InvestigationDetail:
    service = InvestigationService(db)
    investigation = await service.get_investigation(investigation_id)
    if not investigation:
        raise HTTPException(status_code=404, detail="Investigation not found")

    detail = InvestigationDetail.model_validate(investigation)
    if investigation.root_kit:
        detail.root_kit = KitSummary.model_validate(investigation.root_kit)
    return detail


@router.put("/{investigation_id}", response_model=InvestigationDetail)
async def update_investigation(
    investigation_id: uuid.UUID, payload: InvestigationUpdate, db: DbSession
) -> InvestigationDetail:
    service = InvestigationService(db)
    investigation = await service.update_investigation(
        investigation_id, payload.model_dump(exclude_unset=True)
    )
    if not investigation:
        raise HTTPException(status_code=404, detail="Investigation not found")
    detail = InvestigationDetail.model_validate(investigation)
    if investigation.root_kit:
        detail.root_kit = KitSummary.model_validate(investigation.root_kit)
    return detail


@router.delete("/{investigation_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_investigation(investigation_id: uuid.UUID, db: DbSession) -> None:
    service = InvestigationService(db)
    deleted = await service.delete_investigation(investigation_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Investigation not found")
    await db.commit()


@router.post("/bulk-delete")
async def bulk_delete_investigations(
    payload: dict,
    db: DbSession,
):
    """Delete multiple investigations by ID."""
    ids = payload.get("ids", [])
    if not ids:
        raise HTTPException(status_code=400, detail="No IDs provided")

    service = InvestigationService(db)
    deleted = 0
    for raw_id in ids:
        try:
            inv_id = uuid.UUID(str(raw_id))
        except ValueError:
            continue
        if await service.delete_investigation(inv_id):
            deleted += 1
    await db.commit()
    return {"deleted": deleted}


@router.get("/{investigation_id}/tree", response_model=list[InvestigationTreeNode])
async def get_investigation_tree(
    investigation_id: uuid.UUID,
    db: DbSession,
) -> list[InvestigationTreeNode]:
    """Get the parent-child kit tree for an investigation."""
    service = InvestigationService(db)
    investigation = await service.get_investigation(investigation_id)
    if not investigation:
        raise HTTPException(status_code=404, detail="Investigation not found")

    kits = await service.get_kit_tree(investigation_id)
    return _build_tree(kits)


@router.get("/{investigation_id}/kits")
async def get_investigation_kits(
    investigation_id: uuid.UUID,
    db: DbSession,
    pagination: Pagination,
):
    """Flat list of all kits in an investigation."""
    service = InvestigationService(db)
    kits = await service.get_kit_tree(investigation_id)
    total = len(kits)
    page = kits[pagination.offset:pagination.offset + pagination.limit]
    return {
        "items": [KitSummary.model_validate(k) for k in page],
        "total": total,
    }


def _build_tree(kits: list) -> list[InvestigationTreeNode]:
    """Build a tree of InvestigationTreeNode from a flat list of kits."""
    nodes: dict[uuid.UUID, InvestigationTreeNode] = {}
    roots: list[InvestigationTreeNode] = []

    for kit in kits:
        node = InvestigationTreeNode(
            kit=KitSummary.model_validate(kit),
            discovery_method=kit.discovery_method,
            chain_depth=kit.chain_depth,
        )
        nodes[kit.id] = node

    for kit in kits:
        node = nodes[kit.id]
        if kit.parent_kit_id and kit.parent_kit_id in nodes:
            nodes[kit.parent_kit_id].children.append(node)
        else:
            roots.append(node)

    return roots
