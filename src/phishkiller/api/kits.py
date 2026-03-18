"""Kit API endpoints."""

import uuid
from pathlib import Path

from fastapi import APIRouter, Form, HTTPException, UploadFile, status

from phishkiller.api.deps import DbSession, Pagination
from phishkiller.config import get_settings
from phishkiller.schemas.kit import (
    KitBulkCreate,
    KitBulkResponse,
    KitBulkResult,
    KitBulkUploadResponse,
    KitBulkUploadResult,
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
    kit, task_id, duplicate = await service.submit_kit(
        str(payload.url), payload.source_feed
    )

    # Auto-create investigation for manual submissions so crawl_chain fires
    if not duplicate and (payload.source_feed or "manual") == "manual":
        from phishkiller.services.investigation_service import InvestigationService

        inv_service = InvestigationService(db)
        await inv_service.create_from_file(kit)

    return KitSubmitResponse(
        kit_id=kit.id,
        task_id=task_id or "",
        duplicate=duplicate,
        message="Duplicate — existing kit returned" if duplicate else "Kit submitted for analysis",
    )


@router.post("/upload", response_model=KitSubmitResponse, status_code=status.HTTP_202_ACCEPTED)
async def upload_kit(
    db: DbSession,
    file: UploadFile,
    source_feed: str = Form("manual"),
) -> KitSubmitResponse:
    """Upload a local phishing kit file for analysis (skips download step)."""
    settings = get_settings()
    max_bytes = settings.max_kit_size_mb * 1024 * 1024

    # Read file content with size check
    content = await file.read()
    if len(content) > max_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File exceeds {settings.max_kit_size_mb}MB limit",
        )

    # Save to download dir so the chain can find it
    kit_id = uuid.uuid4()
    download_dir = Path(settings.kit_download_dir) / str(kit_id)
    download_dir.mkdir(parents=True, exist_ok=True)
    filepath = download_dir / (file.filename or "upload.bin")
    filepath.write_bytes(content)

    service = KitService(db)
    kit, task_id = await service.submit_file(
        filename=file.filename or "upload.bin",
        local_path=str(filepath),
        source_feed=source_feed,
        kit_id=kit_id,
    )

    # Auto-create investigation for .eml uploads
    filename_lower = (file.filename or "").lower()
    if filename_lower.endswith(".eml"):
        from phishkiller.services.investigation_service import InvestigationService

        inv_service = InvestigationService(db)
        await inv_service.create_from_file(kit)

    return KitSubmitResponse(kit_id=kit.id, task_id=task_id)


@router.post(
    "/upload/bulk",
    response_model=KitBulkUploadResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def bulk_upload_kits(
    db: DbSession,
    files: list[UploadFile],
) -> KitBulkUploadResponse:
    """Upload multiple phishing kit files for analysis (max 50)."""
    if len(files) > 50:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Maximum 50 files per bulk upload",
        )

    settings = get_settings()
    max_bytes = settings.max_kit_size_mb * 1024 * 1024
    file_entries: list[dict] = []

    for file in files:
        content = await file.read()
        if len(content) > max_bytes:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"File '{file.filename}' exceeds {settings.max_kit_size_mb}MB limit",
            )

        kit_id = uuid.uuid4()
        download_dir = Path(settings.kit_download_dir) / str(kit_id)
        download_dir.mkdir(parents=True, exist_ok=True)
        filepath = download_dir / (file.filename or "upload.bin")
        filepath.write_bytes(content)

        file_entries.append({
            "kit_id": kit_id,
            "filename": file.filename or "upload.bin",
            "local_path": str(filepath),
        })

    service = KitService(db)
    results = await service.submit_bulk_files(file_entries)

    # Auto-create investigations for .eml uploads
    from phishkiller.services.investigation_service import InvestigationService

    inv_service = InvestigationService(db)
    final_results: list[KitBulkUploadResult] = []

    for entry, result in zip(file_entries, results):
        investigation_id = None
        if entry["filename"].lower().endswith(".eml"):
            kit = await service.get_kit(result["kit_id"])
            if kit:
                inv = await inv_service.create_from_file(kit)
                investigation_id = inv.id if inv else None

        final_results.append(KitBulkUploadResult(
            filename=result["filename"],
            kit_id=result["kit_id"],
            task_id=result["task_id"],
            investigation_id=investigation_id,
        ))

    return KitBulkUploadResponse(
        submitted=len(final_results),
        results=final_results,
    )


@router.post("/bulk", response_model=KitBulkResponse, status_code=status.HTTP_202_ACCEPTED)
async def bulk_submit(payload: KitBulkCreate, db: DbSession) -> KitBulkResponse:
    """Submit multiple URLs for download and analysis."""
    if len(payload.urls) > 500:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Maximum 500 URLs per bulk request",
        )

    service = KitService(db)
    results, submitted, skipped = await service.submit_bulk(
        [str(u) for u in payload.urls], payload.source_feed
    )

    # Auto-create investigations for manual bulk submissions
    if (payload.source_feed or "manual") == "manual":
        from phishkiller.services.investigation_service import InvestigationService

        inv_service = InvestigationService(db)
        for r in results:
            if not r["duplicate"]:
                kit = await service.get_kit(r["kit_id"])
                if kit:
                    await inv_service.create_from_file(kit)

    return KitBulkResponse(
        submitted=submitted,
        skipped_duplicate=skipped,
        results=[KitBulkResult(**r) for r in results],
    )


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
