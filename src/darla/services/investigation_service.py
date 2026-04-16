"""Investigation business logic."""

import uuid

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from darla.models.investigation import Investigation, InvestigationStatus
from darla.models.kit import Kit, KitStatus


class InvestigationService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def list_investigations(
        self,
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[list[Investigation], int]:
        query = select(Investigation).order_by(Investigation.created_at.desc())
        count_query = select(func.count(Investigation.id))
        total = (await self.db.execute(count_query)).scalar_one()
        result = await self.db.execute(query.offset(offset).limit(limit))
        return list(result.scalars().all()), total

    async def get_investigation(self, investigation_id: uuid.UUID) -> Investigation | None:
        query = (
            select(Investigation)
            .where(Investigation.id == investigation_id)
            .options(selectinload(Investigation.root_kit))
        )
        result = await self.db.execute(query)
        return result.scalar_one_or_none()

    async def create_from_url(
        self, url: str, max_depth: int = 5
    ) -> tuple[Investigation, Kit, str]:
        """Create an investigation starting from a URL."""
        kit = Kit(
            id=uuid.uuid4(),
            source_url=url,
            source_feed="investigation",
            status=KitStatus.PENDING,
            chain_depth=0,
        )
        self.db.add(kit)
        await self.db.flush()

        investigation = Investigation(
            id=uuid.uuid4(),
            name=f"URL-{str(kit.id)[:8]}",
            root_kit_id=kit.id,
            status=InvestigationStatus.IN_PROGRESS,
            max_depth=max_depth,
        )
        self.db.add(investigation)
        await self.db.flush()

        kit.investigation_id = investigation.id

        from darla.tasks.analysis import build_analysis_chain

        chain = build_analysis_chain(str(kit.id))
        result = chain.apply_async()

        return investigation, kit, result.id

    async def create_from_file(
        self,
        kit: Kit,
        max_depth: int = 5,
    ) -> Investigation:
        """Create an investigation from an already-created kit (e.g. .eml or image upload)."""
        # Choose prefix based on file type
        fname = (kit.filename or "").lower()
        image_exts = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp"}
        if any(fname.endswith(ext) for ext in image_exts):
            prefix = "QR"
        elif fname.endswith(".eml"):
            prefix = "EML"
        else:
            prefix = "FILE"
        investigation = Investigation(
            id=uuid.uuid4(),
            name=f"{prefix}-{str(kit.id)[:8]}",
            root_kit_id=kit.id,
            status=InvestigationStatus.IN_PROGRESS,
            max_depth=max_depth,
        )
        self.db.add(investigation)
        await self.db.flush()

        kit.investigation_id = investigation.id
        kit.chain_depth = 0
        return investigation

    async def update_investigation(
        self, investigation_id: uuid.UUID, data: dict
    ) -> Investigation | None:
        investigation = await self.get_investigation(investigation_id)
        if not investigation:
            return None
        for key, value in data.items():
            setattr(investigation, key, value)
        await self.db.flush()
        return investigation

    async def delete_investigation(self, investigation_id: uuid.UUID) -> bool:
        """Delete an investigation.

        DB cascades handle cleanup:
        - root_kit CASCADE deletes (and its child kits cascade too)
        - Other linked kits get investigation_id SET NULL (preserved)
        """
        investigation = await self.get_investigation(investigation_id)
        if not investigation:
            return False

        # Clean up root kit's local files before deletion
        if investigation.root_kit and investigation.root_kit.local_path:
            import shutil
            from pathlib import Path

            from darla.services.kit_service import KitService

            kit_service = KitService(self.db)
            # Use kit service to do a thorough delete (handles descendants + files)
            await kit_service.delete_kit(investigation.root_kit.id)

        await self.db.delete(investigation)
        return True

    async def get_kit_tree(self, investigation_id: uuid.UUID) -> list[Kit]:
        """Get all kits in an investigation, ordered by depth then created_at."""
        query = (
            select(Kit)
            .where(Kit.investigation_id == investigation_id)
            .order_by(Kit.chain_depth, Kit.created_at)
        )
        result = await self.db.execute(query)
        return list(result.scalars().all())
