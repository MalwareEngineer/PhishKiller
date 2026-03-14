"""Kit business logic."""

import uuid

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from phishkiller.models.kit import Kit, KitStatus


class KitService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def list_kits(
        self,
        offset: int = 0,
        limit: int = 50,
        status_filter: str | None = None,
        source_feed: str | None = None,
    ) -> tuple[list[Kit], int]:
        query = select(Kit).order_by(Kit.created_at.desc())
        count_query = select(func.count(Kit.id))

        if status_filter:
            query = query.where(Kit.status == status_filter)
            count_query = count_query.where(Kit.status == status_filter)
        if source_feed:
            query = query.where(Kit.source_feed == source_feed)
            count_query = count_query.where(Kit.source_feed == source_feed)

        total = (await self.db.execute(count_query)).scalar_one()
        result = await self.db.execute(query.offset(offset).limit(limit))
        return list(result.scalars().all()), total

    async def get_kit(self, kit_id: uuid.UUID) -> Kit | None:
        query = (
            select(Kit)
            .where(Kit.id == kit_id)
            .options(
                selectinload(Kit.indicators),
                selectinload(Kit.analysis_results),
            )
        )
        result = await self.db.execute(query)
        return result.scalar_one_or_none()

    async def _find_existing_kit(self, url: str) -> Kit | None:
        """Find an existing non-FAILED kit with the same source URL."""
        query = select(Kit).where(
            Kit.source_url == url,
            Kit.status != KitStatus.FAILED,
        )
        result = await self.db.execute(query)
        return result.scalar_one_or_none()

    async def submit_kit(
        self, url: str, source_feed: str | None = None
    ) -> tuple[Kit, str, bool]:
        # URL dedup: return existing kit if already tracked
        existing = await self._find_existing_kit(url)
        if existing:
            return existing, "", True

        kit = Kit(
            id=uuid.uuid4(),
            source_url=str(url),
            source_feed=source_feed or "manual",
            status=KitStatus.PENDING,
        )
        self.db.add(kit)
        await self.db.flush()

        # Dispatch Celery task
        from phishkiller.tasks.analysis import build_analysis_chain

        chain = build_analysis_chain(str(kit.id))
        result = chain.apply_async()
        task_id = result.id

        return kit, task_id, False

    async def submit_file(
        self,
        filename: str,
        local_path: str,
        source_feed: str | None = None,
        kit_id: uuid.UUID | None = None,
    ) -> tuple[Kit, str]:
        """Submit a locally-stored file for analysis (skip download)."""
        kit = Kit(
            id=kit_id or uuid.uuid4(),
            source_url=f"file://{filename}",
            source_feed=source_feed or "manual",
            local_path=local_path,
            filename=filename,
            status=KitStatus.PENDING,
        )
        self.db.add(kit)
        await self.db.flush()

        from phishkiller.tasks.analysis import build_analysis_chain

        chain = build_analysis_chain(str(kit.id))
        result = chain.apply_async()
        return kit, result.id

    async def submit_bulk(
        self, urls: list[str], source_feed: str | None = None
    ) -> tuple[list[dict], int, int]:
        """Submit multiple URLs. Returns (results, submitted, skipped)."""
        from phishkiller.tasks.analysis import build_analysis_chain

        results = []
        submitted = 0
        skipped = 0

        for url in urls:
            existing = await self._find_existing_kit(url)
            if existing:
                results.append({
                    "url": url,
                    "kit_id": existing.id,
                    "task_id": None,
                    "duplicate": True,
                })
                skipped += 1
                continue

            kit = Kit(
                id=uuid.uuid4(),
                source_url=url,
                source_feed=source_feed or "manual",
                status=KitStatus.PENDING,
            )
            self.db.add(kit)
            await self.db.flush()

            chain = build_analysis_chain(str(kit.id))
            task_result = chain.apply_async()
            results.append({
                "url": url,
                "kit_id": kit.id,
                "task_id": task_result.id,
                "duplicate": False,
            })
            submitted += 1

        return results, submitted, skipped

    async def find_similar(
        self, kit_id: uuid.UUID, threshold: int = 100
    ) -> list[dict]:
        kit = await self.get_kit(kit_id)
        if not kit or not kit.tlsh:
            return []

        # Load all kits with TLSH hashes
        query = select(Kit).where(
            Kit.tlsh.isnot(None),
            Kit.id != kit_id,
        )
        result = await self.db.execute(query)
        candidates = result.scalars().all()

        similar = []
        try:
            import tlsh

            for candidate in candidates:
                distance = tlsh.diff(kit.tlsh, candidate.tlsh)
                if distance <= threshold:
                    similar.append({
                        "id": str(candidate.id),
                        "sha256": candidate.sha256,
                        "tlsh": candidate.tlsh,
                        "source_url": candidate.source_url,
                        "distance": distance,
                    })
            similar.sort(key=lambda x: x["distance"])
        except ImportError:
            pass

        return similar

    async def reanalyze(self, kit_id: uuid.UUID) -> str:
        kit = await self.get_kit(kit_id)
        if not kit:
            raise ValueError("Kit not found")

        kit.status = KitStatus.PENDING
        await self.db.flush()

        from phishkiller.tasks.analysis import build_analysis_chain

        chain = build_analysis_chain(str(kit.id))
        result = chain.apply_async()
        return result.id

    async def delete_kit(self, kit_id: uuid.UUID) -> bool:
        kit = await self.get_kit(kit_id)
        if not kit:
            return False
        await self.db.delete(kit)
        return True
