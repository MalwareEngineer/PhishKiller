"""Feed business logic."""

from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from phishkiller.models.feed_entry import FeedEntry, FeedSource


class FeedService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def list_entries(
        self,
        offset: int = 0,
        limit: int = 50,
        source: str | None = None,
        processed: bool | None = None,
    ) -> tuple[list[FeedEntry], int]:
        query = select(FeedEntry).order_by(FeedEntry.created_at.desc())
        count_query = select(func.count(FeedEntry.id))

        if source:
            query = query.where(FeedEntry.source == source)
            count_query = count_query.where(FeedEntry.source == source)
        if processed is not None:
            query = query.where(FeedEntry.is_processed == processed)
            count_query = count_query.where(FeedEntry.is_processed == processed)

        total = (await self.db.execute(count_query)).scalar_one()
        result = await self.db.execute(query.offset(offset).limit(limit))
        return list(result.scalars().all()), total

    async def get_stats(self) -> list[dict]:
        query = select(
            FeedEntry.source,
            func.count(FeedEntry.id).label("total"),
            func.sum(case((FeedEntry.is_processed, 1), else_=0)).label("processed"),
            func.sum(case((~FeedEntry.is_processed, 1), else_=0)).label("unprocessed"),
        ).group_by(FeedEntry.source)

        result = await self.db.execute(query)
        return [
            {
                "source": row.source.value,
                "total": row.total,
                "processed": row.processed or 0,
                "unprocessed": row.unprocessed or 0,
            }
            for row in result.all()
        ]

    async def trigger_ingestion(self, source: str = "all") -> list[str]:
        from phishkiller.tasks.feeds import (
            ingest_openphish,
            ingest_phishtank,
            ingest_urlhaus,
        )

        task_ids = []
        sources = (
            [source]
            if source != "all"
            else [s.value for s in FeedSource if s != FeedSource.MANUAL]
        )

        task_map = {
            "phishtank": ingest_phishtank,
            "urlhaus": ingest_urlhaus,
            "openphish": ingest_openphish,
        }

        for src in sources:
            task_func = task_map.get(src)
            if task_func:
                result = task_func.delay()
                task_ids.append(result.id)

        return task_ids
