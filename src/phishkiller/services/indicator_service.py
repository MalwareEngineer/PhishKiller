"""Indicator business logic."""

import uuid

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from phishkiller.models.indicator import Indicator


class IndicatorService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def list_indicators(
        self,
        offset: int = 0,
        limit: int = 50,
        type_filter: str | None = None,
        kit_id: uuid.UUID | None = None,
    ) -> tuple[list[Indicator], int]:
        query = select(Indicator).order_by(Indicator.created_at.desc())
        count_query = select(func.count(Indicator.id))

        if type_filter:
            query = query.where(Indicator.type == type_filter)
            count_query = count_query.where(Indicator.type == type_filter)
        if kit_id:
            query = query.where(Indicator.kit_id == kit_id)
            count_query = count_query.where(Indicator.kit_id == kit_id)

        total = (await self.db.execute(count_query)).scalar_one()
        result = await self.db.execute(query.offset(offset).limit(limit))
        return list(result.scalars().all()), total

    async def get_indicator(self, indicator_id: uuid.UUID) -> Indicator | None:
        result = await self.db.execute(
            select(Indicator).where(Indicator.id == indicator_id)
        )
        return result.scalar_one_or_none()

    async def search_indicators(
        self,
        query_str: str,
        type_filter: str | None = None,
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[list[Indicator], int]:
        query = select(Indicator).where(
            Indicator.value.ilike(f"%{query_str}%")
        )
        count_query = select(func.count(Indicator.id)).where(
            Indicator.value.ilike(f"%{query_str}%")
        )

        if type_filter:
            query = query.where(Indicator.type == type_filter)
            count_query = count_query.where(Indicator.type == type_filter)

        total = (await self.db.execute(count_query)).scalar_one()
        result = await self.db.execute(
            query.order_by(Indicator.confidence.desc())
            .offset(offset)
            .limit(limit)
        )
        return list(result.scalars().all()), total

    async def get_indicator_ids_for_kit_tree(
        self, root_kit_id: uuid.UUID
    ) -> list[uuid.UUID]:
        """Return all indicator IDs belonging to a kit and all its descendants."""
        from phishkiller.models.kit import Kit

        # Collect kit IDs: root + all children (BFS)
        kit_ids: list[uuid.UUID] = [root_kit_id]
        queue = [root_kit_id]
        while queue:
            parent_id = queue.pop(0)
            result = await self.db.execute(
                select(Kit.id).where(Kit.parent_kit_id == parent_id)
            )
            children = list(result.scalars().all())
            kit_ids.extend(children)
            queue.extend(children)

        # Get all indicator IDs for these kits
        result = await self.db.execute(
            select(Indicator.id).where(Indicator.kit_id.in_(kit_ids))
        )
        return list(result.scalars().all())

    async def get_stats(self) -> list[dict]:
        query = (
            select(Indicator.type, func.count(Indicator.id).label("count"))
            .group_by(Indicator.type)
            .order_by(func.count(Indicator.id).desc())
        )
        result = await self.db.execute(query)
        return [{"type": row.type.value, "count": row.count} for row in result.all()]
