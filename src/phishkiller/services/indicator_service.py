"""Indicator business logic."""

import uuid

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from phishkiller.models.indicator import Indicator, IndicatorType


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

    async def get_stats(self) -> list[dict]:
        query = (
            select(Indicator.type, func.count(Indicator.id).label("count"))
            .group_by(Indicator.type)
            .order_by(func.count(Indicator.id).desc())
        )
        result = await self.db.execute(query)
        return [{"type": row.type.value, "count": row.count} for row in result.all()]
