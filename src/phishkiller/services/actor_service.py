"""Actor business logic."""

import uuid

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from phishkiller.models.actor import Actor
from phishkiller.models.indicator import Indicator


class ActorService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def list_actors(
        self, offset: int = 0, limit: int = 50
    ) -> tuple[list[Actor], int]:
        total = (await self.db.execute(select(func.count(Actor.id)))).scalar_one()
        result = await self.db.execute(
            select(Actor).order_by(Actor.created_at.desc()).offset(offset).limit(limit)
        )
        return list(result.scalars().all()), total

    async def get_actor(self, actor_id: uuid.UUID) -> Actor | None:
        result = await self.db.execute(
            select(Actor).where(Actor.id == actor_id)
        )
        return result.scalar_one_or_none()

    async def create_actor(self, data: dict) -> Actor:
        actor = Actor(**data)
        self.db.add(actor)
        await self.db.flush()
        return actor

    async def update_actor(self, actor_id: uuid.UUID, data: dict) -> Actor | None:
        actor = await self.get_actor(actor_id)
        if not actor:
            return None
        for key, value in data.items():
            if value is not None:
                setattr(actor, key, value)
        await self.db.flush()
        return actor

    async def link_indicators(
        self, actor_id: uuid.UUID, indicator_ids: list[uuid.UUID]
    ) -> int:
        result = await self.db.execute(
            select(Indicator).where(Indicator.id.in_(indicator_ids))
        )
        indicators = result.scalars().all()
        count = 0
        for indicator in indicators:
            indicator.actor_id = actor_id
            count += 1
        await self.db.flush()
        return count
