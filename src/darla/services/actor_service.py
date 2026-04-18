"""Actor business logic."""

import uuid

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from darla.models.actor import Actor
from darla.models.indicator import Indicator


class ActorService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def list_actors(
        self, offset: int = 0, limit: int = 50, include_auto: bool = False
    ) -> tuple[list[Actor], int]:
        """List analyst-managed actors.

        By default, synthetic actors created by the legacy
        ``correlate_kit_actors`` task (``auto_generated=True``) are hidden —
        they're kept in the DB to preserve historical indicator/kit links but
        are not useful in analyst list views.  Pass ``include_auto=True`` to
        see them (debugging, cleanup tooling, reverse-lookup queries).
        """
        query = select(Actor).order_by(Actor.created_at.desc())
        count_query = select(func.count(Actor.id))
        if not include_auto:
            query = query.where(Actor.auto_generated.is_(False))
            count_query = count_query.where(Actor.auto_generated.is_(False))

        total = (await self.db.execute(count_query)).scalar_one()
        result = await self.db.execute(query.offset(offset).limit(limit))
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

    async def delete_actor(self, actor_id: uuid.UUID) -> bool:
        actor = await self.get_actor(actor_id)
        if not actor:
            return False
        # Unlink indicators (SET NULL) so FK doesn't block delete
        from sqlalchemy import update

        await self.db.execute(
            update(Indicator)
            .where(Indicator.actor_id == actor_id)
            .values(actor_id=None)
        )
        await self.db.delete(actor)
        await self.db.flush()
        return True

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
