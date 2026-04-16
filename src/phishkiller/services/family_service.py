"""Family business logic."""

import uuid

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from phishkiller.models.actor import Actor
from phishkiller.models.family import Family
from phishkiller.models.kit import Kit


class FamilyService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def list_families(
        self, offset: int = 0, limit: int = 50
    ) -> tuple[list[Family], int]:
        total = (await self.db.execute(select(func.count(Family.id)))).scalar_one()
        result = await self.db.execute(
            select(Family).order_by(Family.created_at.desc()).offset(offset).limit(limit)
        )
        return list(result.scalars().all()), total

    async def get_family(self, family_id: uuid.UUID) -> Family | None:
        result = await self.db.execute(
            select(Family)
            .where(Family.id == family_id)
            .options(
                selectinload(Family.kits),
                selectinload(Family.actors),
            )
        )
        return result.scalar_one_or_none()

    async def create_family(self, data: dict) -> Family:
        family = Family(**data)
        self.db.add(family)
        await self.db.flush()
        # Re-fetch with relationships loaded
        return await self.get_family(family.id)  # type: ignore[return-value]

    async def update_family(
        self, family_id: uuid.UUID, data: dict
    ) -> Family | None:
        family = await self.get_family(family_id)
        if not family:
            return None
        for key, value in data.items():
            if value is not None:
                setattr(family, key, value)
        await self.db.flush()
        return family

    async def delete_family(self, family_id: uuid.UUID) -> bool:
        family = await self.get_family(family_id)
        if not family:
            return False
        await self.db.delete(family)
        await self.db.flush()
        return True

    async def link_kits(
        self, family_id: uuid.UUID, kit_ids: list[uuid.UUID]
    ) -> int:
        family = await self.get_family(family_id)
        if not family:
            raise ValueError("Family not found")

        result = await self.db.execute(select(Kit).where(Kit.id.in_(kit_ids)))
        kits = result.scalars().all()
        count = 0
        for kit in kits:
            if kit not in family.kits:
                family.kits.append(kit)
                count += 1
        await self.db.flush()
        return count

    async def link_actors(
        self, family_id: uuid.UUID, actor_ids: list[uuid.UUID]
    ) -> int:
        family = await self.get_family(family_id)
        if not family:
            raise ValueError("Family not found")

        result = await self.db.execute(select(Actor).where(Actor.id.in_(actor_ids)))
        actors = result.scalars().all()
        count = 0
        for actor in actors:
            if actor not in family.actors:
                family.actors.append(actor)
                count += 1
        await self.db.flush()
        return count
