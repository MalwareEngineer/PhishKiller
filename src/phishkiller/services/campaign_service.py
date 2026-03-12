"""Campaign business logic."""

import uuid

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from phishkiller.models.campaign import Campaign
from phishkiller.models.kit import Kit


class CampaignService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def list_campaigns(
        self, offset: int = 0, limit: int = 50, target_brand: str | None = None
    ) -> tuple[list[Campaign], int]:
        query = select(Campaign).order_by(Campaign.created_at.desc())
        count_query = select(func.count(Campaign.id))

        if target_brand:
            query = query.where(Campaign.target_brand.ilike(f"%{target_brand}%"))
            count_query = count_query.where(
                Campaign.target_brand.ilike(f"%{target_brand}%")
            )

        total = (await self.db.execute(count_query)).scalar_one()
        result = await self.db.execute(query.offset(offset).limit(limit))
        return list(result.scalars().all()), total

    async def get_campaign(self, campaign_id: uuid.UUID) -> Campaign | None:
        result = await self.db.execute(
            select(Campaign)
            .where(Campaign.id == campaign_id)
            .options(
                selectinload(Campaign.kits),
                selectinload(Campaign.actors),
            )
        )
        return result.scalar_one_or_none()

    async def create_campaign(self, data: dict) -> Campaign:
        campaign = Campaign(**data)
        self.db.add(campaign)
        await self.db.flush()
        return campaign

    async def update_campaign(
        self, campaign_id: uuid.UUID, data: dict
    ) -> Campaign | None:
        campaign = await self.get_campaign(campaign_id)
        if not campaign:
            return None
        for key, value in data.items():
            if value is not None:
                setattr(campaign, key, value)
        await self.db.flush()
        return campaign

    async def add_kits(
        self, campaign_id: uuid.UUID, kit_ids: list[uuid.UUID]
    ) -> int:
        campaign = await self.get_campaign(campaign_id)
        if not campaign:
            raise ValueError("Campaign not found")

        result = await self.db.execute(select(Kit).where(Kit.id.in_(kit_ids)))
        kits = result.scalars().all()
        count = 0
        for kit in kits:
            if kit not in campaign.kits:
                campaign.kits.append(kit)
                count += 1
        await self.db.flush()
        return count
