"""Campaign business logic.

The ``get_stats`` + drill-down methods mirror ``ActorService`` and
``FamilyService``: one bundled aggregation for the Overview tab and
per-tab paginated endpoints for Kits / Victims / Indicators / Actors
/ Families on the rebuilt campaign-detail page.

Junction reach matrix:

  - kit count, victim count, timeline, top families, top indicators,
    top victims all reach ``campaign_kits``
  - actor list (Actors tab) uses ``campaign_actors`` (analyst-curated
    direct link)
  - family list reaches via ``family_kits`` joined through
    ``campaign_kits`` (families sharing kits with this campaign)
  - victim list reaches via ``kit_victims`` joined through
    ``campaign_kits`` — the PhishPrint integration: every victim
    observed in any kit attributed to this campaign.
"""

import uuid
from collections import defaultdict

from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from darla.models.actor import Actor
from darla.models.analysis_result import AnalysisResult, AnalysisType
from darla.models.associations import (
    campaign_actors,
    campaign_kits,
    family_kits,
    kit_actors,
)
from darla.models.campaign import Campaign
from darla.models.family import Family
from darla.models.indicator import Indicator
from darla.models.kit import Kit
from darla.models.victim import KitVictim, Victim


class CampaignService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def list_campaigns(
        self,
        offset: int = 0,
        limit: int = 50,
        target_brand: str | None = None,
        include_auto: bool = False,
    ) -> tuple[list[Campaign], int]:
        """List campaigns.

        Auto-generated campaigns (minted by the legacy
        ``auto_assign_campaign`` task) are hidden by default so analyst
        campaign lists only show manually curated entries.  Pass
        ``include_auto=True`` to see every row.
        """
        query = select(Campaign).order_by(Campaign.created_at.desc())
        count_query = select(func.count(Campaign.id))

        if target_brand:
            query = query.where(Campaign.target_brand.ilike(f"%{target_brand}%"))
            count_query = count_query.where(
                Campaign.target_brand.ilike(f"%{target_brand}%")
            )

        if not include_auto:
            query = query.where(Campaign.auto_generated.is_(False))
            count_query = count_query.where(Campaign.auto_generated.is_(False))

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
        # Re-fetch with relationships loaded so CampaignDetail can serialize
        return await self.get_campaign(campaign.id)  # type: ignore[return-value]

    async def update_campaign(
        self, campaign_id: uuid.UUID, data: dict
    ) -> Campaign | None:
        """Mutate operator-editable fields.

        Refresh after flush so the post-update ``updated_at`` lands in
        memory before pydantic serializes — see PR #75 / #76 / #77 for
        the MissingGreenlet-on-async-lazyload pattern.
        """
        campaign = await self.get_campaign(campaign_id)
        if not campaign:
            return None
        for key, value in data.items():
            if value is not None:
                setattr(campaign, key, value)
        await self.db.flush()
        await self.db.refresh(campaign)
        return campaign

    async def delete_campaign(self, campaign_id: uuid.UUID) -> bool:
        campaign = await self.get_campaign(campaign_id)
        if not campaign:
            return False
        await self.db.delete(campaign)
        await self.db.flush()
        return True

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

    # ---------------------------------------------------------------------
    # YARA aggregation helper — same Python-side rollup pattern as
    # FamilyService (see PR #77).
    # ---------------------------------------------------------------------

    async def _yara_rule_counts(
        self, campaign_id: uuid.UUID
    ) -> list[tuple[str, int]]:
        rows = (await self.db.execute(
            select(AnalysisResult.kit_id, AnalysisResult.result_data)
            .join(Kit, Kit.id == AnalysisResult.kit_id)
            .join(campaign_kits, campaign_kits.c.kit_id == Kit.id)
            .where(
                campaign_kits.c.campaign_id == campaign_id,
                AnalysisResult.analysis_type == AnalysisType.YARA_SCAN,
            )
        )).all()

        rule_kits: dict[str, set[uuid.UUID]] = defaultdict(set)
        for row in rows:
            matches = (row.result_data or {}).get("matches") or []
            for m in matches:
                rule = m.get("rule") if isinstance(m, dict) else None
                if rule:
                    rule_kits[rule].add(row.kit_id)
        return sorted(
            ((rule, len(kits)) for rule, kits in rule_kits.items()),
            key=lambda x: (-x[1], x[0]),
        )

    # ---------------------------------------------------------------------
    # Stats — drives the rebuilt campaign-detail page's Overview tab.
    # ---------------------------------------------------------------------

    async def get_stats(self, campaign_id: uuid.UUID) -> dict | None:
        """Aggregate everything the Overview tab + chart cards need."""
        campaign = await self.get_campaign(campaign_id)
        if campaign is None:
            return None

        # Counts.
        kit_count = (await self.db.execute(
            select(func.count(campaign_kits.c.kit_id))
            .where(campaign_kits.c.campaign_id == campaign_id)
        )).scalar_one()

        actor_count = (await self.db.execute(
            select(func.count(campaign_actors.c.actor_id))
            .where(campaign_actors.c.campaign_id == campaign_id)
        )).scalar_one()

        # Distinct families sharing any kit with this campaign.
        family_count = (await self.db.execute(
            select(func.count(func.distinct(family_kits.c.family_id)))
            .select_from(campaign_kits)
            .join(family_kits, family_kits.c.kit_id == campaign_kits.c.kit_id)
            .where(campaign_kits.c.campaign_id == campaign_id)
        )).scalar_one()

        indicator_count = (await self.db.execute(
            select(func.count(Indicator.id))
            .select_from(Indicator)
            .join(campaign_kits, campaign_kits.c.kit_id == Indicator.kit_id)
            .where(campaign_kits.c.campaign_id == campaign_id)
        )).scalar_one()

        # Distinct victims observed in any kit attributed to this
        # campaign — the PhishPrint integration headline number.
        victim_count = (await self.db.execute(
            select(func.count(func.distinct(KitVictim.victim_id)))
            .select_from(KitVictim)
            .join(campaign_kits, campaign_kits.c.kit_id == KitVictim.kit_id)
            .where(campaign_kits.c.campaign_id == campaign_id)
        )).scalar_one()

        # Computed first/last seen.
        seen_row = (await self.db.execute(
            select(
                func.min(Kit.created_at).label("first_seen"),
                func.max(Kit.created_at).label("last_seen"),
            )
            .join(campaign_kits, campaign_kits.c.kit_id == Kit.id)
            .where(campaign_kits.c.campaign_id == campaign_id)
        )).one()

        # Top deploying actors — actors attributed to kits in this
        # campaign (kit-level kit_actors, NOT the curated
        # campaign_actors junction).  Same dual-attribution pattern
        # as FamilyService.
        top_actor_rows = (await self.db.execute(
            select(
                Actor.id,
                Actor.name,
                func.count(func.distinct(Kit.id)).label("count"),
            )
            .select_from(Kit)
            .join(campaign_kits, campaign_kits.c.kit_id == Kit.id)
            .join(kit_actors, kit_actors.c.kit_id == Kit.id)
            .join(Actor, Actor.id == kit_actors.c.actor_id)
            .where(campaign_kits.c.campaign_id == campaign_id)
            .group_by(Actor.id, Actor.name)
            .order_by(desc("count"))
            .limit(10)
        )).all()

        # Top families — families sharing kits with this campaign,
        # ranked by shared kit count.
        top_family_rows = (await self.db.execute(
            select(
                Family.id,
                Family.name,
                func.count(func.distinct(Kit.id)).label("count"),
            )
            .select_from(Kit)
            .join(campaign_kits, campaign_kits.c.kit_id == Kit.id)
            .join(family_kits, family_kits.c.kit_id == Kit.id)
            .join(Family, Family.id == family_kits.c.family_id)
            .where(campaign_kits.c.campaign_id == campaign_id)
            .group_by(Family.id, Family.name)
            .order_by(desc("count"))
            .limit(10)
        )).all()

        # Top victims — victims observed across the most kits in this
        # campaign.  Surfaces "this campaign mostly targets so-and-so"
        # signal for the PhishPrint operator.
        top_victim_rows = (await self.db.execute(
            select(
                Victim.id,
                Victim.email,
                Victim.display_name,
                Victim.type,
                func.count(func.distinct(KitVictim.kit_id)).label("count"),
            )
            .select_from(KitVictim)
            .join(Victim, Victim.id == KitVictim.victim_id)
            .join(campaign_kits, campaign_kits.c.kit_id == KitVictim.kit_id)
            .where(campaign_kits.c.campaign_id == campaign_id)
            .group_by(Victim.id, Victim.email, Victim.display_name, Victim.type)
            .order_by(desc("count"))
            .limit(10)
        )).all()

        # Timeline — kits per month bucket.
        timeline_rows = (await self.db.execute(
            select(
                func.date_trunc("month", Kit.created_at).label("bucket"),
                func.count(Kit.id).label("count"),
            )
            .join(campaign_kits, campaign_kits.c.kit_id == Kit.id)
            .where(campaign_kits.c.campaign_id == campaign_id)
            .group_by("bucket")
            .order_by("bucket")
        )).all()

        # Top indicators across the campaign's kits.
        top_indicators = (await self.db.execute(
            select(
                Indicator.type,
                Indicator.value,
                func.count(Indicator.id).label("count"),
            )
            .select_from(Indicator)
            .join(campaign_kits, campaign_kits.c.kit_id == Indicator.kit_id)
            .where(campaign_kits.c.campaign_id == campaign_id)
            .group_by(Indicator.type, Indicator.value)
            .order_by(desc("count"), Indicator.value)
            .limit(20)
        )).all()

        # Top YARA rules — Python-side aggregation.
        yara_top = (await self._yara_rule_counts(campaign_id))[:20]

        # Victim source-channel breakdown — which of the
        # OAuth/EML/AITM channels the campaign is hitting victims via.
        # Useful for "this campaign is purely AITM via login_hint
        # smuggling" etc.  Not gated on victim count > 0; an empty
        # list cleanly renders to "no victims yet."
        source_rows = (await self.db.execute(
            select(
                KitVictim.source,
                func.count(KitVictim.id).label("count"),
            )
            .select_from(KitVictim)
            .join(campaign_kits, campaign_kits.c.kit_id == KitVictim.kit_id)
            .where(campaign_kits.c.campaign_id == campaign_id)
            .group_by(KitVictim.source)
            .order_by(desc("count"))
        )).all()

        return {
            "kit_count": kit_count,
            "actor_count": actor_count,
            "family_count": family_count,
            "indicator_count": indicator_count,
            "victim_count": victim_count,
            "first_seen_computed": seen_row.first_seen,
            "last_seen_computed": seen_row.last_seen,
            "top_actors": [
                {"actor_id": r.id, "actor_name": r.name, "count": r.count}
                for r in top_actor_rows
            ],
            "top_families": [
                {"family_id": r.id, "family_name": r.name, "count": r.count}
                for r in top_family_rows
            ],
            "top_victims": [
                {
                    "victim_id": r.id,
                    "email": r.email,
                    "display_name": r.display_name,
                    "type": r.type.value,
                    "count": r.count,
                }
                for r in top_victim_rows
            ],
            "top_yara_rules": [
                {"rule": rule, "count": count} for rule, count in yara_top
            ],
            "timeline": [
                {
                    "month": r.bucket.strftime("%Y-%m") if r.bucket else None,
                    "count": r.count,
                }
                for r in timeline_rows
                if r.bucket is not None
            ],
            "top_indicators": [
                {
                    "type": r.type.value,
                    "value": r.value,
                    "count": r.count,
                }
                for r in top_indicators
            ],
            "victim_source_breakdown": [
                {"source": r.source.value, "count": r.count}
                for r in source_rows
            ],
        }

    # ---------------------------------------------------------------------
    # Paginated drill-downs.
    # ---------------------------------------------------------------------

    async def list_kits(
        self,
        campaign_id: uuid.UUID,
        offset: int = 0,
        limit: int = 50,
        status: str | None = None,
    ) -> tuple[list[Kit], int]:
        query = (
            select(Kit)
            .join(campaign_kits, campaign_kits.c.kit_id == Kit.id)
            .where(campaign_kits.c.campaign_id == campaign_id)
            .order_by(Kit.created_at.desc())
        )
        count_query = (
            select(func.count(Kit.id))
            .join(campaign_kits, campaign_kits.c.kit_id == Kit.id)
            .where(campaign_kits.c.campaign_id == campaign_id)
        )
        if status:
            query = query.where(Kit.status == status)
            count_query = count_query.where(Kit.status == status)
        total = (await self.db.execute(count_query)).scalar_one()
        result = await self.db.execute(query.offset(offset).limit(limit))
        return list(result.scalars().all()), total

    async def list_indicators(
        self,
        campaign_id: uuid.UUID,
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[list[Indicator], int]:
        """IOCs from kits in this campaign — reach via campaign_kits."""
        query = (
            select(Indicator)
            .join(campaign_kits, campaign_kits.c.kit_id == Indicator.kit_id)
            .where(campaign_kits.c.campaign_id == campaign_id)
            .order_by(Indicator.created_at.desc())
        )
        count_query = (
            select(func.count(Indicator.id))
            .select_from(Indicator)
            .join(campaign_kits, campaign_kits.c.kit_id == Indicator.kit_id)
            .where(campaign_kits.c.campaign_id == campaign_id)
        )
        total = (await self.db.execute(count_query)).scalar_one()
        result = await self.db.execute(query.offset(offset).limit(limit))
        return list(result.scalars().all()), total

    async def list_victims(
        self,
        campaign_id: uuid.UUID,
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[list[Victim], int]:
        """Distinct victims observed in any kit attributed to this
        campaign.  Reach: ``kit_victims → campaign_kits``.

        ``DISTINCT`` is necessary because a single victim is often
        observed in multiple kits — we want one row per victim, not
        per-(kit, victim) pair.  Pagination on the de-duplicated set,
        ordered by most-recently-seen first.
        """
        # Subquery: distinct victim_id + max observed_at per victim
        # within this campaign's kit set.  Ordering by max observation
        # gives a stable "fresh hits at the top" feel on the tab.
        latest_per_victim = (
            select(
                KitVictim.victim_id.label("victim_id"),
                func.max(KitVictim.observed_at).label("latest"),
            )
            .join(campaign_kits, campaign_kits.c.kit_id == KitVictim.kit_id)
            .where(campaign_kits.c.campaign_id == campaign_id)
            .group_by(KitVictim.victim_id)
            .subquery()
        )

        total = (await self.db.execute(
            select(func.count()).select_from(latest_per_victim)
        )).scalar_one()

        rows = await self.db.execute(
            select(Victim)
            .join(latest_per_victim, latest_per_victim.c.victim_id == Victim.id)
            .order_by(latest_per_victim.c.latest.desc())
            .offset(offset)
            .limit(limit)
        )
        return list(rows.scalars().all()), total

    async def list_actors(self, campaign_id: uuid.UUID) -> list[Actor]:
        """Actors curated as members of this campaign
        (``campaign_actors`` junction).  Distinct from the kit-level
        ``kit_actors`` deploy attribution surfaced on the Overview
        tab as 'top deploying actors'."""
        result = await self.db.execute(
            select(Actor)
            .join(campaign_actors, campaign_actors.c.actor_id == Actor.id)
            .where(campaign_actors.c.campaign_id == campaign_id)
            .order_by(Actor.name)
        )
        return list(result.scalars().all())

    async def list_families(self, campaign_id: uuid.UUID) -> list[Family]:
        """Families sharing at least one kit with this campaign."""
        result = await self.db.execute(
            select(Family)
            .distinct()
            .select_from(Family)
            .join(family_kits, family_kits.c.family_id == Family.id)
            .join(campaign_kits, campaign_kits.c.kit_id == family_kits.c.kit_id)
            .where(campaign_kits.c.campaign_id == campaign_id)
            .order_by(Family.name)
        )
        return list(result.scalars().all())

    async def list_yara_rules(self, campaign_id: uuid.UUID) -> list[dict]:
        """Aggregated YARA-rule hit counts across the campaign's kits."""
        rows = await self._yara_rule_counts(campaign_id)
        return [{"rule": rule, "count": count} for rule, count in rows]
