"""Family business logic.

The ``get_stats`` + drill-down methods mirror ``ActorService``: one
bundled aggregation for the Overview tab and per-tab paginated
endpoints for Kits / YARA / Indicators / Actors / Campaigns on the
rebuilt family-detail page.

Junction reach matrix (mirrors the actor-service contract):

  - kit count, polymorphism, timeline, top YARA, top actors, top
    indicators all reach ``family_kits``
  - actor list (Actors tab) uses ``family_actors`` (analyst-curated
    direct link)
  - campaign list uses ``campaign_kits`` joined through ``family_kits``
    (campaigns sharing kits with this family)
"""

import uuid
from collections import defaultdict

from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from darla.models.actor import Actor
from darla.models.analysis_result import AnalysisResult, AnalysisType
from darla.models.associations import (
    campaign_kits,
    family_actors,
    family_kits,
    kit_actors,
)
from darla.models.campaign import Campaign
from darla.models.family import Family
from darla.models.indicator import Indicator
from darla.models.kit import Kit


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
        """Mutate operator-editable fields.

        Refresh after flush so the post-update ``updated_at`` lands in
        memory before pydantic serializes — see the
        MissingGreenlet-on-async-lazyload bug fixed in PR #75.
        """
        family = await self.get_family(family_id)
        if not family:
            return None
        for key, value in data.items():
            if value is not None:
                setattr(family, key, value)
        await self.db.flush()
        await self.db.refresh(family)
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

    # ---------------------------------------------------------------------
    # YARA aggregation helper.
    #
    # Each YARA_SCAN AnalysisResult row stores ``result_data["matches"]``
    # as a JSONB array of ``{"rule": "...", ...}`` objects.  Aggregating
    # in Python (rather than ``jsonb_array_elements`` lateral-join SQL)
    # keeps the implementation portable and avoids SQLAlchemy
    # lateral-join gymnastics.  At family scale (a few hundred kits
    # max per family) the round-trip cost is negligible.
    # ---------------------------------------------------------------------

    async def _yara_rule_counts(
        self, family_id: uuid.UUID
    ) -> list[tuple[str, int]]:
        """Return ``(rule_name, kit_count)`` tuples sorted by count
        desc, name asc.  Aggregation done in Python — see module
        docstring for rationale."""
        rows = (await self.db.execute(
            select(AnalysisResult.kit_id, AnalysisResult.result_data)
            .join(Kit, Kit.id == AnalysisResult.kit_id)
            .join(family_kits, family_kits.c.kit_id == Kit.id)
            .where(
                family_kits.c.family_id == family_id,
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
    # Stats — drives the rebuilt family-detail page's Overview tab.
    # ---------------------------------------------------------------------

    async def get_stats(self, family_id: uuid.UUID) -> dict | None:
        """Aggregate everything the Overview tab + chart cards need.

        One bundled call to keep round-trip count down on page load —
        same rationale as ``ActorService.get_stats``.
        """
        family = await self.get_family(family_id)
        if family is None:
            return None

        # Counts — straight COUNT against junctions.
        kit_count = (await self.db.execute(
            select(func.count(family_kits.c.kit_id))
            .where(family_kits.c.family_id == family_id)
        )).scalar_one()

        actor_count = (await self.db.execute(
            select(func.count(family_actors.c.actor_id))
            .where(family_actors.c.family_id == family_id)
        )).scalar_one()

        # Distinct campaigns sharing any kit with this family.
        campaign_count = (await self.db.execute(
            select(func.count(func.distinct(campaign_kits.c.campaign_id)))
            .select_from(family_kits)
            .join(campaign_kits, campaign_kits.c.kit_id == family_kits.c.kit_id)
            .where(family_kits.c.family_id == family_id)
        )).scalar_one()

        # Indicator count — IOCs from kits in this family.
        indicator_count = (await self.db.execute(
            select(func.count(Indicator.id))
            .select_from(Indicator)
            .join(family_kits, family_kits.c.kit_id == Indicator.kit_id)
            .where(family_kits.c.family_id == family_id)
        )).scalar_one()

        # Polymorphism signal — how many distinct binaries vs distinct
        # near-duplicate clusters.  A high kit_count with a low
        # distinct_sha256_count means the actor is repackaging the
        # same file; high distinct_sha256_count with low
        # distinct_tlsh_count means recompiles of the same source.
        distinct_sha256_count = (await self.db.execute(
            select(func.count(func.distinct(Kit.sha256)))
            .join(family_kits, family_kits.c.kit_id == Kit.id)
            .where(
                family_kits.c.family_id == family_id,
                Kit.sha256.is_not(None),
            )
        )).scalar_one()

        distinct_tlsh_count = (await self.db.execute(
            select(func.count(func.distinct(Kit.tlsh)))
            .join(family_kits, family_kits.c.kit_id == Kit.id)
            .where(
                family_kits.c.family_id == family_id,
                Kit.tlsh.is_not(None),
            )
        )).scalar_one()

        # Computed first/last seen — min/max of family kit timestamps.
        seen_row = (await self.db.execute(
            select(
                func.min(Kit.created_at).label("first_seen"),
                func.max(Kit.created_at).label("last_seen"),
            )
            .join(family_kits, family_kits.c.kit_id == Kit.id)
            .where(family_kits.c.family_id == family_id)
        )).one()

        # Target brand distribution — top 10.
        brand_rows = (await self.db.execute(
            select(
                Campaign.target_brand,
                func.count(func.distinct(Kit.id)).label("count"),
            )
            .select_from(Kit)
            .join(family_kits, family_kits.c.kit_id == Kit.id)
            .join(campaign_kits, campaign_kits.c.kit_id == Kit.id)
            .join(Campaign, Campaign.id == campaign_kits.c.campaign_id)
            .where(
                family_kits.c.family_id == family_id,
                Campaign.target_brand.is_not(None),
            )
            .group_by(Campaign.target_brand)
            .order_by(desc("count"))
            .limit(10)
        )).all()

        # Top deploying actors — actors attributed to kits in this
        # family (kit-level kit_actors junction, not the
        # family_actors curated link).  This is the "who's slinging
        # this kit" view, distinct from the analyst's curated
        # family→actor links shown on the Actors tab.
        top_actor_rows = (await self.db.execute(
            select(
                Actor.id,
                Actor.name,
                func.count(func.distinct(Kit.id)).label("count"),
            )
            .select_from(Kit)
            .join(family_kits, family_kits.c.kit_id == Kit.id)
            .join(kit_actors, kit_actors.c.kit_id == Kit.id)
            .join(Actor, Actor.id == kit_actors.c.actor_id)
            .where(family_kits.c.family_id == family_id)
            .group_by(Actor.id, Actor.name)
            .order_by(desc("count"))
            .limit(10)
        )).all()

        # Timeline — kits per month bucket (Postgres date_trunc).
        timeline_rows = (await self.db.execute(
            select(
                func.date_trunc("month", Kit.created_at).label("bucket"),
                func.count(Kit.id).label("count"),
            )
            .join(family_kits, family_kits.c.kit_id == Kit.id)
            .where(family_kits.c.family_id == family_id)
            .group_by("bucket")
            .order_by("bucket")
        )).all()

        # Top indicators — most frequent (type, value) pairs across
        # the family's kits.  Tells the analyst "this family's
        # signature C2 / drop email / wallet."
        top_indicators = (await self.db.execute(
            select(
                Indicator.type,
                Indicator.value,
                func.count(Indicator.id).label("count"),
            )
            .select_from(Indicator)
            .join(family_kits, family_kits.c.kit_id == Indicator.kit_id)
            .where(family_kits.c.family_id == family_id)
            .group_by(Indicator.type, Indicator.value)
            .order_by(desc("count"), Indicator.value)
            .limit(20)
        )).all()

        # Top YARA rules — Python-side aggregation, top 20.
        yara_top = (await self._yara_rule_counts(family_id))[:20]

        return {
            "kit_count": kit_count,
            "actor_count": actor_count,
            "campaign_count": campaign_count,
            "indicator_count": indicator_count,
            "distinct_sha256_count": distinct_sha256_count,
            "distinct_tlsh_count": distinct_tlsh_count,
            "first_seen_computed": seen_row.first_seen,
            "last_seen_computed": seen_row.last_seen,
            "target_brand_distribution": [
                {"brand": r.target_brand, "count": r.count}
                for r in brand_rows
            ],
            "top_actors": [
                {"actor_id": r.id, "actor_name": r.name, "count": r.count}
                for r in top_actor_rows
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
        }

    # ---------------------------------------------------------------------
    # Paginated drill-downs — Kits / YARA / Indicators tabs.
    # ---------------------------------------------------------------------

    async def list_kits(
        self,
        family_id: uuid.UUID,
        offset: int = 0,
        limit: int = 50,
        status: str | None = None,
    ) -> tuple[list[Kit], int]:
        query = (
            select(Kit)
            .join(family_kits, family_kits.c.kit_id == Kit.id)
            .where(family_kits.c.family_id == family_id)
            .order_by(Kit.created_at.desc())
        )
        count_query = (
            select(func.count(Kit.id))
            .join(family_kits, family_kits.c.kit_id == Kit.id)
            .where(family_kits.c.family_id == family_id)
        )
        if status:
            query = query.where(Kit.status == status)
            count_query = count_query.where(Kit.status == status)
        total = (await self.db.execute(count_query)).scalar_one()
        result = await self.db.execute(query.offset(offset).limit(limit))
        return list(result.scalars().all()), total

    async def list_indicators(
        self,
        family_id: uuid.UUID,
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[list[Indicator], int]:
        """IOCs extracted from kits in this family.  Indicators are
        scoped to a kit (not directly to a family); we reach through
        ``family_kits`` rather than denormalising a family_id column
        on Indicator."""
        query = (
            select(Indicator)
            .join(family_kits, family_kits.c.kit_id == Indicator.kit_id)
            .where(family_kits.c.family_id == family_id)
            .order_by(Indicator.created_at.desc())
        )
        count_query = (
            select(func.count(Indicator.id))
            .select_from(Indicator)
            .join(family_kits, family_kits.c.kit_id == Indicator.kit_id)
            .where(family_kits.c.family_id == family_id)
        )
        total = (await self.db.execute(count_query)).scalar_one()
        result = await self.db.execute(query.offset(offset).limit(limit))
        return list(result.scalars().all()), total

    async def list_yara_rules(self, family_id: uuid.UUID) -> list[dict]:
        """Aggregated YARA-rule hit counts across the family's kits.

        Returned sorted by count desc — drives the YARA tab's
        'rules anchoring this family' view.  Not paginated; a
        family rarely has more than ~30 distinct YARA rule hits and
        the operator wants the whole list visible at once.
        """
        rows = await self._yara_rule_counts(family_id)
        return [{"rule": rule, "count": count} for rule, count in rows]

    async def list_actors(self, family_id: uuid.UUID) -> list[Actor]:
        """Actors curated as members of this family
        (``family_actors`` junction).  This is the analyst's
        deliberate link, distinct from the kit-level ``kit_actors``
        deploy attribution surfaced on the Overview tab as
        'top deploying actors'."""
        result = await self.db.execute(
            select(Actor)
            .join(family_actors, family_actors.c.actor_id == Actor.id)
            .where(family_actors.c.family_id == family_id)
            .order_by(Actor.name)
        )
        return list(result.scalars().all())

    async def list_campaigns(self, family_id: uuid.UUID) -> list[Campaign]:
        """Campaigns that share at least one kit with this family.
        Reached via ``campaign_kits ∩ family_kits`` rather than a
        family↔campaign junction (which doesn't exist — campaigns
        link to families through their shared kit roster)."""
        result = await self.db.execute(
            select(Campaign)
            .distinct()
            .select_from(Campaign)
            .join(campaign_kits, campaign_kits.c.campaign_id == Campaign.id)
            .join(family_kits, family_kits.c.kit_id == campaign_kits.c.kit_id)
            .where(family_kits.c.family_id == family_id)
            .order_by(Campaign.name)
        )
        return list(result.scalars().all())
