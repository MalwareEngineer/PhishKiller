"""Auto-campaign assignment task — groups kits by shared actor + tight TLSH similarity."""

import contextlib
import logging
import uuid
from datetime import UTC, datetime

from sqlalchemy import select

from phishkiller.celery_app import celery_app
from phishkiller.config import get_settings
from phishkiller.database import get_sync_db
from phishkiller.models.actor import Actor
from phishkiller.models.associations import campaign_actors, campaign_kits
from phishkiller.models.campaign import Campaign
from phishkiller.models.indicator import Indicator
from phishkiller.models.kit import Kit, KitStatus

logger = logging.getLogger(__name__)


@celery_app.task(
    name="phishkiller.tasks.campaigns.auto_assign_campaign",
    bind=True,
    queue="analysis",
)
def auto_assign_campaign(self, prev_result: dict) -> dict:
    """Auto-create or assign a campaign when kit shares an actor AND tight TLSH match.

    Requirements (both must be met):
    1. The kit was correlated to an actor (actor_id in prev_result)
    2. At least one kit from that same actor has TLSH distance ≤ threshold

    If a matching auto-generated campaign already exists for that actor, the
    kit is added to it.  Otherwise a new auto-generated campaign is created.
    """
    kit_id = prev_result["kit_id"]
    if prev_result.get("status") == "failed":
        return prev_result

    actor_id = prev_result.get("actor_id")
    if not actor_id:
        # No actor correlation — nothing to campaign-cluster
        return {**prev_result, "campaign_id": None}

    settings = get_settings()
    threshold = settings.campaign_tlsh_threshold
    db = get_sync_db()

    try:
        kit = db.query(Kit).filter(Kit.id == uuid.UUID(kit_id)).first()
        if not kit or not kit.tlsh:
            return {**prev_result, "campaign_id": None}

        actor = db.query(Actor).filter(Actor.id == uuid.UUID(actor_id)).first()
        if not actor:
            return {**prev_result, "campaign_id": None}

        # ------------------------------------------------------------------
        # Find other kits linked to the same actor via indicators
        # ------------------------------------------------------------------
        sibling_kit_ids = set(
            db.scalars(
                select(Indicator.kit_id)
                .where(
                    Indicator.actor_id == actor.id,
                    Indicator.kit_id != kit.id,
                    Indicator.kit_id.isnot(None),
                )
                .distinct()
            ).all()
        )

        if not sibling_kit_ids:
            return {**prev_result, "campaign_id": None}

        # ------------------------------------------------------------------
        # Check TLSH distance against sibling kits
        # ------------------------------------------------------------------
        from phishkiller.analysis.hasher import compute_tlsh_distance

        siblings = db.scalars(
            select(Kit).where(
                Kit.id.in_(sibling_kit_ids),
                Kit.tlsh.isnot(None),
                Kit.status == KitStatus.ANALYZED,
            )
        ).all()

        tight_matches: list[Kit] = []
        for sibling in siblings:
            distance = compute_tlsh_distance(kit.tlsh, sibling.tlsh)
            if distance is not None and distance <= threshold:
                tight_matches.append(sibling)

        if not tight_matches:
            return {**prev_result, "campaign_id": None}

        # ------------------------------------------------------------------
        # Find existing auto-generated campaign for this actor
        # ------------------------------------------------------------------
        existing_campaign = db.execute(
            select(Campaign)
            .join(campaign_actors, campaign_actors.c.campaign_id == Campaign.id)
            .where(
                campaign_actors.c.actor_id == actor.id,
                Campaign.auto_generated.is_(True),
            )
            .limit(1)
        ).scalar_one_or_none()

        today = datetime.now(UTC).strftime("%Y-%m-%d")

        if existing_campaign:
            campaign = existing_campaign
            # Update end_date to today (campaign is still active)
            campaign.end_date = today
        else:
            # Create new auto-generated campaign
            short_actor = actor.name or str(actor.id)[:8].upper()
            campaign = Campaign(
                name=f"AUTO-{short_actor}-{today}",
                description=(
                    f"Auto-generated campaign for actor {actor.name}. "
                    f"Kits share TLSH distance ≤{threshold}."
                ),
                auto_generated=True,
                start_date=today,
                end_date=today,
            )
            db.add(campaign)
            db.flush()

            # Link actor to campaign
            db.execute(
                campaign_actors.insert().values(
                    campaign_id=campaign.id, actor_id=actor.id
                )
            )

        # ------------------------------------------------------------------
        # Add this kit to the campaign (if not already linked)
        # ------------------------------------------------------------------
        already_linked = db.execute(
            select(campaign_kits.c.kit_id).where(
                campaign_kits.c.campaign_id == campaign.id,
                campaign_kits.c.kit_id == kit.id,
            )
        ).first()

        if not already_linked:
            db.execute(
                campaign_kits.insert().values(
                    campaign_id=campaign.id, kit_id=kit.id
                )
            )

        # Also add tight-match siblings that aren't already in the campaign
        for sibling in tight_matches:
            exists = db.execute(
                select(campaign_kits.c.kit_id).where(
                    campaign_kits.c.campaign_id == campaign.id,
                    campaign_kits.c.kit_id == sibling.id,
                )
            ).first()
            if not exists:
                db.execute(
                    campaign_kits.insert().values(
                        campaign_id=campaign.id, kit_id=sibling.id
                    )
                )

        db.commit()

        logger.info(
            "Campaign %s (%s) — kit %s added with %d tight TLSH matches "
            "(actor=%s, threshold=%d)",
            campaign.id,
            campaign.name,
            kit_id,
            len(tight_matches),
            actor.name,
            threshold,
        )

        return {
            **prev_result,
            "campaign_id": str(campaign.id),
            "campaign_name": campaign.name,
            "campaign_new": existing_campaign is None,
            "campaign_tight_matches": len(tight_matches),
        }

    except Exception as e:
        logger.exception("Error auto-assigning campaign for kit %s: %s", kit_id, e)
        with contextlib.suppress(Exception):
            db.rollback()
        # Campaign failure is non-fatal
        return {**prev_result, "campaign_id": None}
    finally:
        db.close()
