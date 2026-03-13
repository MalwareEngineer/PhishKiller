"""Actor correlation task — auto-clusters kits by shared high-confidence IOCs."""

import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy import select

from phishkiller.celery_app import celery_app
from phishkiller.database import get_sync_db
from phishkiller.models.actor import Actor
from phishkiller.models.indicator import Indicator, IndicatorType
from phishkiller.models.kit import Kit

logger = logging.getLogger(__name__)

# Only correlate on IOC types that reliably identify an operator
CORRELATION_TYPES = {
    IndicatorType.EMAIL,
    IndicatorType.TELEGRAM_BOT_TOKEN,
    IndicatorType.SMTP_CREDENTIAL,
    IndicatorType.CRYPTOCURRENCY_WALLET,
}

# Minimum confidence to use an IOC for correlation
MIN_CORRELATION_CONFIDENCE = 80


@celery_app.task(
    name="phishkiller.tasks.correlation.correlate_kit_actors",
    bind=True,
    queue="analysis",
)
def correlate_kit_actors(self, prev_result: dict) -> dict:
    """Link kit indicators to actors based on shared high-confidence IOCs.

    For each high-confidence IOC in this kit, checks if the same IOC exists
    in other kits. If so, assigns the same actor (or creates a new one).
    """
    kit_id = prev_result["kit_id"]
    if prev_result.get("status") == "failed":
        return prev_result

    db = get_sync_db()

    try:
        kit = db.query(Kit).filter(Kit.id == uuid.UUID(kit_id)).first()
        if not kit:
            return prev_result

        # Get this kit's high-confidence correlatable indicators
        kit_indicators = db.scalars(
            select(Indicator).where(
                Indicator.kit_id == kit.id,
                Indicator.type.in_(CORRELATION_TYPES),
                Indicator.confidence >= MIN_CORRELATION_CONFIDENCE,
            )
        ).all()

        if not kit_indicators:
            return {**prev_result, "actors_linked": 0}

        actors_linked = 0
        actor_for_kit = None  # Track if we find/create an actor for this kit

        for indicator in kit_indicators:
            # Find matching indicators in OTHER kits
            matching = db.scalars(
                select(Indicator).where(
                    Indicator.type == indicator.type,
                    Indicator.value == indicator.value,
                    Indicator.kit_id != kit.id,
                    Indicator.confidence >= MIN_CORRELATION_CONFIDENCE,
                ).limit(20)
            ).all()

            if not matching:
                continue

            # Check if any matched indicator already has an actor
            existing_actor = None
            for match in matching:
                if match.actor_id:
                    existing_actor = db.query(Actor).filter(
                        Actor.id == match.actor_id
                    ).first()
                    if existing_actor:
                        break

            if existing_actor:
                actor = existing_actor
            elif actor_for_kit:
                # Reuse actor we already created/found for this kit
                actor = actor_for_kit
            else:
                # Create new actor
                short_id = str(kit.id)[:8].upper()
                actor = Actor(
                    name=f"ACTOR-{short_id}",
                    description=f"Auto-correlated from shared IOCs in kit {kit_id}",
                    first_seen=kit.created_at.strftime("%Y-%m-%d") if kit.created_at else None,
                )
                db.add(actor)
                db.flush()  # Get the actor ID

            actor_for_kit = actor

            # Link this indicator to the actor
            if not indicator.actor_id:
                indicator.actor_id = actor.id
                actors_linked += 1

            # Link matching indicators to the same actor
            for match in matching:
                if not match.actor_id:
                    match.actor_id = actor.id

        # Update actor metadata
        if actor_for_kit:
            _update_actor_metadata(db, actor_for_kit)

        db.commit()

        if actors_linked:
            logger.info(
                "Correlation for kit %s: linked %d indicators to actor %s",
                kit_id, actors_linked,
                actor_for_kit.name if actor_for_kit else "none",
            )

        return {
            **prev_result,
            "actors_linked": actors_linked,
            "actor_id": str(actor_for_kit.id) if actor_for_kit else None,
        }

    except Exception as e:
        logger.exception("Error correlating actors for kit %s: %s", kit_id, e)
        try:
            db.rollback()
        except Exception:
            pass
        # Correlation failure is non-fatal
        return {**prev_result, "actors_linked": 0}
    finally:
        db.close()


def _update_actor_metadata(db, actor: Actor) -> None:
    """Update actor's email_addresses, telegram_handles, and timestamps."""
    # Gather all linked indicators
    linked = db.scalars(
        select(Indicator).where(Indicator.actor_id == actor.id)
    ).all()

    emails = set(actor.email_addresses or [])
    handles = set(actor.telegram_handles or [])
    earliest = actor.first_seen
    latest = actor.last_seen

    for ind in linked:
        if ind.type == IndicatorType.EMAIL:
            emails.add(ind.value)
        elif ind.type == IndicatorType.TELEGRAM_BOT_TOKEN:
            handles.add(ind.value[:20] + "...")  # Truncate token for display

        # Update timestamps from linked kit
        if ind.kit and ind.kit.created_at:
            kit_date = ind.kit.created_at.strftime("%Y-%m-%d")
            if not earliest or kit_date < earliest:
                earliest = kit_date
            if not latest or kit_date > latest:
                latest = kit_date

    actor.email_addresses = list(emails) if emails else None
    actor.telegram_handles = list(handles) if handles else None
    actor.first_seen = earliest
    actor.last_seen = latest
