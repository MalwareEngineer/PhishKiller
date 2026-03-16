"""Chain crawler — submits child kits for scored links within an investigation."""

import logging
import uuid

from sqlalchemy.orm import Session

from phishkiller.models.kit import Kit, KitStatus

logger = logging.getLogger(__name__)


class ChainCrawler:
    """Submit child kits for links that scored above threshold."""

    def __init__(self, db: Session):
        self.db = db

    def submit_child_kits(
        self,
        parent_kit_id: uuid.UUID,
        investigation_id: uuid.UUID,
        scored_links: list,  # list[ScoredLink]
        current_depth: int,
    ) -> list[uuid.UUID]:
        """Create child Kit records and dispatch analysis chains.

        Returns list of created kit IDs.
        """
        from phishkiller.tasks.analysis import build_analysis_chain

        child_ids = []

        for link in scored_links:
            # Dedup: skip if we already have this URL in the investigation
            existing = self.db.query(Kit.id).filter(
                Kit.source_url == link.url,
                Kit.investigation_id == investigation_id,
                Kit.status != KitStatus.FAILED,
            ).first()
            if existing:
                logger.debug("Skipping duplicate URL in investigation: %s", link.url)
                continue

            kit = Kit(
                source_url=link.url,
                source_feed="investigation",
                status=KitStatus.PENDING,
                parent_kit_id=parent_kit_id,
                investigation_id=investigation_id,
                chain_depth=current_depth + 1,
                discovery_method=link.source,
            )
            self.db.add(kit)
            self.db.flush()  # Get the ID

            child_ids.append(kit.id)

            # Dispatch the full analysis chain for this child kit
            build_analysis_chain(str(kit.id)).apply_async()

            logger.info(
                "Spawned child kit %s (depth=%d, method=%s, score=%.2f): %s",
                kit.id, current_depth + 1, link.source, link.score, link.url,
            )

        self.db.commit()
        return child_ids
