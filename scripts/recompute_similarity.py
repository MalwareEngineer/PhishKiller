#!/usr/bin/env python3
"""Recompute TLSH similarity for all analyzed kits via Celery.

Deletes stale SIMILARITY analysis results, then dispatches individual
compute_similarity tasks through the analysis queue. Each task loads
~25K TLSH hashes and does ~25K tlsh.diff() calls (~50ms), so the full
backfill takes ~10 minutes at 45 tasks/sec.

Usage:
    # Dry run (default) — shows what would be dispatched
    python scripts/recompute_similarity.py

    # Actually dispatch
    python scripts/recompute_similarity.py --execute
"""

import argparse

from sqlalchemy import text

from phishkiller.celery_app import celery_app
from phishkiller.database import get_sync_db


def main() -> None:
    parser = argparse.ArgumentParser(description="Recompute TLSH similarity for all kits")
    parser.add_argument("--execute", action="store_true", help="Actually dispatch tasks")
    args = parser.parse_args()

    db = get_sync_db()

    # Get all analyzed kits with TLSH hashes
    kit_ids = db.execute(
        text(
            "SELECT id FROM kits "
            "WHERE status = 'ANALYZED' AND tlsh IS NOT NULL"
        )
    ).fetchall()
    n = len(kit_ids)
    print(f"Found {n:,} analyzed kits with TLSH hashes")

    if n == 0:
        print("Nothing to do.")
        return

    if not args.execute:
        # Count existing stale results
        stale = db.execute(
            text("SELECT COUNT(*) FROM analysis_results WHERE analysis_type = 'SIMILARITY'")
        ).scalar()
        print(f"Stale SIMILARITY results to delete: {stale:,}")
        print(f"Tasks to dispatch: {n:,}")
        print(f"Estimated time at 45 tasks/sec: ~{n / 45:.0f}s")
        print("\nDry run — pass --execute to dispatch. Exiting.")
        return

    # Delete old similarity results
    deleted = db.execute(
        text("DELETE FROM analysis_results WHERE analysis_type = 'SIMILARITY'")
    )
    db.commit()
    print(f"Deleted {deleted.rowcount:,} stale SIMILARITY results")

    # Dispatch compute_similarity for each kit
    print(f"Dispatching {n:,} compute_similarity tasks...")
    for i, row in enumerate(kit_ids):
        celery_app.send_task(
            "phishkiller.tasks.analysis.compute_similarity",
            args=[{"kit_id": str(row.id), "status": "analyzed"}],
            queue="analysis",
        )
        if (i + 1) % 5000 == 0:
            print(f"  dispatched {i + 1:,}/{n:,}")

    print(f"Done — dispatched {n:,} tasks to analysis queue")
    db.close()


if __name__ == "__main__":
    main()
