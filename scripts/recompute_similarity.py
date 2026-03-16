#!/usr/bin/env python3
"""One-time full recomputation of TLSH similarity across all analyzed kits.

Loads all TLSH hashes into memory and computes the full N*(N-1)/2 pairwise
distance matrix, then bulk upserts SIMILARITY analysis results.

Much faster than dispatching N individual Celery tasks — a single process
doing ~310M tlsh.diff() calls in C takes ~5-10 minutes vs hours of DB churn.

Usage:
    # Dry run (default) — shows stats without writing
    python scripts/recompute_similarity.py

    # Actually write results
    python scripts/recompute_similarity.py --execute
"""

import argparse
import sys
import time
import uuid
from collections import defaultdict

import tlsh
from sqlalchemy import text

from phishkiller.database import get_sync_db

THRESHOLD = 100
MAX_SIMILAR_PER_KIT = 50  # cap stored results per kit


def main() -> None:
    parser = argparse.ArgumentParser(description="Recompute TLSH similarity for all kits")
    parser.add_argument("--execute", action="store_true", help="Actually write results")
    args = parser.parse_args()

    db = get_sync_db()

    # Step 1: Load all (id, tlsh, sha256, source_url) into memory
    print("Loading TLSH hashes from database...")
    rows = db.execute(
        text(
            "SELECT id, tlsh, sha256, source_url FROM kits "
            "WHERE status = 'ANALYZED' AND tlsh IS NOT NULL"
        )
    ).fetchall()
    n = len(rows)
    total_pairs = n * (n - 1) // 2
    print(f"Loaded {n:,} kits with TLSH hashes ({total_pairs:,} pairs to compare)")

    if n == 0:
        print("No kits to compare.")
        return

    # Step 2: Compute full pairwise distances
    print("Computing pairwise TLSH distances (threshold <= %d)..." % THRESHOLD)
    start = time.monotonic()

    # Build similarity map: kit_id -> list of {kit_id, distance, sha256, source_url}
    similarity: dict[str, list[dict]] = defaultdict(list)
    checked = 0
    matches = 0

    for i in range(n):
        for j in range(i + 1, n):
            distance = tlsh.diff(rows[i].tlsh, rows[j].tlsh)
            checked += 1
            if distance <= THRESHOLD:
                matches += 1
                kit_a = str(rows[i].id)
                kit_b = str(rows[j].id)
                similarity[kit_a].append({
                    "kit_id": kit_b,
                    "distance": distance,
                    "sha256": rows[j].sha256,
                    "source_url": rows[j].source_url,
                })
                similarity[kit_b].append({
                    "kit_id": kit_a,
                    "distance": distance,
                    "sha256": rows[i].sha256,
                    "source_url": rows[i].source_url,
                })

            if checked % 50_000_000 == 0:
                elapsed = time.monotonic() - start
                rate = checked / elapsed
                eta = (total_pairs - checked) / rate
                print(
                    f"  {checked:>12,}/{total_pairs:,} pairs "
                    f"({100*checked/total_pairs:.1f}%) "
                    f"matches={matches:,}  "
                    f"rate={rate:,.0f}/s  ETA={eta:.0f}s"
                )

    elapsed = time.monotonic() - start
    print(
        f"Done: {checked:,} pairs in {elapsed:.1f}s "
        f"({checked/elapsed:,.0f}/s), {matches:,} matches"
    )

    # Sort each kit's matches by distance
    kits_with_matches = 0
    for kit_id in similarity:
        similarity[kit_id].sort(key=lambda x: x["distance"])
        similarity[kit_id] = similarity[kit_id][:MAX_SIMILAR_PER_KIT]
        kits_with_matches += 1

    print(f"{kits_with_matches:,} kits have at least one similar kit")

    if not args.execute:
        print("\nDry run — pass --execute to write results. Exiting.")
        return

    # Step 3: Delete old SIMILARITY results and bulk insert new ones
    print("Deleting old SIMILARITY analysis results...")
    deleted = db.execute(
        text("DELETE FROM analysis_results WHERE analysis_type = 'SIMILARITY'")
    )
    print(f"Deleted {deleted.rowcount:,} old results")

    print("Inserting new SIMILARITY results...")
    insert_count = 0
    batch = []

    for kit_id, similar in similarity.items():
        batch.append({
            "id": str(uuid.uuid4()),
            "kit_id": kit_id,
            "analysis_type": "SIMILARITY",
            "result_data": {
                "similar_kits": similar,
                "candidates_checked": n - 1,
                "threshold": THRESHOLD,
                "matches_found": len(similar),
            },
            "duration_seconds": round(elapsed / n, 3),
        })
        insert_count += 1

        if len(batch) >= 500:
            _insert_batch(db, batch)
            batch = []

    if batch:
        _insert_batch(db, batch)

    db.commit()
    print(f"Inserted {insert_count:,} SIMILARITY results")
    db.close()


def _insert_batch(db, batch: list[dict]) -> None:
    """Insert a batch of analysis results."""
    import json
    for row in batch:
        db.execute(
            text(
                "INSERT INTO analysis_results (id, kit_id, analysis_type, result_data, duration_seconds) "
                "VALUES (:id, :kit_id, :analysis_type, :result_data, :duration_seconds)"
            ),
            {
                "id": row["id"],
                "kit_id": row["kit_id"],
                "analysis_type": row["analysis_type"],
                "result_data": json.dumps(row["result_data"]),
                "duration_seconds": row["duration_seconds"],
            },
        )


if __name__ == "__main__":
    main()
