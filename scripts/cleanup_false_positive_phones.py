#!/usr/bin/env python3
"""One-time cleanup of false positive PHONE_NUMBER indicators.

Deletes phone numbers that fail the tightened validation:
  - Digit count < 9 (too short to be meaningful)
  - Digit count > 13 (JS/CSS numeric garbage)
  - Unbalanced closing paren (mangled CSS/JS fragments)

Usage:
    # Dry run (default)
    python scripts/cleanup_false_positive_phones.py

    # Actually delete
    python scripts/cleanup_false_positive_phones.py --execute
"""

import argparse

from sqlalchemy import text

from phishkiller.database import get_sync_db


def main() -> None:
    parser = argparse.ArgumentParser(description="Cleanup false positive phone IOCs")
    parser.add_argument("--execute", action="store_true", help="Actually delete")
    args = parser.parse_args()

    db = get_sync_db()

    # Count what would be deleted
    result = db.execute(text("""
        SELECT COUNT(*) FROM indicators
        WHERE type = 'PHONE_NUMBER'
        AND (
            LENGTH(regexp_replace(value, '[^0-9]', '', 'g')) < 9
            OR LENGTH(regexp_replace(value, '[^0-9]', '', 'g')) > 13
            OR value ~ '\\)[^(]'
        )
    """)).scalar()

    total = db.execute(text(
        "SELECT COUNT(*) FROM indicators WHERE type = 'PHONE_NUMBER'"
    )).scalar()

    print(f"PHONE_NUMBER indicators: {total:,} total, {result:,} false positives ({100*result/total:.0f}%)")

    if not args.execute:
        print("Dry run — pass --execute to delete. Exiting.")
        return

    deleted = db.execute(text("""
        DELETE FROM indicators
        WHERE type = 'PHONE_NUMBER'
        AND (
            LENGTH(regexp_replace(value, '[^0-9]', '', 'g')) < 9
            OR LENGTH(regexp_replace(value, '[^0-9]', '', 'g')) > 13
            OR value ~ '\\)[^(]'
        )
    """))
    db.commit()
    print(f"Deleted {deleted.rowcount:,} false positive phone indicators")
    db.close()


if __name__ == "__main__":
    main()
