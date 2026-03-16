#!/usr/bin/env python3
"""Round 4 false-positive IOC cleanup.

Purges stale indicators that the updated extraction patterns no longer produce:
  - SMTP_CREDENTIAL: HTML/JS junk values + SaaS host FPs
  - TELEGRAM_CHAT_ID: @handles in the exclusion set
  - C2_URL: benign domain URLs + localhost
  - IP_ADDRESS: network addresses (x.x.0.0, x.0.0.0)
  - DOMAIN: JS identifiers, i18n keys, console.* builtins
  - EMAIL: retina image refs (@2x.png etc.) + placeholder domains
  - CRYPTOCURRENCY_WALLET: MD5 hashes misidentified as wallets

Usage:
    python scripts/cleanup_false_positive_iocs_r4.py            # dry run
    python scripts/cleanup_false_positive_iocs_r4.py --execute   # delete
"""

import argparse

from sqlalchemy import text

from phishkiller.analysis.patterns import (
    BENIGN_URL_ROOT_DOMAINS,
    SMTP_HOST_EXCLUSIONS,
    TELEGRAM_HANDLE_EXCLUSIONS,
    extract_root_domain,
)
from phishkiller.database import get_sync_db


def main() -> None:
    parser = argparse.ArgumentParser(description="Round 4 IOC false-positive cleanup")
    parser.add_argument("--execute", action="store_true", help="Actually delete rows")
    args = parser.parse_args()

    db = get_sync_db()
    total_deleted = 0

    # --- SMTP credentials: known junk values ---
    # These are HTML attributes, JS fragments, and English words that the old
    # broad regex captured before PR#21 tightened it.
    smtp_junk_prefixes = [
        "smtp_pass=name=", "smtp_pass=is", "smtp_pass=to",
        "smtp_pass=minlength=", "smtp_pass=update", "smtp_pass=without",
        "smtp_pass=id=", "smtp_pass=[{icon:", "smtp_pass=class=",
        "smtp_pass=placeholder=", "smtp_pass=,", "smtp_pass={",
        "smtp_pass=was", "smtp_pass=the", "smtp_pass=not",
        "smtp_pass=and", "smtp_pass=for", "smtp_pass=are",
        "smtp_pass=this", "smtp_pass=that", "smtp_pass=with",
        "smtp_pass=from", "smtp_pass=your", "smtp_pass=have",
        "smtp_pass=will", "smtp_pass=been", "smtp_pass=type=",
        "smtp_pass=value=", "smtp_pass=required", "smtp_pass=maxlength=",
        "smtp_pass=autocomplete=", "smtp_pass=.val()",
    ]
    # SMTP host SaaS/JS exclusions
    smtp_host_junk = [f"smtp_host={h}" for h in SMTP_HOST_EXCLUSIONS]

    smtp_values = smtp_junk_prefixes + smtp_host_junk
    placeholders = ", ".join(f":v{i}" for i in range(len(smtp_values)))
    params = {f"v{i}": v for i, v in enumerate(smtp_values)}

    count = db.execute(
        text(f"SELECT COUNT(*) FROM indicators WHERE type = 'SMTP_CREDENTIAL' AND value IN ({placeholders})"),
        params,
    ).scalar()
    print(f"SMTP_CREDENTIAL junk values: {count:,}")
    total_deleted += count

    if args.execute and count:
        db.execute(
            text(f"DELETE FROM indicators WHERE type = 'SMTP_CREDENTIAL' AND value IN ({placeholders})"),
            params,
        )
        db.commit()
        print(f"  -> deleted {count:,}")

    # --- Telegram handles in exclusion set ---
    tg_exclusions = [f"@{h}" for h in TELEGRAM_HANDLE_EXCLUSIONS]
    placeholders = ", ".join(f":t{i}" for i in range(len(tg_exclusions)))
    params = {f"t{i}": v for i, v in enumerate(tg_exclusions)}

    count = db.execute(
        text(f"SELECT COUNT(*) FROM indicators WHERE type = 'TELEGRAM_CHAT_ID' AND value IN ({placeholders})"),
        params,
    ).scalar()
    print(f"TELEGRAM_CHAT_ID excluded handles: {count:,}")
    total_deleted += count

    if args.execute and count:
        db.execute(
            text(f"DELETE FROM indicators WHERE type = 'TELEGRAM_CHAT_ID' AND value IN ({placeholders})"),
            params,
        )
        db.commit()
        print(f"  -> deleted {count:,}")

    # --- C2_URL: localhost ---
    count = db.execute(
        text("SELECT COUNT(*) FROM indicators WHERE type = 'C2_URL' AND value LIKE 'http://localhost%'"),
    ).scalar()
    print(f"C2_URL localhost: {count:,}")
    total_deleted += count

    if args.execute and count:
        db.execute(text("DELETE FROM indicators WHERE type = 'C2_URL' AND value LIKE 'http://localhost%'"))
        db.commit()
        print(f"  -> deleted {count:,}")

    # --- C2_URL: newly-added benign domains ---
    # Find C2 URLs whose hostname root domain is now in the benign set
    # We do this in Python since SQL can't easily replicate root-domain extraction
    print("Scanning C2_URLs for newly-benign domains (this may take a moment)...")
    rows = db.execute(
        text("SELECT id, value FROM indicators WHERE type = 'C2_URL'")
    ).fetchall()

    benign_ids = []
    for row in rows:
        try:
            from urllib.parse import urlparse
            hostname = urlparse(row.value).hostname
            if hostname:
                root = extract_root_domain(hostname.lower())
                if root in BENIGN_URL_ROOT_DOMAINS:
                    benign_ids.append(str(row.id))
        except Exception:
            continue

    print(f"C2_URL benign domains (newly added): {len(benign_ids):,}")
    total_deleted += len(benign_ids)

    if args.execute and benign_ids:
        # Delete in batches of 5000
        for i in range(0, len(benign_ids), 5000):
            batch = benign_ids[i:i + 5000]
            placeholders = ", ".join(f":id{j}" for j in range(len(batch)))
            params = {f"id{j}": uid for j, uid in enumerate(batch)}
            db.execute(
                text(f"DELETE FROM indicators WHERE id::text IN ({placeholders})"),
                params,
            )
            db.commit()
        print(f"  -> deleted {len(benign_ids):,}")

    # --- IP_ADDRESS: network addresses (x.x.0.0, x.0.0.0) ---
    count = db.execute(
        text("SELECT COUNT(*) FROM indicators WHERE type = 'IP_ADDRESS' AND (value LIKE '%.0.0.0' OR value LIKE '%.0.0')"),
    ).scalar()
    # More precise: only x.x.0.0 and x.0.0.0 patterns
    count = db.execute(
        text("""
            SELECT COUNT(*) FROM indicators
            WHERE type = 'IP_ADDRESS'
            AND (
                value ~ '^[0-9]+[.][0-9]+[.]0[.]0$'
                OR value ~ '^[0-9]+[.]0[.]0[.]0$'
            )
        """),
    ).scalar()
    print(f"IP_ADDRESS network addresses: {count:,}")
    total_deleted += count

    if args.execute and count:
        db.execute(text("""
            DELETE FROM indicators
            WHERE type = 'IP_ADDRESS'
            AND (
                value ~ '^[0-9]+[.][0-9]+[.]0[.]0$'
                OR value ~ '^[0-9]+[.]0[.]0[.]0$'
            )
        """))
        db.commit()
        print(f"  -> deleted {count:,}")

    # --- DOMAIN: console.* JS builtins ---
    count = db.execute(
        text("SELECT COUNT(*) FROM indicators WHERE type = 'DOMAIN' AND value LIKE 'console.%'"),
    ).scalar()
    print(f"DOMAIN console.* builtins: {count:,}")
    total_deleted += count

    if args.execute and count:
        db.execute(text("DELETE FROM indicators WHERE type = 'DOMAIN' AND value LIKE 'console.%'"))
        db.commit()
        print(f"  -> deleted {count:,}")

    # --- DOMAIN: i18n key patterns (4+ labels with error/message/input) ---
    count = db.execute(
        text("""
            SELECT COUNT(*) FROM indicators
            WHERE type = 'DOMAIN'
            AND array_length(string_to_array(value, '.'), 1) >= 4
            AND (value LIKE '%.error.%' OR value LIKE '%.message.%' OR value LIKE '%.input.%')
        """),
    ).scalar()
    print(f"DOMAIN i18n key patterns: {count:,}")
    total_deleted += count

    if args.execute and count:
        db.execute(text("""
            DELETE FROM indicators
            WHERE type = 'DOMAIN'
            AND array_length(string_to_array(value, '.'), 1) >= 4
            AND (value LIKE '%.error.%' OR value LIKE '%.message.%' OR value LIKE '%.input.%')
        """))
        db.commit()
        print(f"  -> deleted {count:,}")

    # --- DOMAIN: single-word .id TLD (JS property access) ---
    count = db.execute(
        text("""
            SELECT COUNT(*) FROM indicators
            WHERE type = 'DOMAIN'
            AND value LIKE '%.id'
            AND array_length(string_to_array(value, '.'), 1) = 2
            AND value NOT LIKE '%-%'
        """),
    ).scalar()
    print(f"DOMAIN single-word .id FPs: {count:,}")
    total_deleted += count

    if args.execute and count:
        db.execute(text("""
            DELETE FROM indicators
            WHERE type = 'DOMAIN'
            AND value LIKE '%.id'
            AND array_length(string_to_array(value, '.'), 1) = 2
            AND value NOT LIKE '%-%'
        """))
        db.commit()
        print(f"  -> deleted {count:,}")

    # --- EMAIL: retina image refs (@2x.png, @3x.jpg, etc.) ---
    count = db.execute(
        text("SELECT COUNT(*) FROM indicators WHERE type = 'EMAIL' AND value ~ '@[0-9]+x?\\.'"),
    ).scalar()
    print(f"EMAIL retina image refs: {count:,}")
    total_deleted += count

    if args.execute and count:
        db.execute(text("DELETE FROM indicators WHERE type = 'EMAIL' AND value ~ '@[0-9]+x?\\.'"))
        db.commit()
        print(f"  -> deleted {count:,}")

    # --- EMAIL: placeholder domains ---
    placeholder_domains = ("mysite.com", "abc.com", "domain.com", "yoursite.com", "site.com")
    placeholders = ", ".join(f":p{i}" for i in range(len(placeholder_domains)))
    params = {f"p{i}": f"%@{d}" for i, d in enumerate(placeholder_domains)}
    # Build LIKE conditions
    like_conditions = " OR ".join(f"value LIKE :p{i}" for i in range(len(placeholder_domains)))

    count = db.execute(
        text(f"SELECT COUNT(*) FROM indicators WHERE type = 'EMAIL' AND ({like_conditions})"),
        params,
    ).scalar()
    print(f"EMAIL placeholder domains: {count:,}")
    total_deleted += count

    if args.execute and count:
        db.execute(
            text(f"DELETE FROM indicators WHERE type = 'EMAIL' AND ({like_conditions})"),
            params,
        )
        db.commit()
        print(f"  -> deleted {count:,}")

    # --- CRYPTOCURRENCY_WALLET: MD5 hashes (32 lowercase hex) ---
    count = db.execute(
        text("SELECT COUNT(*) FROM indicators WHERE type = 'CRYPTOCURRENCY_WALLET' AND value ~ '^[0-9a-f]{32}$'"),
    ).scalar()
    print(f"CRYPTOCURRENCY_WALLET MD5 hashes: {count:,}")
    total_deleted += count

    if args.execute and count:
        db.execute(
            text("DELETE FROM indicators WHERE type = 'CRYPTOCURRENCY_WALLET' AND value ~ '^[0-9a-f]{32}$'"),
        )
        db.commit()
        print(f"  -> deleted {count:,}")

    print(f"\nTotal rows to purge: {total_deleted:,}")
    if not args.execute:
        print("Dry run — pass --execute to delete. Exiting.")

    db.close()


if __name__ == "__main__":
    main()
