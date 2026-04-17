"""Add TELEGRAM_HANDLE indicator type and remap old mis-typed handle rows.

Revision ID: p6l2m3n4o5g7
Revises: o5k1l2m3n4f6
Create Date: 2026-04-16

Handles were previously stored under TELEGRAM_CHAT_ID because no dedicated
enum value existed (see ioc_engine._extract_telegram_handles comment:
"Re-use existing type for handles").  That corrupted counts and filtering —
a real Telegram chat ID and a stray JS decorator like "@build" landed in
the same bucket.  This migration adds the proper enum value and remaps
existing rows whose value starts with "@" to it.
"""
from alembic import op

revision = "p6l2m3n4o5g7"
down_revision = "o5k1l2m3n4f6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add the enum value (PostgreSQL requires commit between ADD VALUE and
    # subsequent usage in some versions; Alembic runs upgrade() in its own
    # transaction, so use ADD VALUE IF NOT EXISTS with an outer DO block).
    op.execute(
        """
        DO $$
        BEGIN
            ALTER TYPE indicatortype ADD VALUE IF NOT EXISTS 'TELEGRAM_HANDLE';
        END$$;
        """
    )
    # PostgreSQL disallows using a newly-added enum value in the same
    # transaction that created it.  Commit before re-typing existing rows.
    op.execute("COMMIT")

    # Remap rows that were stored as TELEGRAM_CHAT_ID but carry an "@handle"
    # value — those were handles misclassified by the old extractor.
    op.execute(
        """
        UPDATE indicators
        SET type = 'TELEGRAM_HANDLE'
        WHERE type = 'TELEGRAM_CHAT_ID'
          AND value LIKE '@%';
        """
    )


def downgrade() -> None:
    # PostgreSQL cannot drop an enum value in-place.  Remap rows back to
    # TELEGRAM_CHAT_ID and rename the value so future upgrades can recreate
    # it cleanly (same pattern used elsewhere in this migration chain).
    op.execute(
        """
        UPDATE indicators
        SET type = 'TELEGRAM_CHAT_ID'
        WHERE type = 'TELEGRAM_HANDLE';
        """
    )
    op.execute(
        """
        ALTER TYPE indicatortype RENAME VALUE 'TELEGRAM_HANDLE'
            TO '__REMOVED_TELEGRAM_HANDLE';
        """
    )
