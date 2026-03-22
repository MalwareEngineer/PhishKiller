"""Add SOURCE_URL indicator type for tracking kit source URLs as IOCs.

Revision ID: h8d4e5f6a7b9
Revises: g7c3d4e5f6a8
Create Date: 2026-03-22 00:00:00.000000
"""
from alembic import op

revision = "h8d4e5f6a7b9"
down_revision = "g7c3d4e5f6a8"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Fix: must use uppercase name to match SQLAlchemy Enum(IndicatorType)
    # which stores members by .name (SOURCE_URL), not .value (source_url).
    # If the old lowercase value exists from a prior run, rename it first.
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1 FROM pg_enum
                WHERE enumtypid = 'indicatortype'::regtype
                  AND enumlabel = 'source_url'
            ) THEN
                ALTER TYPE indicatortype RENAME VALUE 'source_url' TO 'SOURCE_URL';
            ELSE
                ALTER TYPE indicatortype ADD VALUE IF NOT EXISTS 'SOURCE_URL';
            END IF;
        END$$;
        """
    )


def downgrade() -> None:
    # PostgreSQL does not support removing enum values directly.
    # Rename to mark as removed (same pattern as BASE64_BLOCK removal).
    op.execute(
        """
        DELETE FROM indicators WHERE type = 'SOURCE_URL';
        """
    )
    op.execute(
        """
        ALTER TYPE indicatortype RENAME VALUE 'SOURCE_URL' TO '__REMOVED_SOURCE_URL';
        """
    )
