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
    op.execute(
        """
        ALTER TYPE indicatortype ADD VALUE IF NOT EXISTS 'source_url';
        """
    )


def downgrade() -> None:
    # PostgreSQL does not support removing enum values directly.
    # Rename to mark as removed (same pattern as BASE64_BLOCK removal).
    op.execute(
        """
        DELETE FROM indicators WHERE type = 'source_url';
        """
    )
    op.execute(
        """
        ALTER TYPE indicatortype RENAME VALUE 'source_url' TO '__REMOVED_source_url';
        """
    )
