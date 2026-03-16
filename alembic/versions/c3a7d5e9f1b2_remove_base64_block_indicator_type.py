"""Remove BASE64_BLOCK indicator type and purge existing rows.

Revision ID: c3a7d5e9f1b2
Revises: b9e2f4a7c8d1
Create Date: 2026-03-15 18:00:00.000000
"""
from alembic import op

revision = "c3a7d5e9f1b2"
down_revision = "b9e2f4a7c8d1"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Delete all BASE64_BLOCK indicators (batch to avoid long lock)
    op.execute(
        """
        DELETE FROM indicators WHERE type = 'BASE64_BLOCK';
        """
    )
    # Remove the enum value — PostgreSQL 10+ supports this
    op.execute(
        """
        ALTER TYPE indicatortype RENAME VALUE 'BASE64_BLOCK' TO '__REMOVED_BASE64_BLOCK';
        """
    )


def downgrade() -> None:
    op.execute(
        """
        ALTER TYPE indicatortype RENAME VALUE '__REMOVED_BASE64_BLOCK' TO 'BASE64_BLOCK';
        """
    )
