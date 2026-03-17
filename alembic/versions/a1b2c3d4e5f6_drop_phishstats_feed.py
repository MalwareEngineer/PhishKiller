"""Drop PHISHSTATS feed source.

PhishStats feed never worked — 0 entries ingested. Removing from pipeline.

Revision ID: a1b2c3d4e5f6
Revises: f6b2c3d4e5a7
Create Date: 2026-03-17 01:30:00.000000
"""
from alembic import op

revision = "a1b2c3d4e5f6"
down_revision = "f6b2c3d4e5a7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "ALTER TYPE feedsource RENAME VALUE 'PHISHSTATS' TO '__REMOVED_PHISHSTATS'"
    )


def downgrade() -> None:
    op.execute(
        "ALTER TYPE feedsource RENAME VALUE '__REMOVED_PHISHSTATS' TO 'PHISHSTATS'"
    )
