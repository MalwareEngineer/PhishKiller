"""add phishstats and phishing_database feed sources

Revision ID: a8f1c2d3e4b5
Revises: 5d423d02b247
Create Date: 2026-03-14 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'a8f1c2d3e4b5'
down_revision: Union[str, None] = '5d423d02b247'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add new enum values to the feedsource PostgreSQL enum type
    op.execute("ALTER TYPE feedsource ADD VALUE IF NOT EXISTS 'phishstats'")
    op.execute("ALTER TYPE feedsource ADD VALUE IF NOT EXISTS 'phishing_database'")


def downgrade() -> None:
    # PostgreSQL does not support removing enum values directly.
    # The new values will remain but be unused after downgrade.
    pass
