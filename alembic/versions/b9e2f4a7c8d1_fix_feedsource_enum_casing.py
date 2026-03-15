"""fix feedsource enum value casing to match SQLAlchemy convention

The a8f1c2d3e4b5 migration added 'phishstats' and 'phishing_database'
as lowercase enum values, but SQLAlchemy's Enum type sends .name (uppercase)
by default.  Rename them to match the existing convention (PHISHTANK, etc.).

Revision ID: b9e2f4a7c8d1
Revises: a8f1c2d3e4b5
Create Date: 2026-03-15 15:30:00.000000

"""
from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b9e2f4a7c8d1"
down_revision: Union[str, None] = "a8f1c2d3e4b5"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("ALTER TYPE feedsource RENAME VALUE 'phishstats' TO 'PHISHSTATS'")
    op.execute(
        "ALTER TYPE feedsource RENAME VALUE 'phishing_database' TO 'PHISHING_DATABASE'"
    )


def downgrade() -> None:
    op.execute("ALTER TYPE feedsource RENAME VALUE 'PHISHSTATS' TO 'phishstats'")
    op.execute(
        "ALTER TYPE feedsource RENAME VALUE 'PHISHING_DATABASE' TO 'phishing_database'"
    )
