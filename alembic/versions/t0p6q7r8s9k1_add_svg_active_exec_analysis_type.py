"""add svg_active_exec analysis type

Revision ID: t0p6q7r8s9k1
Revises: s9o5p6q7r8j0
Create Date: 2026-04-20

"""
from typing import Sequence, Union

from alembic import op

revision: str = "t0p6q7r8s9k1"
down_revision: Union[str, None] = "s9o5p6q7r8j0"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("ALTER TYPE analysistype ADD VALUE IF NOT EXISTS 'SVG_ACTIVE_EXEC'")


def downgrade() -> None:
    # PostgreSQL does not support removing enum values; no-op.
    pass
