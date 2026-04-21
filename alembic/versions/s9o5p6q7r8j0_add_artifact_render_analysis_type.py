"""add artifact_render analysis type

Revision ID: s9o5p6q7r8j0
Revises: r8n4o5p6q7i9
Create Date: 2026-04-19

"""
from typing import Sequence, Union

from alembic import op

revision: str = "s9o5p6q7r8j0"
down_revision: Union[str, None] = "r8n4o5p6q7i9"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("ALTER TYPE analysistype ADD VALUE IF NOT EXISTS 'ARTIFACT_RENDER'")


def downgrade() -> None:
    # PostgreSQL does not support removing enum values; no-op.
    pass
