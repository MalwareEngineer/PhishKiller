"""add oauth_authorize analysis type

Revision ID: u1q7r8s9t0l2
Revises: t0p6q7r8s9k1
Create Date: 2026-04-24

"""
from typing import Sequence, Union

from alembic import op

revision: str = "u1q7r8s9t0l2"
down_revision: Union[str, None] = "t0p6q7r8s9k1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("ALTER TYPE analysistype ADD VALUE IF NOT EXISTS 'OAUTH_AUTHORIZE'")


def downgrade() -> None:
    # PostgreSQL does not support removing enum values; no-op.
    pass
