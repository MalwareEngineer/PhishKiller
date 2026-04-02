"""add external_js_fetch analysis type

Revision ID: m3i9j0k1l2d4
Revises: l2h8i9j0k1c3
Create Date: 2026-03-31

"""
from typing import Sequence, Union

from alembic import op

revision: str = "m3i9j0k1l2d4"
down_revision: Union[str, None] = "l2h8i9j0k1c3"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("ALTER TYPE analysistype ADD VALUE IF NOT EXISTS 'EXTERNAL_JS_FETCH'")


def downgrade() -> None:
    # PostgreSQL does not support removing enum values; no-op.
    pass
