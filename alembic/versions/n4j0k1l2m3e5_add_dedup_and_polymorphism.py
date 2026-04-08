"""add duplicate_of_kit_id and polymorphism analysis type

Revision ID: n4j0k1l2m3e5
Revises: m3i9j0k1l2d4
Create Date: 2026-04-07

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

revision: str = "n4j0k1l2m3e5"
down_revision: Union[str, None] = "m3i9j0k1l2d4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "kits",
        sa.Column(
            "duplicate_of_kit_id",
            UUID(as_uuid=True),
            sa.ForeignKey("kits.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.create_index("ix_kits_duplicate_of_kit_id", "kits", ["duplicate_of_kit_id"])
    op.execute("ALTER TYPE analysistype ADD VALUE IF NOT EXISTS 'POLYMORPHISM'")


def downgrade() -> None:
    op.drop_index("ix_kits_duplicate_of_kit_id", table_name="kits")
    op.drop_column("kits", "duplicate_of_kit_id")
    # PostgreSQL does not support removing enum values; no-op for analysistype.
