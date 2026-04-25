"""add chain_cursor column to kits

Revision ID: v2r8s9t0u1m3
Revises: u1q7r8s9t0l2
Create Date: 2026-04-25

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "v2r8s9t0u1m3"
down_revision: Union[str, None] = "u1q7r8s9t0l2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "kits",
        sa.Column("chain_cursor", sa.String(length=64), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("kits", "chain_cursor")
