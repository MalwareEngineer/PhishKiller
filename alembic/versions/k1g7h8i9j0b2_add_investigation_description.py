"""add description to investigations

Revision ID: k1g7h8i9j0b2
Revises: j0f6g7h8i9a1
Create Date: 2026-03-25

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "k1g7h8i9j0b2"
down_revision: Union[str, None] = "j0f6g7h8i9a1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("investigations", sa.Column("description", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("investigations", "description")
