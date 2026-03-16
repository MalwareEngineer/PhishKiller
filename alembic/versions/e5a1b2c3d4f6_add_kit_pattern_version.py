"""Add pattern_version column to kits table.

Tracks which IOC extraction pattern version was used to analyze each kit.
NULL means pre-versioning (stale — needs re-analysis).

Revision ID: e5a1b2c3d4f6
Revises: d4f5a6b7c8e9
Create Date: 2026-03-16 20:00:00.000000
"""
from alembic import op
import sqlalchemy as sa

revision = "e5a1b2c3d4f6"
down_revision = "d4f5a6b7c8e9"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("kits", sa.Column("pattern_version", sa.Integer(), nullable=True))
    op.create_index("ix_kits_pattern_version", "kits", ["pattern_version"])


def downgrade() -> None:
    op.drop_index("ix_kits_pattern_version", table_name="kits")
    op.drop_column("kits", "pattern_version")
