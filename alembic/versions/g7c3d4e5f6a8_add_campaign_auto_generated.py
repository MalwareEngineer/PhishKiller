"""Add auto_generated column to campaigns table.

Supports auto-campaign creation from actor + TLSH similarity clustering.
Distinguishes auto-generated campaigns from manually created ones.

Revision ID: g7c3d4e5f6a8
Revises: f6b2c3d4e5a7
Create Date: 2026-03-17 10:00:00.000000
"""
from alembic import op
import sqlalchemy as sa

revision = "g7c3d4e5f6a8"
down_revision = "a1b2c3d4e5f6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "campaigns",
        sa.Column(
            "auto_generated",
            sa.Boolean(),
            nullable=False,
            server_default="false",
        ),
    )
    op.create_index(
        "ix_campaigns_auto_generated", "campaigns", ["auto_generated"]
    )


def downgrade() -> None:
    op.drop_index("ix_campaigns_auto_generated", table_name="campaigns")
    op.drop_column("campaigns", "auto_generated")
