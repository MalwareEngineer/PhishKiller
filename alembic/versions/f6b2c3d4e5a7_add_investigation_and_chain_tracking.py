"""Add Investigation model and chain-tracking columns to kits.

Supports multi-step phishing chain crawling: parent-child kit tree,
investigation grouping, and new analysis types for EML/QR/link/redirect.

Revision ID: f6b2c3d4e5a7
Revises: e5a1b2c3d4f6
Create Date: 2026-03-16 22:00:00.000000
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

revision = "f6b2c3d4e5a7"
down_revision = "e5a1b2c3d4f6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create investigations table
    op.create_table(
        "investigations",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(256), nullable=True),
        sa.Column("root_kit_id", UUID(as_uuid=True), sa.ForeignKey("kits.id"), nullable=False),
        sa.Column("status", sa.Enum(
            "PENDING", "IN_PROGRESS", "COMPLETED", "FAILED",
            name="investigationstatus", create_type=True,
        ), nullable=False, server_default="PENDING"),
        sa.Column("max_depth", sa.Integer(), nullable=False, server_default="3"),
        sa.Column("total_kits", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("total_depth_reached", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_investigations_root_kit_id", "investigations", ["root_kit_id"])

    # Add chain-tracking columns to kits
    op.add_column("kits", sa.Column("parent_kit_id", UUID(as_uuid=True), sa.ForeignKey("kits.id"), nullable=True))
    op.add_column("kits", sa.Column("investigation_id", UUID(as_uuid=True), sa.ForeignKey("investigations.id"), nullable=True))
    op.add_column("kits", sa.Column("chain_depth", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("kits", sa.Column("discovery_method", sa.String(50), nullable=True))
    op.create_index("ix_kits_parent_kit_id", "kits", ["parent_kit_id"])
    op.create_index("ix_kits_investigation_id", "kits", ["investigation_id"])

    # Add new analysis type enum values
    op.execute("ALTER TYPE analysistype ADD VALUE IF NOT EXISTS 'EML_PARSE'")
    op.execute("ALTER TYPE analysistype ADD VALUE IF NOT EXISTS 'QR_DECODE'")
    op.execute("ALTER TYPE analysistype ADD VALUE IF NOT EXISTS 'LINK_SCORE'")
    op.execute("ALTER TYPE analysistype ADD VALUE IF NOT EXISTS 'REDIRECT_CHAIN'")


def downgrade() -> None:
    op.drop_index("ix_kits_investigation_id", table_name="kits")
    op.drop_index("ix_kits_parent_kit_id", table_name="kits")
    op.drop_column("kits", "discovery_method")
    op.drop_column("kits", "chain_depth")
    op.drop_column("kits", "investigation_id")
    op.drop_column("kits", "parent_kit_id")
    op.drop_index("ix_investigations_root_kit_id", table_name="investigations")
    op.drop_table("investigations")
    # Note: PG enum values cannot be removed; they'll remain as unused labels
