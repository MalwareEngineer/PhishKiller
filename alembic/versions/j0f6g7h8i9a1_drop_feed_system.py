"""Drop feed_entries table, feed_entry_id FK on kits, and feedsource enum.

Transitions Darla to manual/API-only intake — no automated feed
ingestion (PhishTank, OpenPhish, CertStream). Every kit now originates
from analyst submission, email gateway, or SOAR integration.

Revision ID: j0f6g7h8i9a1
Revises: i9e5f6a7b8c0
Create Date: 2026-03-22 00:00:00.000000
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

revision = "j0f6g7h8i9a1"
down_revision = "i9e5f6a7b8c0"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. Drop feed_entry_id FK and column from kits
    op.drop_constraint("kits_feed_entry_id_fkey", "kits", type_="foreignkey")
    op.drop_column("kits", "feed_entry_id")

    # 2. Drop feed_entries table (cascades its indexes)
    op.drop_table("feed_entries")

    # 3. Drop the feedsource PostgreSQL enum type
    op.execute("DROP TYPE IF EXISTS feedsource")


def downgrade() -> None:
    # Recreate feedsource enum
    feedsource = sa.Enum(
        "PHISHTANK", "OPENPHISH", "CERTSTREAM", "MANUAL",
        name="feedsource",
    )
    feedsource.create(op.get_bind(), checkfirst=True)

    # Recreate feed_entries table
    op.create_table(
        "feed_entries",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("source", feedsource, nullable=False),
        sa.Column("url", sa.Text, nullable=False),
        sa.Column("external_id", sa.String(128)),
        sa.Column("raw_data", sa.JSON),
        sa.Column("target_brand", sa.String(128)),
        sa.Column("is_processed", sa.Boolean, default=False, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_feed_entries_source", "feed_entries", ["source"])
    op.create_index("ix_feed_entries_is_processed", "feed_entries", ["is_processed"])
    op.create_index("ix_feed_entries_url", "feed_entries", ["url"])
    op.create_index(
        "ix_feed_entries_source_external_id", "feed_entries",
        ["source", "external_id"], unique=True,
    )

    # Recreate feed_entry_id column and FK on kits
    op.add_column("kits", sa.Column("feed_entry_id", UUID(as_uuid=True)))
    op.create_foreign_key(
        "kits_feed_entry_id_fkey", "kits", "feed_entries",
        ["feed_entry_id"], ["id"],
    )
