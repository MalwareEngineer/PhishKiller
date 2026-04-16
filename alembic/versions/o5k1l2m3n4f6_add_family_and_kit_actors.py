"""add family model and kit_actors association

Revision ID: o5k1l2m3n4f6
Revises: n4j0k1l2m3e5
Create Date: 2026-04-15

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import ARRAY, UUID

revision: str = "o5k1l2m3n4f6"
down_revision: Union[str, None] = "n4j0k1l2m3e5"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Families table
    op.create_table(
        "families",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False, unique=True),
        sa.Column("aliases", ARRAY(sa.String)),
        sa.Column("description", sa.Text),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )

    # family_kits M2M
    op.create_table(
        "family_kits",
        sa.Column(
            "family_id",
            UUID(as_uuid=True),
            sa.ForeignKey("families.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "kit_id",
            UUID(as_uuid=True),
            sa.ForeignKey("kits.id", ondelete="CASCADE"),
            primary_key=True,
        ),
    )

    # family_actors M2M
    op.create_table(
        "family_actors",
        sa.Column(
            "family_id",
            UUID(as_uuid=True),
            sa.ForeignKey("families.id"),
            primary_key=True,
        ),
        sa.Column(
            "actor_id",
            UUID(as_uuid=True),
            sa.ForeignKey("actors.id"),
            primary_key=True,
        ),
    )

    # kit_actors M2M (direct kit-to-actor linking for manual attribution)
    op.create_table(
        "kit_actors",
        sa.Column(
            "kit_id",
            UUID(as_uuid=True),
            sa.ForeignKey("kits.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "actor_id",
            UUID(as_uuid=True),
            sa.ForeignKey("actors.id", ondelete="CASCADE"),
            primary_key=True,
        ),
    )


def downgrade() -> None:
    op.drop_table("kit_actors")
    op.drop_table("family_actors")
    op.drop_table("family_kits")
    op.drop_table("families")
