"""add monitored_domains, victims, kit_victims for PhishPrint

Three tables backing the PhishPrint per-employee attack-surface view:

* ``monitored_domains`` — operator-curated allowlist that gates which
  observed emails are promoted to first-class :class:`Victim` rows.
  Without this gate, every random email an attacker happens to encode
  into OAuth ``state`` would create a Victim and contaminate the
  per-employee view.
* ``victims`` — first-class entity for monitored-domain employees.
  Carries operator-editable ``display_name``, ``type`` (enum
  user/exec/distro/shared_mailbox/service/unknown), and ``notes``.
  ``first_seen`` / ``last_seen`` are denormalized from the junction
  for fast list-page rendering.
* ``kit_victims`` — junction recording every per-kit observation with
  a ``source`` channel (oauth_state, login_hint, aitm_url_fragment,
  eml_to/cc/bcc, kit_content) and ``observed_at``.

Revision ID: x4t0u1v2w3o5
Revises: w3s9t0u1v2n4
Create Date: 2026-04-26

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "x4t0u1v2w3o5"
down_revision: Union[str, None] = "w3s9t0u1v2n4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "monitored_domains",
        sa.Column("id", sa.UUID(), primary_key=True),
        sa.Column("domain", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.UniqueConstraint("domain", name="uq_monitored_domains_domain"),
    )
    op.create_index(
        "ix_monitored_domains_domain", "monitored_domains", ["domain"],
    )

    # SQLAlchemy auto-emits ``CREATE TYPE victimtype`` when the type
    # is referenced via a column in op.create_table below — no need
    # for an explicit ``.create()`` call.  The type lives at the
    # database level, not the column level, so SA serializes the
    # order correctly.
    victim_type_enum = sa.Enum(
        "USER", "EXEC", "DISTRO", "SHARED_MAILBOX", "SERVICE", "UNKNOWN",
        name="victimtype",
    )

    op.create_table(
        "victims",
        sa.Column("id", sa.UUID(), primary_key=True),
        sa.Column("email", sa.String(320), nullable=False),
        sa.Column("domain", sa.String(255), nullable=False),
        sa.Column("display_name", sa.String(255), nullable=True),
        sa.Column(
            "type", victim_type_enum,
            nullable=False, server_default="USER",
        ),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column(
            "first_seen", sa.DateTime(timezone=True), nullable=True,
        ),
        sa.Column(
            "last_seen", sa.DateTime(timezone=True), nullable=True,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.UniqueConstraint("email", name="uq_victims_email"),
    )
    op.create_index("ix_victims_email", "victims", ["email"])
    op.create_index("ix_victims_domain", "victims", ["domain"])

    observation_source_enum = sa.Enum(
        "OAUTH_STATE", "OAUTH_LOGIN_HINT", "AITM_URL_FRAGMENT",
        "EML_TO", "EML_CC", "EML_BCC", "KIT_CONTENT", "OTHER",
        name="victimobservationsource",
    )

    op.create_table(
        "kit_victims",
        sa.Column("id", sa.UUID(), primary_key=True),
        sa.Column("kit_id", sa.UUID(), nullable=False),
        sa.Column("victim_id", sa.UUID(), nullable=False),
        sa.Column("source", observation_source_enum, nullable=False),
        sa.Column(
            "observed_at", sa.DateTime(timezone=True), nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["kit_id"], ["kits.id"], ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["victim_id"], ["victims.id"], ondelete="CASCADE",
        ),
    )
    op.create_index("ix_kit_victims_kit_id", "kit_victims", ["kit_id"])
    op.create_index("ix_kit_victims_victim_id", "kit_victims", ["victim_id"])
    op.create_index(
        "ix_kit_victims_kit_source", "kit_victims", ["kit_id", "source"],
    )


def downgrade() -> None:
    op.drop_index("ix_kit_victims_kit_source", table_name="kit_victims")
    op.drop_index("ix_kit_victims_victim_id", table_name="kit_victims")
    op.drop_index("ix_kit_victims_kit_id", table_name="kit_victims")
    op.drop_table("kit_victims")
    sa.Enum(name="victimobservationsource").drop(
        op.get_bind(), checkfirst=True,
    )

    op.drop_index("ix_victims_domain", table_name="victims")
    op.drop_index("ix_victims_email", table_name="victims")
    op.drop_table("victims")
    sa.Enum(name="victimtype").drop(op.get_bind(), checkfirst=True)

    op.drop_index(
        "ix_monitored_domains_domain", table_name="monitored_domains",
    )
    op.drop_table("monitored_domains")
