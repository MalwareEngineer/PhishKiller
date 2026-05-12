"""Phase 1 of RFC 0001 — auth & identity schema foundation.

Three changes, all additive (no destructive migrations on existing data):

1. ``users`` table — minimal local mirror of OIDC-authenticated identities.
   See :mod:`darla.models.user` for the full design rationale.

2. ``audit_log`` table — append-only request journal.  See
   :mod:`darla.models.audit_log`.

3. ``attributed_by_subject`` column added to the three attribution-evidence
   junction tables (``kit_actors``, ``family_kits``, ``campaign_kits``).
   Coexists with the legacy free-string ``attributed_by`` column; new
   writes from the auth middleware populate the subject column, the UI
   prefers it when present, and the legacy column is the fallback for
   pre-auth historical rows.  No backfill.

The auth middleware that *uses* these tables ships in Phase 2 — this
migration only lays the foundation so models can be referenced from
service-layer code without breaking existing deploys.

Revision ID: y5u1v2w3x4p6
Revises: x4t0u1v2w3o5
Create Date: 2026-05-11
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "y5u1v2w3x4p6"
down_revision: Union[str, None] = "x4t0u1v2w3o5"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_EVIDENCE_TABLES = ("kit_actors", "family_kits", "campaign_kits")


def upgrade() -> None:
    # 1. users
    user_role_enum = sa.Enum("VIEWER", "ANALYST", name="userrole")
    op.create_table(
        "users",
        sa.Column("id", sa.UUID(), primary_key=True),
        sa.Column("oidc_subject", sa.String(128), nullable=False),
        sa.Column("upn", sa.String(255), nullable=False),
        sa.Column("display_name", sa.String(255), nullable=False),
        sa.Column("role", user_role_enum, nullable=False),
        sa.Column("role_override", user_role_enum, nullable=True),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("disabled_at", sa.DateTime(timezone=True), nullable=True),
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
        sa.UniqueConstraint("oidc_subject", name="uq_users_oidc_subject"),
    )
    op.create_index(
        "ix_users_oidc_subject", "users", ["oidc_subject"],
    )

    # 2. audit_log
    op.create_table(
        "audit_log",
        sa.Column("id", sa.UUID(), primary_key=True),
        sa.Column(
            "timestamp",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("actor_subject", sa.String(128), nullable=True),
        sa.Column("actor_upn", sa.String(255), nullable=True),
        sa.Column("auth_mode", sa.String(16), nullable=False),
        sa.Column("method", sa.String(8), nullable=False),
        sa.Column("path", sa.String(512), nullable=False),
        sa.Column("status_code", sa.Integer(), nullable=False),
        sa.Column("response_ms", sa.Integer(), nullable=False),
        sa.Column("request_id", sa.String(64), nullable=False),
        sa.Column(
            "extra",
            sa.dialects.postgresql.JSONB(),
            nullable=True,
        ),
    )
    op.create_index("ix_audit_log_timestamp", "audit_log", ["timestamp"])
    op.create_index("ix_audit_log_actor_subject", "audit_log", ["actor_subject"])
    op.create_index("ix_audit_log_path", "audit_log", ["path"])
    # Composite drives the "audit recent --user X --since 7d" CLI query.
    op.create_index(
        "ix_audit_log_actor_timestamp",
        "audit_log",
        ["actor_subject", "timestamp"],
    )

    # 3. attributed_by_subject on the three evidence-bearing junctions.
    for table in _EVIDENCE_TABLES:
        op.add_column(
            table,
            sa.Column("attributed_by_subject", sa.String(128), nullable=True),
        )


def downgrade() -> None:
    for table in _EVIDENCE_TABLES:
        op.drop_column(table, "attributed_by_subject")

    op.drop_index("ix_audit_log_actor_timestamp", table_name="audit_log")
    op.drop_index("ix_audit_log_path", table_name="audit_log")
    op.drop_index("ix_audit_log_actor_subject", table_name="audit_log")
    op.drop_index("ix_audit_log_timestamp", table_name="audit_log")
    op.drop_table("audit_log")

    op.drop_index("ix_users_oidc_subject", table_name="users")
    op.drop_table("users")
    # Drop the orphaned enum type now that no column references it.
    sa.Enum(name="userrole").drop(op.get_bind(), checkfirst=False)
