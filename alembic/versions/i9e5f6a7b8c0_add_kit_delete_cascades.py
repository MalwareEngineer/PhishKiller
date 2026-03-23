"""Add ON DELETE CASCADE/SET NULL to all FKs referencing kits.id.

Enables cascading kit deletion: deleting a parent kit removes all children,
their indicators, analysis results, campaign_kits junction rows, and the
investigation (if this kit is the root). SET NULL on kits.investigation_id
breaks the circular FK between kits and investigations.

Revision ID: i9e5f6a7b8c0
Revises: h8d4e5f6a7b9
Create Date: 2026-03-22 00:00:00.000000
"""

from alembic import op

revision = "i9e5f6a7b8c0"
down_revision = "h8d4e5f6a7b9"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. indicators.kit_id → kits.id  ON DELETE CASCADE
    op.drop_constraint("indicators_kit_id_fkey", "indicators", type_="foreignkey")
    op.create_foreign_key(
        "indicators_kit_id_fkey", "indicators", "kits",
        ["kit_id"], ["id"], ondelete="CASCADE",
    )

    # 2. analysis_results.kit_id → kits.id  ON DELETE CASCADE
    op.drop_constraint("analysis_results_kit_id_fkey", "analysis_results", type_="foreignkey")
    op.create_foreign_key(
        "analysis_results_kit_id_fkey", "analysis_results", "kits",
        ["kit_id"], ["id"], ondelete="CASCADE",
    )

    # 3. campaign_kits.kit_id → kits.id  ON DELETE CASCADE
    op.drop_constraint("campaign_kits_kit_id_fkey", "campaign_kits", type_="foreignkey")
    op.create_foreign_key(
        "campaign_kits_kit_id_fkey", "campaign_kits", "kits",
        ["kit_id"], ["id"], ondelete="CASCADE",
    )

    # 4. campaign_kits.campaign_id → campaigns.id  ON DELETE CASCADE
    op.drop_constraint("campaign_kits_campaign_id_fkey", "campaign_kits", type_="foreignkey")
    op.create_foreign_key(
        "campaign_kits_campaign_id_fkey", "campaign_kits", "campaigns",
        ["campaign_id"], ["id"], ondelete="CASCADE",
    )

    # 5. kits.parent_kit_id → kits.id  ON DELETE CASCADE (recursive tree deletion)
    op.drop_constraint("kits_parent_kit_id_fkey", "kits", type_="foreignkey")
    op.create_foreign_key(
        "kits_parent_kit_id_fkey", "kits", "kits",
        ["parent_kit_id"], ["id"], ondelete="CASCADE",
    )

    # 6. investigations.root_kit_id → kits.id  ON DELETE CASCADE
    op.drop_constraint("investigations_root_kit_id_fkey", "investigations", type_="foreignkey")
    op.create_foreign_key(
        "investigations_root_kit_id_fkey", "investigations", "kits",
        ["root_kit_id"], ["id"], ondelete="CASCADE",
    )

    # 7. kits.investigation_id → investigations.id  ON DELETE SET NULL
    #    Breaks the circular FK: when investigation cascades away, kits just
    #    get investigation_id=NULL (not deleted from this side).
    op.drop_constraint("kits_investigation_id_fkey", "kits", type_="foreignkey")
    op.create_foreign_key(
        "kits_investigation_id_fkey", "kits", "investigations",
        ["investigation_id"], ["id"], ondelete="SET NULL",
    )


def downgrade() -> None:
    # Reverse all constraints back to NO ACTION (the original default)
    op.drop_constraint("kits_investigation_id_fkey", "kits", type_="foreignkey")
    op.create_foreign_key(
        "kits_investigation_id_fkey", "kits", "investigations",
        ["investigation_id"], ["id"],
    )

    op.drop_constraint("investigations_root_kit_id_fkey", "investigations", type_="foreignkey")
    op.create_foreign_key(
        "investigations_root_kit_id_fkey", "investigations", "kits",
        ["root_kit_id"], ["id"],
    )

    op.drop_constraint("kits_parent_kit_id_fkey", "kits", type_="foreignkey")
    op.create_foreign_key(
        "kits_parent_kit_id_fkey", "kits", "kits",
        ["parent_kit_id"], ["id"],
    )

    op.drop_constraint("campaign_kits_campaign_id_fkey", "campaign_kits", type_="foreignkey")
    op.create_foreign_key(
        "campaign_kits_campaign_id_fkey", "campaign_kits", "campaigns",
        ["campaign_id"], ["id"],
    )

    op.drop_constraint("campaign_kits_kit_id_fkey", "campaign_kits", type_="foreignkey")
    op.create_foreign_key(
        "campaign_kits_kit_id_fkey", "campaign_kits", "kits",
        ["kit_id"], ["id"],
    )

    op.drop_constraint("analysis_results_kit_id_fkey", "analysis_results", type_="foreignkey")
    op.create_foreign_key(
        "analysis_results_kit_id_fkey", "analysis_results", "kits",
        ["kit_id"], ["id"],
    )

    op.drop_constraint("indicators_kit_id_fkey", "indicators", type_="foreignkey")
    op.create_foreign_key(
        "indicators_kit_id_fkey", "indicators", "kits",
        ["kit_id"], ["id"],
    )
