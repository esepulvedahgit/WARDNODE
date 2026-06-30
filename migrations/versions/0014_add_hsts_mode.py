"""add hsts_mode column to site

Revision ID: 0014_add_hsts_mode
Revises: 0013_remove_pl_categories
Create Date: 2026-05-26

Adds site.hsts_mode (String 20, default 'off') to control HSTS via a
UI select instead of the generic security-headers table.
Valid values: 'off', '1y', '1y-sub', '1y-sub-preload'.
"""
import sqlalchemy as sa
from alembic import op

revision = "0014_add_hsts_mode"
down_revision = "0013_remove_pl_categories"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "site",
        sa.Column("hsts_mode", sa.String(20), nullable=False, server_default="off"),
    )


def downgrade():
    op.drop_column("site", "hsts_mode")
