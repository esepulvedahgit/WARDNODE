"""add is_console to site

Revision ID: 0006_add_site_is_console
Revises: 0005_add_letsencrypt_status
Create Date: 2026-05-14

"""
from alembic import op
import sqlalchemy as sa

revision = "0006_add_site_is_console"
down_revision = "0005_add_letsencrypt_status"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "site",
        sa.Column("is_console", sa.Boolean(), nullable=False, server_default="false"),
    )


def downgrade():
    op.drop_column("site", "is_console")
