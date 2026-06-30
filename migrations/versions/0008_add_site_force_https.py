"""add force_https to site

Revision ID: 0008_add_site_force_https
Revises: 0007_add_user_totp
Create Date: 2026-05-14
"""

import sqlalchemy as sa
from alembic import op

revision = "0008_add_site_force_https"
down_revision = "0007_add_user_totp"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "site",
        sa.Column("force_https", sa.Boolean(), nullable=False, server_default="false"),
    )


def downgrade():
    op.drop_column("site", "force_https")
