"""add totp columns to user

Revision ID: 0007_add_user_totp
Revises: 0006_add_site_is_console
Create Date: 2026-05-14
"""

import sqlalchemy as sa
from alembic import op

revision = "0007_add_user_totp"
down_revision = "0006_add_site_is_console"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("user", sa.Column("totp_secret", sa.Text(), nullable=True))
    op.add_column(
        "user",
        sa.Column("totp_enabled", sa.Boolean(), nullable=False, server_default="false"),
    )


def downgrade():
    op.drop_column("user", "totp_enabled")
    op.drop_column("user", "totp_secret")
