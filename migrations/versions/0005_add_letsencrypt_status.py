"""add letsencrypt_status to site

Revision ID: 0005_add_letsencrypt_status
Revises: 0004_add_attack_event_action
Create Date: 2026-05-14

"""
from alembic import op
import sqlalchemy as sa

revision = "0005_add_letsencrypt_status"
down_revision = "0004_add_attack_event_action"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "site",
        sa.Column("letsencrypt_status", sa.String(20), nullable=False, server_default="none"),
    )
    op.add_column(
        "site",
        sa.Column("letsencrypt_error", sa.Text(), nullable=True),
    )


def downgrade():
    op.drop_column("site", "letsencrypt_status")
    op.drop_column("site", "letsencrypt_error")
