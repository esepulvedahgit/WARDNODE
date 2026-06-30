"""add bot protection config

Revision ID: 0001_bot_protection
Revises:
Create Date: 2026-05-13

"""
from alembic import op
import sqlalchemy as sa

revision = "0001_bot_protection"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "bot_protection_config",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("site_id", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["site_id"], ["site.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("site_id"),
    )


def downgrade():
    op.drop_table("bot_protection_config")
