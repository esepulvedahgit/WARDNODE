"""add app_config table

Revision ID: 0003_add_app_config
Revises: 0002_add_geoip
Create Date: 2026-05-13

"""
from alembic import op
import sqlalchemy as sa

revision = "0003_add_app_config"
down_revision = "0002_add_geoip"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "app_config",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("key", sa.String(128), nullable=False),
        sa.Column("value", sa.Text(), nullable=True),
        sa.Column("encrypted", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("key"),
    )


def downgrade():
    op.drop_table("app_config")
