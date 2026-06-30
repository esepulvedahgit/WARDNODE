"""add action column to attack_event

Revision ID: 0004_add_attack_event_action
Revises: 0003_add_app_config
Create Date: 2026-05-13

"""
from alembic import op
import sqlalchemy as sa

revision = "0004_add_attack_event_action"
down_revision = "0003_add_app_config"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "attack_event",
        sa.Column("action", sa.String(20), nullable=False, server_default="block"),
    )


def downgrade():
    op.drop_column("attack_event", "action")
