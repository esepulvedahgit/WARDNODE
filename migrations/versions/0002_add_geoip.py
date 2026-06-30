"""add GeoIP fields

Revision ID: 0002_add_geoip
Revises: 0001_bot_protection
Create Date: 2026-05-13

"""
from alembic import op
import sqlalchemy as sa

revision = "0002_add_geoip"
down_revision = "0001_bot_protection"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "attack_event",
        sa.Column("country_code", sa.String(2), nullable=True),
    )
    op.create_index("ix_attack_event_country_code", "attack_event", ["country_code"])

    op.create_table(
        "geo_blocklist_entry",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("country_code", sa.String(2), nullable=False),
        sa.Column("country_name", sa.String(80), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("country_code"),
    )
    op.create_index("ix_geo_blocklist_entry_country_code", "geo_blocklist_entry", ["country_code"])


def downgrade():
    op.drop_index("ix_geo_blocklist_entry_country_code", table_name="geo_blocklist_entry")
    op.drop_table("geo_blocklist_entry")
    op.drop_index("ix_attack_event_country_code", table_name="attack_event")
    op.drop_column("attack_event", "country_code")
