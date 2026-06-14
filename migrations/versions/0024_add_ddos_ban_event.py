"""add ddos_ban_event table for CrowdSec SSH brute-force bans

Revision ID: 0024_add_ddos_ban_event
Revises: 0023_cascade_del_pwd_token
Create Date: 2026-06-11

Crea la tabla ddos_ban_event que almacena los baneos registrados por
CrowdSec (módulo DDoS). El campo cs_alert_id garantiza deduplicación:
el poller puede reintentar la misma ventana de tiempo sin insertar
duplicados (IntegrityError → rollback silencioso).
"""

import sqlalchemy as sa
from alembic import op

revision = "0024_add_ddos_ban_event"
down_revision = "0023_cascade_del_pwd_token"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "ddos_ban_event",
        sa.Column("id",           sa.Integer(),     nullable=False),
        sa.Column("cs_alert_id",  sa.Integer(),     nullable=False),
        sa.Column("source_ip",    sa.String(80),    nullable=False),
        sa.Column("scenario",     sa.String(120),   nullable=False, server_default="unknown"),
        sa.Column("country_code", sa.String(2),     nullable=True),
        sa.Column("events_count", sa.Integer(),     nullable=False, server_default="1"),
        sa.Column("created_at",   sa.DateTime(),    nullable=False),
        sa.Column("expires_at",   sa.DateTime(),    nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("cs_alert_id", name="uq_ddos_ban_event_cs_alert_id"),
    )
    op.create_index("ix_ddos_ban_event_cs_alert_id", "ddos_ban_event", ["cs_alert_id"])
    op.create_index("ix_ddos_ban_event_created_at",  "ddos_ban_event", ["created_at"])


def downgrade():
    op.drop_index("ix_ddos_ban_event_created_at",  table_name="ddos_ban_event")
    op.drop_index("ix_ddos_ban_event_cs_alert_id", table_name="ddos_ban_event")
    op.drop_table("ddos_ban_event")
