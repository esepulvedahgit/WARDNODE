"""add modsec_raw_log table for raw ModSecurity audit log storage

Revision ID: 0025_add_modsec_raw_log
Revises: 0024_add_ddos_ban_event
Create Date: 2026-06-23

Crea la tabla modsec_raw_log que almacena el JSON crudo de cada evento
ModSecurity tal como lo produce el hilo ingest. El campo transaction_id
garantiza deduplicación: el hilo ingest puede reintentar la misma línea
sin insertar duplicados (IntegrityError → rollback silencioso).
"""

import sqlalchemy as sa
from alembic import op

revision = "0025_add_modsec_raw_log"
down_revision = "0024_add_ddos_ban_event"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "modsec_raw_log",
        sa.Column("id",             sa.Integer(),    nullable=False),
        sa.Column("transaction_id", sa.String(64),   nullable=True),
        sa.Column("created_at",     sa.DateTime(),   nullable=False),
        sa.Column("updated_at",     sa.DateTime(),   nullable=False),
        sa.Column("source_ip",      sa.String(80),   nullable=True),
        sa.Column("rule_id",        sa.String(80),   nullable=True),
        sa.Column("raw_json",       sa.Text(),       nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("transaction_id", name="uq_modsec_raw_log_transaction_id"),
    )
    op.create_index(
        "ix_modsec_raw_log_transaction_id", "modsec_raw_log", ["transaction_id"]
    )
    op.create_index(
        "ix_modsec_raw_log_created_at", "modsec_raw_log", ["created_at"]
    )
    op.create_index(
        "ix_modsec_raw_log_source_ip", "modsec_raw_log", ["source_ip"]
    )


def downgrade():
    op.drop_index("ix_modsec_raw_log_source_ip",      table_name="modsec_raw_log")
    op.drop_index("ix_modsec_raw_log_created_at",     table_name="modsec_raw_log")
    op.drop_index("ix_modsec_raw_log_transaction_id", table_name="modsec_raw_log")
    op.drop_table("modsec_raw_log")
