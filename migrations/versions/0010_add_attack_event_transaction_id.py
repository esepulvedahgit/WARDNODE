"""add transaction_id to attack_event

Revision ID: 0010_add_event_txn_id
Revises: 0009_add_audit_log
Create Date: 2026-05-20
"""

import sqlalchemy as sa
from alembic import op

revision = "0010_add_event_txn_id"
down_revision = "0009_add_audit_log"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "attack_event",
        sa.Column("transaction_id", sa.String(64), nullable=True),
    )
    op.create_index(
        "ix_attack_event_transaction_id",
        "attack_event",
        ["transaction_id"],
        unique=True,
    )


def downgrade():
    op.drop_index("ix_attack_event_transaction_id", "attack_event")
    op.drop_column("attack_event", "transaction_id")
