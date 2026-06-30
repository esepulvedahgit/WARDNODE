"""add audit_log table

Revision ID: 0009_add_audit_log
Revises: 0008_add_site_force_https
Create Date: 2026-05-19
"""

import sqlalchemy as sa
from alembic import op

revision = "0009_add_audit_log"
down_revision = "0008_add_site_force_https"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "audit_log",
        sa.Column("id",            sa.Integer(),     nullable=False),
        sa.Column("created_at",    sa.DateTime(),    nullable=False),
        sa.Column("actor_email",   sa.String(255),   nullable=False, server_default="sistema"),
        sa.Column("actor_id",      sa.Integer(),     nullable=True),
        sa.Column("action",        sa.String(80),    nullable=False),
        sa.Column("resource_type", sa.String(40),    nullable=True),
        sa.Column("resource_name", sa.String(255),   nullable=True),
        sa.Column("detail",        sa.Text(),        nullable=True),
        sa.Column("ip_address",    sa.String(80),    nullable=True),
        sa.Column("severity",      sa.String(20),    nullable=False, server_default="info"),
        sa.Column("status",        sa.String(20),    nullable=False, server_default="success"),
        sa.ForeignKeyConstraint(["actor_id"], ["user.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_audit_log_created_at", "audit_log", ["created_at"])
    op.create_index("ix_audit_log_actor_id",   "audit_log", ["actor_id"])
    op.create_index("ix_audit_log_action",     "audit_log", ["action"])


def downgrade():
    op.drop_index("ix_audit_log_action",     "audit_log")
    op.drop_index("ix_audit_log_actor_id",   "audit_log")
    op.drop_index("ix_audit_log_created_at", "audit_log")
    op.drop_table("audit_log")
