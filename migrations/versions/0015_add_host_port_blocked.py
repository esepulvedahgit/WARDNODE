"""add host_port_blocked column to site

Revision ID: 0015_add_host_port_blocked
Revises: 0014_add_hsts_mode
Create Date: 2026-05-27

Tracks whether the upstream host port (host.docker.internal:<port>) has been
blocked in iptables INPUT to prevent WAF bypass. Acts as "intent" state;
the iptables rules on the host are the authoritative source of truth.
"""
import sqlalchemy as sa
from alembic import op

revision = "0015_add_host_port_blocked"
down_revision = "0014_add_hsts_mode"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "site",
        sa.Column("host_port_blocked", sa.Boolean(), nullable=False, server_default="false"),
    )


def downgrade():
    op.drop_column("site", "host_port_blocked")
