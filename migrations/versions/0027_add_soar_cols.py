"""add SOAR columns to soc_incident (blocked, blocked_at, blocked_method, blocked_until)

Revision ID: 0027_add_soar_cols
Revises: 0026_add_waf_rule_exclusion
Create Date: 2026-06-24

Añade las columnas de trazabilidad SOAR a soc_incident:
  - blocked       (Boolean, default false)    — fue bloqueada por SOAR
  - blocked_at    (DateTime, nullable)         — timestamp UTC del bloqueo
  - blocked_method (String(20), nullable)      — "crowdsec" | "ufw"
  - blocked_until  (DateTime, nullable)        — expiración (solo CrowdSec)
"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "0027_add_soar_cols"
down_revision = "0026_add_waf_rule_exclusion"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "soc_incident",
        sa.Column("blocked", sa.Boolean(), nullable=False, server_default="false"),
    )
    op.add_column(
        "soc_incident",
        sa.Column("blocked_at", sa.DateTime(), nullable=True),
    )
    op.add_column(
        "soc_incident",
        sa.Column("blocked_method", sa.String(length=20), nullable=True),
    )
    op.add_column(
        "soc_incident",
        sa.Column("blocked_until", sa.DateTime(), nullable=True),
    )
    op.create_index(
        op.f("ix_soc_incident_blocked"),
        "soc_incident",
        ["blocked"],
        unique=False,
    )


def downgrade():
    op.drop_index(op.f("ix_soc_incident_blocked"), table_name="soc_incident")
    op.drop_column("soc_incident", "blocked_until")
    op.drop_column("soc_incident", "blocked_method")
    op.drop_column("soc_incident", "blocked_at")
    op.drop_column("soc_incident", "blocked")
