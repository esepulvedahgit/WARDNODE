"""add waf_rule_exclusion table for per-site CRS rule ID exceptions

Revision ID: 0026_add_waf_rule_exclusion
Revises: 0025_add_modsec_raw_log
Create Date: 2026-06-23

Añade la tabla waf_rule_exclusion que almacena exclusiones WAF por ID de
regla CRS (SecRuleRemoveById) con alcance por sitio. Cada fila se renderiza
como "SecRuleRemoveById <rule_id>" dentro del bloque modsecurity_rules del
server{} del sitio, garantizando que la exclusión afecta únicamente al sitio
para el cual se configuró.
"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "0026_add_waf_rule_exclusion"
down_revision = "0025_add_modsec_raw_log"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "waf_rule_exclusion",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("site_id", sa.Integer(), nullable=False),
        sa.Column("rule_id", sa.Integer(), nullable=False),
        sa.Column("comment", sa.String(length=200), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["site_id"], ["site.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("site_id", "rule_id", name="uq_site_rule_exclusion"),
    )
    op.create_index(
        op.f("ix_waf_rule_exclusion_site_id"),
        "waf_rule_exclusion",
        ["site_id"],
        unique=False,
    )


def downgrade():
    op.drop_index(
        op.f("ix_waf_rule_exclusion_site_id"), table_name="waf_rule_exclusion"
    )
    op.drop_table("waf_rule_exclusion")
