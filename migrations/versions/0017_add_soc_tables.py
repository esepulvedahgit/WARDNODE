"""add SOC module tables (soc_incident, soc_analysis, threat_intel_cache)

Revision ID: 0017_add_soc_tables
Revises: 0016_add_data_leakage_categories
Create Date: 2026-06-09

El módulo SOC correlaciona AttackEvents en incidentes por IP origen y ventana
temporal, los enriquece con threat intel (AbuseIPDB, MITRE ATT&CK) y los analiza
con un LLM multi-proveedor. Tres tablas nuevas:

- soc_incident: incidente correlacionado con score heurístico y estado de revisión.
- soc_analysis: salida JSON estandarizada del análisis LLM por incidente.
- threat_intel_cache: cache local por IP de respuestas AbuseIPDB (con TTL).
"""

import sqlalchemy as sa
from alembic import op

revision = "0017_add_soc_tables"
down_revision = "0016_add_data_leakage_categories"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "soc_incident",
        sa.Column("id",           sa.Integer(),    nullable=False),
        sa.Column("created_at",   sa.DateTime(),   nullable=False),
        sa.Column("updated_at",   sa.DateTime(),   nullable=False),
        sa.Column("source_ip",    sa.String(80),   nullable=False),
        sa.Column("domain",       sa.String(255),  nullable=True),
        sa.Column("window_start", sa.DateTime(),   nullable=False),
        sa.Column("window_end",   sa.DateTime(),   nullable=False),
        sa.Column("event_count",  sa.Integer(),    nullable=False, server_default="0"),
        sa.Column("score",        sa.Float(),      nullable=False, server_default="0"),
        sa.Column("severity",     sa.String(20),   nullable=False, server_default="medium"),
        sa.Column("status",       sa.String(20),   nullable=False, server_default="nuevo"),
        sa.Column("reviewed_by",  sa.Integer(),    nullable=True),
        sa.Column("reviewed_at",  sa.DateTime(),   nullable=True),
        sa.Column("abuse_score",  sa.Integer(),    nullable=True),
        sa.Column("mitre",        sa.Text(),       nullable=True),
        sa.ForeignKeyConstraint(["reviewed_by"], ["user.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_soc_incident_source_ip",  "soc_incident", ["source_ip"])
    op.create_index("ix_soc_incident_window_end", "soc_incident", ["window_end"])
    op.create_index("ix_soc_incident_severity",   "soc_incident", ["severity"])
    op.create_index("ix_soc_incident_status",     "soc_incident", ["status"])
    op.create_index("ix_soc_incident_ip_status",  "soc_incident", ["source_ip", "status"])

    op.create_table(
        "soc_analysis",
        sa.Column("id",          sa.Integer(),    nullable=False),
        sa.Column("created_at",  sa.DateTime(),   nullable=False),
        sa.Column("updated_at",  sa.DateTime(),   nullable=False),
        sa.Column("incident_id", sa.Integer(),    nullable=False),
        sa.Column("payload",     sa.Text(),       nullable=False),
        sa.Column("provider",    sa.String(40),   nullable=False),
        sa.Column("model",       sa.String(120),  nullable=False),
        sa.Column("tokens_in",   sa.Integer(),    nullable=True),
        sa.Column("tokens_out",  sa.Integer(),    nullable=True),
        sa.Column("read_at",     sa.DateTime(),   nullable=True),
        sa.ForeignKeyConstraint(["incident_id"], ["soc_incident.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_soc_analysis_incident_id", "soc_analysis", ["incident_id"])

    op.create_table(
        "threat_intel_cache",
        sa.Column("id",         sa.Integer(),   nullable=False),
        sa.Column("created_at", sa.DateTime(),  nullable=False),
        sa.Column("updated_at", sa.DateTime(),  nullable=False),
        sa.Column("ip",         sa.String(80),  nullable=False),
        sa.Column("payload",    sa.Text(),      nullable=False),
        sa.Column("fetched_at", sa.DateTime(),  nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_threat_intel_cache_ip", "threat_intel_cache", ["ip"], unique=True)


def downgrade():
    op.drop_index("ix_soc_analysis_incident_id", "soc_analysis")
    op.drop_table("soc_analysis")
    op.drop_index("ix_soc_incident_ip_status",  "soc_incident")
    op.drop_index("ix_soc_incident_status",     "soc_incident")
    op.drop_index("ix_soc_incident_severity",   "soc_incident")
    op.drop_index("ix_soc_incident_window_end", "soc_incident")
    op.drop_index("ix_soc_incident_source_ip",  "soc_incident")
    op.drop_table("soc_incident")
    op.drop_index("ix_threat_intel_cache_ip", "threat_intel_cache")
    op.drop_table("threat_intel_cache")
