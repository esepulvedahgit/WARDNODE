"""add mitre_attack_technique table (CTI knowledge base del SOC)

Revision ID: 0018_add_mitre_attack_technique
Revises: 0017_add_soc_tables
Create Date: 2026-06-09

Tabla local de técnicas MITRE ATT&CK Enterprise sincronizada desde el CTI
oficial (enterprise-attack.json). Sirve como referencia autorizada de nombres
y tácticas para el mapeo CRS→MITRE y para validar los IDs sugeridos por el LLM
(anti-alucinación).
"""

import sqlalchemy as sa
from alembic import op

revision = "0018_add_mitre_attack_technique"
down_revision = "0017_add_soc_tables"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "mitre_attack_technique",
        sa.Column("id",              sa.Integer(),    nullable=False),
        sa.Column("created_at",      sa.DateTime(),   nullable=False),
        sa.Column("updated_at",      sa.DateTime(),   nullable=False),
        sa.Column("technique_id",    sa.String(20),   nullable=False),
        sa.Column("name",            sa.String(255),  nullable=False),
        sa.Column("tactic",          sa.String(255),  nullable=True),
        sa.Column("is_subtechnique", sa.Boolean(),    nullable=True),
        sa.Column("synced_at",       sa.DateTime(),   nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_mitre_attack_technique_technique_id",
        "mitre_attack_technique",
        ["technique_id"],
        unique=True,
    )


def downgrade():
    op.drop_index("ix_mitre_attack_technique_technique_id", "mitre_attack_technique")
    op.drop_table("mitre_attack_technique")
