"""add soc_analysis.origin + manual_reason — análisis IA retroactivo bajo demanda

Revision ID: 0020_add_soc_analysis_origin
Revises: 0019_add_soc_alerts_ml
Create Date: 2026-06-10

origin distingue el análisis del worker ("auto") del disparado manualmente
desde el detalle del incidente ("manual"); manual_reason guarda el motivo
corto opcional que indica el operador. server_default="auto" deja los
análisis existentes como auto sin backfill.
"""

import sqlalchemy as sa
from alembic import op

revision = "0020_add_soc_analysis_origin"
down_revision = "0019_add_soc_alerts_ml"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("soc_analysis") as batch:
        batch.add_column(
            sa.Column("origin", sa.String(length=10), nullable=False, server_default="auto")
        )
        batch.add_column(sa.Column("manual_reason", sa.String(length=200), nullable=True))


def downgrade():
    with op.batch_alter_table("soc_analysis") as batch:
        batch.drop_column("manual_reason")
        batch.drop_column("origin")
