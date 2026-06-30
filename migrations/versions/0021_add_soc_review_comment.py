"""add soc_incident.review_comment — evidencia escrita de la revisión humana

Revision ID: 0021_add_soc_review_comment
Revises: 0020_add_soc_analysis_origin
Create Date: 2026-06-10

Al marcar un incidente como "revisado" el operador deja un comentario
obligatorio que queda como evidencia de la revisión humana (visible en el
botón "Ver revisión" y enviado por email a los destinatarios de alertas SOC).
"""

import sqlalchemy as sa
from alembic import op

revision = "0021_add_soc_review_comment"
down_revision = "0020_add_soc_analysis_origin"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("soc_incident") as batch:
        batch.add_column(sa.Column("review_comment", sa.String(length=1000), nullable=True))


def downgrade():
    with op.batch_alter_table("soc_incident") as batch:
        batch.drop_column("review_comment")
