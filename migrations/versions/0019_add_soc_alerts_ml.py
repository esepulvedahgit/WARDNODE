"""add SOC alerting + ML: soc_ml_model, ml_score/alerted_at, índice attack_event

Revision ID: 0019_add_soc_alerts_ml
Revises: 0018_add_mitre_attack_technique
Create Date: 2026-06-09

Fase 4 (alertas): soc_incident.alerted_at — base del cooldown anti-spam.
Fase 5 (ML): soc_ml_model (IsolationForest serializado con joblib en DB para
consistencia multi-worker) + soc_incident.ml_score.
Rendimiento: índice compuesto attack_event(source_ip, created_at) — las
agregaciones de detect.find_candidates() y ml.build_training_matrix() filtran
por ventana temporal y agrupan por IP.
"""

import sqlalchemy as sa
from alembic import op

revision = "0019_add_soc_alerts_ml"
down_revision = "0018_add_mitre_attack_technique"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "soc_ml_model",
        sa.Column("id",         sa.Integer(),     nullable=False),
        sa.Column("created_at", sa.DateTime(),    nullable=False),
        sa.Column("updated_at", sa.DateTime(),    nullable=False),
        sa.Column("blob",       sa.LargeBinary(), nullable=False),
        sa.Column("n_samples",  sa.Integer(),     nullable=False),
        sa.Column("features",   sa.Text(),        nullable=False),
        sa.Column("score_min",  sa.Float(),       nullable=False),
        sa.Column("score_max",  sa.Float(),       nullable=False),
        sa.Column("trained_at", sa.DateTime(),    nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )

    with op.batch_alter_table("soc_incident") as batch:
        batch.add_column(sa.Column("ml_score",   sa.Float(),    nullable=True))
        batch.add_column(sa.Column("alerted_at", sa.DateTime(), nullable=True))

    op.create_index(
        "ix_attack_event_ip_created", "attack_event", ["source_ip", "created_at"]
    )


def downgrade():
    op.drop_index("ix_attack_event_ip_created", "attack_event")
    with op.batch_alter_table("soc_incident") as batch:
        batch.drop_column("alerted_at")
        batch.drop_column("ml_score")
    op.drop_table("soc_ml_model")
