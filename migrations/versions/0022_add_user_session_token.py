"""add user.session_token — invalida sesiones al cambiar contraseña

Revision ID: 0022_add_user_session_token
Revises: 0021_add_soc_review_comment
Create Date: 2026-06-10

Añade user.session_token (32 hex chars). Flask-Login usa get_id()="id:token",
por lo que cambiar la contraseña (set_password rota el token) invalida todas
las sesiones activas del usuario. Backfill con UUID hex para filas existentes.
"""

import uuid

import sqlalchemy as sa
from alembic import op

revision = "0022_add_user_session_token"
down_revision = "0021_add_soc_review_comment"
branch_labels = None
depends_on = None


def upgrade():
    # 1. Añadir como nullable para poder hacer backfill
    op.add_column("user", sa.Column("session_token", sa.String(32), nullable=True))

    # 2. Backfill — cada usuario existente recibe un token único
    conn = op.get_bind()
    user_table = sa.table("user", sa.column("id", sa.Integer), sa.column("session_token", sa.String))
    rows = conn.execute(sa.select(user_table.c.id)).fetchall()
    for (user_id,) in rows:
        conn.execute(
            user_table.update()
            .where(user_table.c.id == user_id)
            .values(session_token=uuid.uuid4().hex)
        )

    # 3. Hacer NOT NULL ahora que todas las filas tienen valor
    op.alter_column("user", "session_token", nullable=False)


def downgrade():
    op.drop_column("user", "session_token")
