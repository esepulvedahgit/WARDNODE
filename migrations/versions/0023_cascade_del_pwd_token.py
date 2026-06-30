"""cascade delete on password_reset_token.user_id

Revision ID: 0023_cascade_del_pwd_token
Revises: 0022_add_user_session_token
Create Date: 2026-06-10

Añade ON DELETE CASCADE a la FK password_reset_token.user_id → user.id.
Antes solo había cascade a nivel ORM (SQLAlchemy cascade="all, delete-orphan"),
lo que dejaba tokens huérfanos si el borrado se realizaba fuera del ORM.
"""

import sqlalchemy as sa
from alembic import op

revision = "0023_cascade_del_pwd_token"
down_revision = "0022_add_user_session_token"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("password_reset_token") as batch_op:
        batch_op.drop_constraint("password_reset_token_user_id_fkey", type_="foreignkey")
        batch_op.create_foreign_key(
            "password_reset_token_user_id_fkey",
            "user",
            ["user_id"],
            ["id"],
            ondelete="CASCADE",
        )


def downgrade():
    with op.batch_alter_table("password_reset_token") as batch_op:
        batch_op.drop_constraint("password_reset_token_user_id_fkey", type_="foreignkey")
        batch_op.create_foreign_key(
            "password_reset_token_user_id_fkey",
            "user",
            ["user_id"],
            ["id"],
        )
