"""geo_blocklist per site

Revision ID: 0011_geo_blocklist_per_site
Revises: 0010_add_event_txn_id
Create Date: 2026-05-22

"""
from alembic import op
import sqlalchemy as sa

revision = "0011_geo_blocklist_per_site"
down_revision = "0010_add_event_txn_id"
branch_labels = None
depends_on = None


def upgrade():
    # Limpiar filas globales (sin site_id asignable)
    op.execute("DELETE FROM geo_blocklist_entry")

    # Eliminar constraint único global y su índice
    with op.batch_alter_table("geo_blocklist_entry") as batch_op:
        batch_op.drop_index("ix_geo_blocklist_entry_country_code")
        batch_op.drop_constraint("geo_blocklist_entry_country_code_key", type_="unique")

    # Añadir columna site_id
    with op.batch_alter_table("geo_blocklist_entry") as batch_op:
        batch_op.add_column(sa.Column("site_id", sa.Integer(), nullable=False, server_default="0"))
        batch_op.create_foreign_key(
            "fk_geo_blocklist_site",
            "site", ["site_id"], ["id"],
            ondelete="CASCADE",
        )
        batch_op.create_unique_constraint("uq_geo_blocklist_site_country", ["site_id", "country_code"])
        batch_op.create_index("ix_geo_blocklist_entry_country_code", ["country_code"])


def downgrade():
    with op.batch_alter_table("geo_blocklist_entry") as batch_op:
        batch_op.drop_index("ix_geo_blocklist_entry_country_code")
        batch_op.drop_constraint("uq_geo_blocklist_site_country", type_="unique")
        batch_op.drop_constraint("fk_geo_blocklist_site", type_="foreignkey")
        batch_op.drop_column("site_id")
        batch_op.create_unique_constraint("geo_blocklist_entry_country_code_key", ["country_code"])
        batch_op.create_index("ix_geo_blocklist_entry_country_code", ["country_code"])
