"""remove paranoia-level rule categories (architecturally incorrect)

Revision ID: 0013_remove_pl_categories
Revises: 0012_severity_remap
Create Date: 2026-05-23

SecRuleRemoveByTag "paranoia-level/N" removes every CRS rule because each rule carries
exactly one paranoia-level/N tag. These categories always disabled, silently neutering all
CRS rules regardless of which attack categories the user enabled. The paranoia level is
already correctly controlled by tx.paranoia_level in modsecurity-override.conf.
"""
from alembic import op

revision = "0013_remove_pl_categories"
down_revision = "0012_severity_remap"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("""
        DELETE FROM site_rule_setting
        WHERE category_id IN (
            SELECT id FROM rule_category WHERE key IN ('pl1','pl2','pl3','pl4')
        )
    """)
    op.execute("DELETE FROM rule_category WHERE key IN ('pl1','pl2','pl3','pl4')")


def downgrade():
    pass
