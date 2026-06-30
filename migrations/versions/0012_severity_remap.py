"""severity remap: warning→medium, notice→low, error→high

Revision ID: 0012_severity_remap
Revises: 0011_geo_blocklist_per_site
Create Date: 2026-05-23

"""
from alembic import op

revision = "0012_severity_remap"
down_revision = "0011_geo_blocklist_per_site"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("UPDATE attack_event SET severity = 'medium' WHERE severity = 'warning'")
    op.execute("UPDATE attack_event SET severity = 'low'    WHERE severity = 'notice'")
    op.execute("UPDATE attack_event SET severity = 'high'   WHERE severity = 'error'")


def downgrade():
    op.execute("UPDATE attack_event SET severity = 'warning' WHERE severity = 'medium'")
    op.execute("UPDATE attack_event SET severity = 'notice'  WHERE severity = 'low'")
    op.execute("UPDATE attack_event SET severity = 'error'   WHERE severity = 'high'")
