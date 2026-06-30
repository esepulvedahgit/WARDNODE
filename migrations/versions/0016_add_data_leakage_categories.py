"""add data-leakage and correlation CRS categories

Revision ID: 0016_add_data_leakage_categories
Revises: 0015_add_host_port_blocked
Create Date: 2026-05-28

OWASP CRS carga las reglas RESPONSE-950 a RESPONSE-954 (tag OWASP_CRS/DATA-LEAKAGES) y
RESPONSE-980 (tag OWASP_CRS/CORRELATION) desde la imagen pero no estaban en el catálogo de
WardNode. Al activar WAF con todas las categorías UI desactivadas, estas reglas permanecían
activas e inspeccionaban los bodies de respuesta — incluyendo las APIs de Grafana/Loki que
devuelven logs de seguridad con contenido que parece datos sensibles, causando falsos positivos.

Ambas categorías se añaden con enabled_by_default=False (desactivadas por defecto).
"""
from alembic import op
import sqlalchemy as sa

revision = "0016_add_data_leakage_categories"
down_revision = "0015_add_host_port_blocked"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("""
        INSERT INTO rule_category (key, name, description, crs_tag, enabled_by_default)
        SELECT 'data-leakage',
               'Filtración de datos',
               'Inspección de respuestas HTTP en busca de datos sensibles (errores SQL, stack traces, versiones de servidor). Puede generar falsos positivos en APIs que devuelven logs de seguridad como Grafana/Loki.',
               'OWASP_CRS/DATA-LEAKAGES',
               0
        WHERE NOT EXISTS (SELECT 1 FROM rule_category WHERE key = 'data-leakage')
    """)
    op.execute("""
        INSERT INTO rule_category (key, name, description, crs_tag, enabled_by_default)
        SELECT 'correlation',
               'Correlación de ataques',
               'Reglas de correlación que consolidan eventos de ataque al final de la transacción. Desactivar solo si se observan falsos positivos en el cierre de requests.',
               'OWASP_CRS/CORRELATION',
               0
        WHERE NOT EXISTS (SELECT 1 FROM rule_category WHERE key = 'correlation')
    """)


def downgrade():
    op.execute("""
        DELETE FROM site_rule_setting
        WHERE category_id IN (
            SELECT id FROM rule_category WHERE key IN ('data-leakage', 'correlation')
        )
    """)
    op.execute("DELETE FROM rule_category WHERE key IN ('data-leakage', 'correlation')")
