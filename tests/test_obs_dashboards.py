"""Validación estática de provisioning de Grafana.

Sin fixtures de Flask — solo lectura de archivos JSON/YAML.
Detecta JSON inválido, UIDs incorrectos y datasources mal referenciados
antes del despliegue.
"""
import json
from pathlib import Path

import yaml

DASHBOARDS_DIR = Path(__file__).parent.parent / "observability/grafana/provisioning/dashboards"
DATASOURCES_DIR = Path(__file__).parent.parent / "observability/grafana/provisioning/datasources"


# ── Dashboards ────────────────────────────────────────────────────────────────

def test_all_dashboard_jsons_are_valid():
    """Todos los archivos .json de dashboards deben ser JSON válido."""
    jsons = list(DASHBOARDS_DIR.glob("*.json"))
    assert jsons, "No se encontraron dashboards en el directorio de provisioning"
    for path in jsons:
        try:
            json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            raise AssertionError(f"{path.name} contiene JSON inválido: {e}") from e


def test_waf_analytics_dashboard_uid():
    """03-waf-analytics.json debe tener uid correcto."""
    path = DASHBOARDS_DIR / "03-waf-analytics.json"
    assert path.exists(), "Falta 03-waf-analytics.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["uid"] == "wardnode-waf-analytics"


def test_waf_analytics_all_panels_use_postgres():
    """Todos los paneles de 03-waf-analytics.json deben usar wardnode-postgres."""
    path = DASHBOARDS_DIR / "03-waf-analytics.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    for panel in data.get("panels", []):
        for target in panel.get("targets", []):
            ds = target.get("datasource", {})
            assert ds.get("uid") == "wardnode-postgres", (
                f"Panel '{panel.get('title')}' tiene target con datasource inesperado: {ds}"
            )


def test_waf_analytics_has_expected_panels():
    """03-waf-analytics.json debe tener los 11 paneles planeados."""
    path = DASHBOARDS_DIR / "03-waf-analytics.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    panels = data.get("panels", [])
    assert len(panels) == 11, f"Se esperaban 11 paneles, hay {len(panels)}"


def test_waf_analytics_panel_types():
    """Verifica los tipos de panel clave del dashboard de analítica."""
    path = DASHBOARDS_DIR / "03-waf-analytics.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    types = [p["type"] for p in data["panels"]]
    assert types.count("stat") == 4
    assert "piechart" in types
    assert "barchart" in types
    assert "timeseries" in types
    assert types.count("table") == 3


# ── Datasources ───────────────────────────────────────────────────────────────

def test_all_datasource_yamls_are_valid():
    """Todos los archivos .yaml de datasources deben ser YAML válido."""
    yamls = list(DATASOURCES_DIR.glob("*.yaml"))
    assert yamls, "No se encontraron datasources en el directorio de provisioning"
    for path in yamls:
        try:
            yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as e:
            raise AssertionError(f"{path.name} contiene YAML inválido: {e}") from e


def test_postgres_datasource_uid_and_type():
    """postgres.yaml debe declarar uid wardnode-postgres y type postgres."""
    path = DATASOURCES_DIR / "postgres.yaml"
    assert path.exists(), "Falta observability/grafana/provisioning/datasources/postgres.yaml"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    ds = data["datasources"][0]
    assert ds["uid"] == "wardnode-postgres"
    assert ds["type"] == "postgres"
    assert ds["url"] == "db:5432"
