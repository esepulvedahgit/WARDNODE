"""Detección heurística de incidentes SOC sobre AttackEvent.

Agregación SQL por IP origen dentro de una ventana temporal + score
determinista (volumen, diversidad de categorías, ratio de bloqueo y fan-out
de paths). El score ML complementario (IsolationForest, app/soc/ml.py) usa
los mismos agregados; las heurísticas son siempre el piso de severidad.
"""

import ipaddress
from datetime import datetime

from sqlalchemy import case, func

from app.extensions import db
from app.models import AppConfig, AttackEvent

_SEV_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

DEFAULT_WINDOW_MINUTES = 15
DEFAULT_THRESHOLD_EVENTS = 20


def find_candidates(
    window_start: datetime, window_end: datetime, min_events: int
) -> list[dict]:
    """IPs con actividad anómala en la ventana, agregadas por SQL.

    Agrupa solo por source_ip: un atacante que barre varios sitios es un
    único incidente; el dominio dominante se guarda como referencia.
    """
    rows = (
        db.session.query(
            AttackEvent.source_ip,
            func.count(AttackEvent.id).label("event_count"),
            func.count(func.distinct(AttackEvent.category)).label("cat_diversity"),
            func.count(func.distinct(AttackEvent.path)).label("path_fanout"),
            func.sum(case((AttackEvent.action == "block", 1), else_=0)).label("blocks"),
            # Diversidad de métodos/status: features extra para el scoring ML
            # (app/soc/ml.py) — mismas agregaciones que la matriz de entrenamiento.
            func.count(func.distinct(AttackEvent.method)).label("method_diversity"),
            func.count(func.distinct(AttackEvent.status_code)).label("status_diversity"),
        )
        .filter(AttackEvent.created_at.between(window_start, window_end))
        .group_by(AttackEvent.source_ip)
        .having(func.count(AttackEvent.id) >= min_events)
        .all()
    )

    candidates = []
    for row in rows:
        # Descartar source_ip no parseables como IP (basura atacante-controlada).
        # Las IPs privadas se aceptan: un atacante interno es un incidente válido.
        try:
            ipaddress.ip_address(row.source_ip)
        except (ValueError, TypeError):
            continue

        top_domain = (
            db.session.query(AttackEvent.domain, func.count(AttackEvent.id).label("n"))
            .filter(
                AttackEvent.source_ip == row.source_ip,
                AttackEvent.created_at.between(window_start, window_end),
            )
            .group_by(AttackEvent.domain)
            .order_by(func.count(AttackEvent.id).desc())
            .first()
        )
        categories = [
            c[0]
            for c in db.session.query(func.distinct(AttackEvent.category))
            .filter(
                AttackEvent.source_ip == row.source_ip,
                AttackEvent.created_at.between(window_start, window_end),
            )
            .all()
        ]
        candidates.append(
            {
                "source_ip": row.source_ip,
                "event_count": row.event_count,
                "cat_diversity": row.cat_diversity,
                "path_fanout": row.path_fanout,
                "blocks": row.blocks or 0,
                "method_diversity": row.method_diversity,
                "status_diversity": row.status_diversity,
                "domain": top_domain[0] if top_domain else None,
                "categories": categories,
                "min_events": min_events,
            }
        )
    return candidates


def score_candidate(c: dict) -> float:
    """Score heurístico 0–100 a partir de los agregados de find_candidates."""
    min_events = max(1, c.get("min_events", DEFAULT_THRESHOLD_EVENTS))
    event_count = c["event_count"]
    volume = min(40.0, 40.0 * event_count / (2 * min_events))
    diversity = min(20.0, 5.0 * c["cat_diversity"])
    block_ratio = 20.0 * (c["blocks"] / event_count) if event_count else 0.0
    fanout = min(20.0, 2.0 * c["path_fanout"])
    return round(volume + diversity + block_ratio + fanout, 1)


def severity_for_score(score: float) -> str:
    """Clasifica un score 0-100 en severidad.

    Los umbrales se leen desde AppConfig (soc_sev_critical/high/medium) con
    defaults 80/60/40. Si el orden no es coherente (med >= high o high >= crit)
    se usan los defaults para garantizar una clasificación correcta.
    """
    try:
        crit = max(1, min(100, int(AppConfig.get("soc_sev_critical") or 80)))
        high = max(1, min(100, int(AppConfig.get("soc_sev_high") or 60)))
        med  = max(1, min(100, int(AppConfig.get("soc_sev_medium") or 40)))
    except (TypeError, ValueError):
        crit, high, med = 80, 60, 40
    # Orden incoherente → caer a defaults para no romper la clasificación.
    if not (med < high < crit):
        crit, high, med = 80, 60, 40
    if score >= crit:
        return "critical"
    if score >= high:
        return "high"
    if score >= med:
        return "medium"
    return "low"
