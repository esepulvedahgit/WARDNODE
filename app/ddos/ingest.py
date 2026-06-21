"""Thread daemon de ingesta de alertas CrowdSec.

Consulta periódicamente 'cscli alerts list' dentro del contenedor
wardnode-crowdsec y almacena los baneos en DdosBanEvent (dedupe por
cs_alert_id, igual que AttackEvent.transaction_id en proxy/ingest.py).
"""
from __future__ import annotations

import json
import logging
import threading
import time
from datetime import datetime, timezone

log = logging.getLogger(__name__)

_CROWDSEC_CONTAINER = "wardnode-crowdsec"
_POLL_INTERVAL_S    = 300   # 5 minutos entre polling
_SINCE_WINDOW       = "168h"  # última semana (deduplicación cubre re-vistas)


def _parse_alert(alert: dict) -> dict | None:
    """Extrae los campos relevantes de una alerta CrowdSec.

    El formato JSON de 'cscli alerts list -o json' tiene la estructura:
    {
        "id": 42,
        "source": {"ip": "1.2.3.4"},
        "scenario": "crowdsecurity/ssh-slow-bf",
        "events_count": 15,
        "created_at": "2026-06-11T20:00:00Z",
        "decisions": [{"duration": "24h", ...}]
    }
    """
    try:
        alert_id = int(alert.get("id", 0))
        if not alert_id:
            return None

        source = alert.get("source") or {}
        source_ip = source.get("ip", "")
        if not source_ip:
            return None

        scenario = alert.get("scenario") or "unknown"
        events_count = int(alert.get("events_count") or 1)

        created_raw = alert.get("created_at") or alert.get("startAt") or ""
        created_at = None
        for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%fZ"):
            try:
                created_at = datetime.strptime(created_raw[:26], fmt[:len(created_raw)])
                break
            except (ValueError, TypeError):
                continue
        if created_at is None:
            created_at = datetime.now(timezone.utc).replace(tzinfo=None)
        else:
            # Normalizar a datetime naive UTC (igual que AttackEvent.created_at)
            if created_at.tzinfo is not None:
                created_at = created_at.astimezone(timezone.utc).replace(tzinfo=None)

        # Leer expiración de la primera decisión (si existe)
        expires_at = None
        decisions = alert.get("decisions") or []
        if decisions:
            stop_raw = decisions[0].get("until") or ""
            for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%fZ"):
                try:
                    expires_at = datetime.strptime(stop_raw[:26], fmt[:len(stop_raw)])
                    break
                except (ValueError, TypeError):
                    continue
            if expires_at is not None and expires_at.tzinfo is not None:
                expires_at = expires_at.astimezone(timezone.utc).replace(tzinfo=None)

        return {
            "cs_alert_id":  alert_id,
            "source_ip":    source_ip,
            "scenario":     scenario,
            "events_count": events_count,
            "created_at":   created_at,
            "expires_at":   expires_at,
        }
    except Exception as exc:
        log.debug("ddos-ingest: error parsing alert: %s", exc)
        return None


def _poll_once(app, docker_client) -> None:
    """Ejecuta cscli alerts list y almacena los nuevos baneos."""
    try:
        container = docker_client.containers.get(_CROWDSEC_CONTAINER)
    except Exception as exc:
        log.debug("ddos-ingest: contenedor %s no disponible: %s", _CROWDSEC_CONTAINER, exc)
        return

    if container.status != "running":
        return

    try:
        exit_code, output = container.exec_run(
            ["cscli", "alerts", "list", "--since", _SINCE_WINDOW, "-o", "json"],
            user="root",
        )
        if exit_code != 0:
            log.debug("ddos-ingest: cscli terminó con código %d", exit_code)
            return

        raw = output.decode("utf-8", errors="replace").strip()
        if not raw:
            return

        try:
            alerts = json.loads(raw)
        except json.JSONDecodeError as exc:
            log.debug("ddos-ingest: JSON inválido de cscli: %s", exc)
            return

        if not isinstance(alerts, list):
            return

        # Obtener GeoIP dentro del contexto de la app
        with app.app_context():
            from sqlalchemy.exc import IntegrityError
            from app.extensions import db
            from app.models import DdosBanEvent
            from app.proxy.geoip import get_country_code

            inserted = 0
            for alert in alerts:
                parsed = _parse_alert(alert)
                if not parsed:
                    continue

                country_code = None
                try:
                    country_code = get_country_code(parsed["source_ip"])
                except Exception as exc:
                    log.debug("ddos-ingest: GeoIP lookup failed for %s: %s", parsed["source_ip"], exc)

                event = DdosBanEvent(
                    cs_alert_id  = parsed["cs_alert_id"],
                    source_ip    = parsed["source_ip"],
                    scenario     = parsed["scenario"],
                    country_code = country_code,
                    events_count = parsed["events_count"],
                    created_at   = parsed["created_at"],
                    expires_at   = parsed["expires_at"],
                )
                db.session.add(event)
                try:
                    db.session.commit()
                    inserted += 1
                except IntegrityError:
                    db.session.rollback()  # ya existía — deduplicación silenciosa
                except Exception:
                    db.session.rollback()
                    raise

            if inserted:
                log.info("ddos-ingest: %d nuevos baneos almacenados", inserted)

    except Exception as exc:
        log.warning("ddos-ingest: error en ciclo de polling: %s", exc)


def _poll_loop(app) -> None:
    """Bucle principal del thread daemon."""
    try:
        import docker
        client = docker.from_env()
    except Exception as exc:
        log.debug("ddos-ingest: Docker no disponible: %s", exc)
        return

    log.info("ddos-ingest: thread iniciado (polling cada %ds)", _POLL_INTERVAL_S)
    while True:
        try:
            _poll_once(app, client)
        except Exception as exc:
            log.error("ddos-ingest: error inesperado: %s", exc)
        time.sleep(_POLL_INTERVAL_S)


def start_ddos_ingest_thread(app) -> threading.Thread | None:
    """Arranca el thread de ingesta DDoS solo si el módulo está habilitado y Docker responde."""
    try:
        import docker
        docker.from_env().ping()
    except Exception as exc:
        log.debug("ddos-ingest: Docker no disponible (%s), thread no iniciado", exc)
        return None

    # Warn early if the GeoIP database is missing — ban events will have country_code=None.
    import os
    db_path = os.environ.get("GEOIP_DB_PATH", "")
    if not db_path or not os.path.exists(db_path):
        log.warning(
            "ddos-ingest: GeoIP enrichment disabled — database not found at '%s'. "
            "Download it via /proxy/settings or run 'flask ensure-geoip'.",
            db_path or "<GEOIP_DB_PATH not set>",
        )

    # Verificar que el módulo esté activo antes de arrancar
    # (se re-verificará dentro del bucle también)
    with app.app_context():
        try:
            from app.models import AppConfig
            if AppConfig.get("module_ddos_enabled") != "1":
                log.debug("ddos-ingest: módulo DDoS no habilitado, thread no iniciado")
                return None
        except Exception:
            return None

    t = threading.Thread(
        target=_poll_loop,
        args=(app,),
        name="ddos-ingest",
        daemon=True,
    )
    t.start()
    log.info("ddos-ingest: thread ddos-ingest iniciado")
    return t
