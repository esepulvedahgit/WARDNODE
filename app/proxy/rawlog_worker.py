"""Worker programado para el prune diario de ModSecRawLog.

Thread daemon (mismo patrón que app/backup/worker.py) que ejecuta el prune
diario de logs crudos ModSecurity a la hora configurada (modsec_rawlog_prune_hour,
UTC). En PostgreSQL con gunicorn multi-worker, un advisory lock (815004 — SOC
usa 815001, backup 815002, port_monitor 815003) garantiza un solo proceso activo.
"""

import logging
import threading
import time
from datetime import datetime, timezone

from flask import current_app
from sqlalchemy import text

from app.extensions import db
from app.models import AppConfig
from app.proxy.rawlog_service import prune_and_archive

log = logging.getLogger(__name__)

RAWLOG_ADVISORY_LOCK_KEY = 815004  # SOC=815001, backup=815002, port_monitor=815003

_TICK_SECONDS = 60
_BOOT_DELAY_SECONDS = 90
_ERROR_BACKOFF_SECONDS = 60


def is_prune_due(now: datetime, prune_hour: int, last_run_at: datetime | None) -> bool:
    """¿Toca ejecutar el prune diario? (función pura, testeable sin DB).

    Reglas:
    - Si now.hour < prune_hour → False (aún no es la hora)
    - Si last_run_at es None → True (nunca ha corrido)
    - Si last_run_at.date() < now.date() → True (ya es un nuevo día)
    - En caso contrario → False (ya corrió hoy)
    """
    if now.hour < prune_hour:
        return False
    if last_run_at is None:
        return True
    return last_run_at.date() < now.date()


def _read_last_run() -> datetime | None:
    """Lee modsec_rawlog_last_prune_at de AppConfig. Retorna None si no existe o falla."""
    raw = AppConfig.get("modsec_rawlog_last_prune_at") or ""
    try:
        return datetime.fromisoformat(raw)
    except ValueError:
        return None


def _run_locked_body(app) -> None:
    """Ejecuta el prune si toca. Llamada bajo advisory lock (o directamente en SQLite)."""
    try:
        prune_hour = int(AppConfig.get("modsec_rawlog_prune_hour") or "3")
    except (TypeError, ValueError):
        prune_hour = 3
    prune_hour = max(0, min(23, prune_hour))

    now = datetime.now(timezone.utc)
    last_run = _read_last_run()

    if not is_prune_due(now, prune_hour, last_run):
        return

    try:
        prune_and_archive(now)
    except Exception as exc:
        current_app.logger.error("rawlog-worker: error en prune: %s", exc)


def _run_locked(app) -> None:
    """Obtiene advisory lock PostgreSQL y ejecuta el cuerpo del prune."""
    if db.engine.dialect.name == "postgresql":
        conn = db.engine.connect()
        try:
            got = conn.execute(
                text("SELECT pg_try_advisory_lock(:key)"),
                {"key": RAWLOG_ADVISORY_LOCK_KEY},
            ).scalar()
            if not got:
                return  # otro worker gunicorn lo está ejecutando
            try:
                _run_locked_body(app)
            finally:
                conn.execute(
                    text("SELECT pg_advisory_unlock(:key)"),
                    {"key": RAWLOG_ADVISORY_LOCK_KEY},
                )
        finally:
            conn.close()
    else:
        # SQLite en dev/test — ejecutar sin lock
        _run_locked_body(app)


def _rawlog_loop(app) -> None:
    time.sleep(_BOOT_DELAY_SECONDS)
    while True:
        try:
            with app.app_context():
                _run_locked(app)
        except Exception as exc:
            log.warning(
                "rawlog-worker: unhandled error: %s, reintento en %ss",
                exc,
                _ERROR_BACKOFF_SECONDS,
            )
            time.sleep(_ERROR_BACKOFF_SECONDS)
            continue
        time.sleep(_TICK_SECONDS)


def start_rawlog_thread(app) -> threading.Thread | None:
    """Arranca el thread daemon de prune de rawlog.

    Retorna None en modo TESTING (para evitar efectos secundarios en tests).
    En PostgreSQL usa advisory lock 815004 para asegurar single-writer bajo
    gunicorn multi-worker.
    """
    if app.config.get("TESTING"):
        return None
    t = threading.Thread(target=_rawlog_loop, args=(app,), name="rawlog-worker", daemon=True)
    t.start()
    log.info("rawlog-worker: thread iniciado (prune diario programado)")
    return t
